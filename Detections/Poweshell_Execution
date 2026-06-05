# PowerShell Execution Detection

## Objective
Detect and investigate PowerShell execution on Windows endpoints using Sysmon Process
Creation logs to identify potentially malicious or unauthorized script execution.

---

## Event ID & Data Source
| Event ID | Log Source | Description |
|----------|------------|-------------|
| 1 | Microsoft-Windows-Sysmon/Operational | Process Create |

---

## Environment
| Field | Value |
|-------|-------|
| Computer Name | Namrata |
| User | Namrata\namra |
| SID | S-1-5-18 |
| Log Source | Microsoft-Windows-Sysmon/Operational |
| Detection Date | 06/06/2026 |
| UTC Time | 2026-06-05 22:36:57.692 |
| Record Number | 67922 |

---

## SPL Query

### Basic Detection
```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*powershell.exe"
| table _time, Image, CommandLine, ParentImage, User, ComputerName
```

### Detect Encoded/Obfuscated Commands (high risk)
```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*powershell.exe" (CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*"
OR CommandLine="*-nop*" OR CommandLine="*bypass*" OR CommandLine="*hidden*")
| table _time, User, CommandLine, ParentImage
```

### PowerShell launched from suspicious parent
```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*powershell.exe"
ParentImage IN ("*cmd.exe", "*wscript.exe", "*mshta.exe", "*winword.exe", "*excel.exe")
| table _time, User, CommandLine, ParentImage
```

---

## Real Log Analysis

### What Was Detected
On **06/06/2026 at 04:06:57 AM**, Sysmon captured a PowerShell process creation event
on machine `Namrata`. The process was launched from the user's Desktop directory by
account `Namrata\namra`.

### Log Details
| Field | Value |
|-------|-------|
| EventCode | 1 (Process Create) |
| Process GUID | {7bab82a6-4f89-6a23-f989-00000000a300} |
| Process ID | 23192 |
| Image | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe |
| Original Filename | PowerShell.EXE |
| File Version | 10.0.26100.5074 (WinBuild.160101.0800) |
| Command Line | C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe |
| Current Directory | C:\Users\Namrata\Desktop\ |
| User | Namrata\namra |
| Logon GUID | {7bab82a6-a9e7-6a22-2964-0a0000000000} |
| Task Category | Sysmon config state changed |
| Company | Microsoft Corporation |
| Product | Microsoft Windows Operating System |

---

## Key Findings
- PowerShell was launched **directly from `C:\Users\Namrata\Desktop\`** — users running
  PowerShell from the Desktop is a common indicator of manual script execution and worth
  investigating
- The command line shows **no arguments** were passed — could be an interactive session
  or the arguments may have been passed separately
- User `Namrata\namra` is a standard domain user account — not SYSTEM or a service account,
  meaning a real person (or something running as them) triggered this
- SID `S-1-5-18` in the event header vs user `Namrata\namra` in the process field is
  worth noting — the Sysmon agent runs as SYSTEM but logged the process under the actual
  user context correctly
- No encoded commands (`-enc`, `-bypass`, `-nop`) visible in the command line — reduces
  immediate suspicion but does not rule out malicious use
- `ParentImage` was not captured in this log view — scrolling down to retrieve it would
  confirm how PowerShell was launched (explorer, cmd, Office app, etc.)

---

## Investigation Steps
1. **Review the CommandLine** — no flags visible here, but check if a script path was
   passed. Run the encoded command SPL query above to rule out obfuscation
2. **Check ParentImage** — scroll down in the event or run:
```spl
   source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
   ProcessGuid="{7bab82a6-4f89-6a23-f989-00000000a300}"
   | table ParentImage, ParentCommandLine
```
3. **Verify the user account** — confirm `Namrata\namra` was logged in and active at
   04:06 AM. An early morning execution by a standard user is suspicious
4. **Look for encoded or obfuscated commands** — check for `-enc`, `-EncodedCommand`,
   `-nop`, `-bypass`, `-windowstyle hidden`
5. **Correlate with network activity** — check Sysmon Event ID 3 (Network Connection)
   around the same ProcessGuid to see if PowerShell made any outbound connections
6. **Check for file creation** — look for Sysmon Event ID 11 (File Create) around the
   same time to see if PowerShell dropped any files

---

## MITRE ATT&CK Mapping
| Field | Detail |
|-------|--------|
| Tactic | Execution |
| Technique | T1059 — Command and Scripting Interpreter |
| Sub-technique | T1059.001 — PowerShell |
| Platform | Windows |
| Data Source | Sysmon Event ID 1 (Process Create) |

---

## Suspicious PowerShell Indicators Reference
| Indicator | Risk | Description |
|-----------|------|-------------|
| `-EncodedCommand` / `-enc` | High | Base64 encoded payload — common in malware |
| `-ExecutionPolicy Bypass` | High | Bypasses script execution restrictions |
| `-WindowStyle Hidden` | High | Hides the PowerShell window from the user |
| `-NonInteractive` / `-nop` | Medium | No profile loaded — avoids leaving traces |
| `IEX` / `Invoke-Expression` | High | Executes strings as code — used in fileless attacks |
| `DownloadString` / `WebClient` | High | Downloads and executes remote payloads |
| Launched from Desktop | Medium | Manual or script-triggered execution |
| Launched from Temp/AppData | High | Common malware staging location |
| Parent = Office app | Critical | Macro-based malware execution |

---

## Response Actions
- Confirm whether `Namrata\namra` intentionally ran PowerShell at 04:06 AM
- Retrieve the `ParentImage` to determine how PowerShell was invoked
- Check Sysmon Event ID 3 for any network connections made by Process ID `23192`
- Check Sysmon Event ID 11 for any files created around UTC 22:36:57
- If no legitimate reason found, isolate the machine and investigate further
- Review all PowerShell events for this user across the past 24 hours

---

## Detection Outcome
| Field | Value |
|-------|-------|
| Status | Requires Investigation |
| Confidence | Medium |
| Requires Escalation | Yes — pending ParentImage and network correlation |

PowerShell execution from the Desktop directory by a standard user at an unusual hour
(04:06 AM) warrants further investigation. The event itself is not confirmed malicious
but should not be dismissed without retrieving the ParentImage and checking for
associated network or file activity.

## Investigation Evidence

### PowerShell Process Creation — Sysmon Event ID 1
![PowerShell Execution](../Screenshots/Powershell_execution_01.png)
![PowerShell Execution](../Screenshots/Powershell_execution_02.png)

---
