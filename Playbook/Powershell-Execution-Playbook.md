# Playbook: Suspicious PowerShell Execution

## Alert Details

| Field | Details |
|---|---|
| Detection File | [Detections/Powershell_Execution.md](../Detections/Powershell_Execution.md) |
| MITRE Technique | T1059.001 - Command and Scripting Interpreter: PowerShell |
| Tactic | Execution |
| Severity | High |
| Log Source | Sysmon |
| Key Event ID | Sysmon Event ID 1 (Process Creation) |

---

## What This Alert Means

This alert fires when PowerShell is launched with suspicious flags or from an unexpected parent process. Attackers commonly use PowerShell to run malicious scripts, download malware, move laterally, and evade defenses because it is a built-in Windows tool that is often trusted by security software.

---

## Step 1 - Initial Triage (first 5 minutes)

Ask these questions immediately:

- What flags were used? (-enc, -nop, -w hidden are high risk)
- What process launched PowerShell? (Word, Excel, browser = very suspicious)
- Which user ran it? (SYSTEM or a standard user running PowerShell is unusual)
- What machine did this happen on?

Run this search in Splunk to get an overview:

```spl
index=endpoint EventCode=1 Image="*powershell.exe*"
| table _time, host, user, ParentImage, CommandLine
| sort - _time
```

---

## Step 2 - Investigation

Dig deeper to understand what happened:

**Check for encoded or obfuscated commands:**
```spl
index=endpoint EventCode=1 Image="*powershell.exe*"
| search CommandLine="*-enc*" OR CommandLine="*-EncodedCommand*" OR CommandLine="*-nop*" OR CommandLine="*hidden*"
| table _time, host, user, CommandLine
```

Encoded commands (-enc) are a strong indicator of malicious activity as attackers use them to hide what the script is doing.

**Check what parent process launched PowerShell:**
```spl
index=endpoint EventCode=1 Image="*powershell.exe*"
| table _time, host, user, ParentImage, ParentCommandLine, CommandLine
```

Suspicious parent processes include:
- `winword.exe` (Word)
- `excel.exe` (Excel)
- `outlook.exe` (Outlook)
- `chrome.exe` or `firefox.exe` (Browser)
- `wscript.exe` or `cscript.exe` (Script host)

**Check if PowerShell made any network connections:**
```spl
index=endpoint EventCode=3 Image="*powershell.exe*"
| table _time, host, user, DestinationIp, DestinationPort
```

PowerShell connecting to the internet is a strong indicator of a download or command and control activity.

**Check if any files were created after PowerShell ran:**
```spl
index=endpoint EventCode=11
| table _time, host, user, Image, TargetFilename
| sort - _time
```

---

## Step 3 - Evidence to Collect

Save the following before taking any action:

- Screenshot of Splunk search results
- Full command line used (especially if encoded)
- Parent process that launched PowerShell
- Username and hostname
- Any network connections made by PowerShell
- Any files created or modified after execution
- Timestamp of the event

---

## Step 4 - Response Actions

Take these actions based on what you found:

**If the command line is encoded or obfuscated:**
- Isolate the machine from the network immediately
- Decode the base64 command to understand what it did (use CyberChef: https://gchq.github.io/CyberChef)
- Check for any dropped files or persistence mechanisms

**If PowerShell was launched by Office or a browser:**
- This is likely a phishing attack
- Isolate the machine
- Check what document or link triggered it
- Notify the user who opened it

**If PowerShell made outbound network connections:**
- Block the destination IP at the firewall
- Check if any data was sent out
- Scan the machine for malware

**If no clear malicious intent is found:**
- Document the activity
- Monitor the machine for further suspicious behavior
- Check with the user if they intentionally ran a PowerShell script

---

## Step 5 - Escalation

Escalate to a senior analyst if any of the following are true:

- The command line is encoded or obfuscated
- PowerShell was launched by an Office application or browser (phishing indicator)
- PowerShell made outbound connections to unknown IPs
- New files or scheduled tasks were created after execution
- The affected user is an Administrator
- Multiple machines show the same PowerShell activity (lateral movement)

---

## Step 6 - Resolution

Once the threat is contained:

1. Confirm the machine is clean (run antivirus scan)
2. Confirm no persistence mechanisms were left behind (check scheduled tasks, registry run keys, startup folder)
3. Confirm any malicious network connections are blocked
4. Reset credentials of the affected user if compromise is confirmed
5. Document the full timeline of the incident
6. Close the alert with notes on what was found and what action was taken

---

## References

- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [Sysmon Event ID 1 - Process Creation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [CyberChef - Decode Base64](https://gchq.github.io/CyberChef)
