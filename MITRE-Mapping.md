# MITRE ATT&CK Mapping — SOC Detection Lab

For detailed notes on the MITRE ATT&CK framework, refer to my dedicated repo:
-> https://github.com/NamrataSonii/Cybersecurity-Attacks-and-Frameworks/blob/main/MITREAttack.md

---

## Techniques Detected in This Lab

| Detection | Technique ID | Technique Name | Tactic | Log Source |
|---|---|---|---|---|
| Brute Force Login | T1110 | Brute Force | Credential Access | Event ID 4625 |
| Suspicious PowerShell | T1059.001 | PowerShell | Execution | Sysmon Event ID 1 |
| New User Created | T1136.001 | Create Local Account | Persistence | Event ID 4720 |
| Privilege Escalation | T1548 | Abuse Elevation Control | Privilege Escalation | Event ID 4672 |

---
