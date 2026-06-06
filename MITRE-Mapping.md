# MITRE ATT&CK Mapping — SOC Detection Lab

This file maps all detections in this lab to the MITRE ATT&CK framework.
Each detection is implemented as a Splunk SPL query triggered via Windows Event Logs and Sysmon.

For detailed notes on the MITRE ATT&CK framework, refer to my dedicated repo:
https://github.com/NamrataSonii/Cybersecurity-Attacks-and-Frameworks/blob/main/MITREAttack.md

---

## Mapping Table

| Detection File | What It Detects | MITRE Technique | Technique ID | Tactic | Log Source |
|---|---|---|---|---|---|
| [Failed_login.md](./Detections/Failed_login.md) | Multiple failed login attempts | Brute Force | T1110 | Credential Access | Windows Security Log (Event ID 4625) |
| [Successful_login.md](./Detections/Successful_login.md) | Successful logins for audit and monitoring | Valid Accounts | T1078 | Defense Evasion | Windows Security Log (Event ID 4624) |
| [User_Creation.md](./Detections/User_Creation.md) | New local user account created | Create Local Account | T1136.001 | Persistence | Windows Security Log (Event ID 4720) |
| [Local_Group_Member_Modification.md](./Detections/Local_Group_Member_Modification.md) | User added to local security group | Account Manipulation | T1098 | Persistence | Windows Security Log (Event ID 4732) |
| [Powershell_Execution.md](./Detections/Powershell_Execution.md) | Suspicious PowerShell process launched | PowerShell | T1059.001 | Execution | Sysmon Event ID 1 |

---

## Tactic Coverage

| Tactic | Techniques Covered |
|--------|--------------------|
| Credential Access | T1110 - Brute Force |
| Defense Evasion | T1078 - Valid Accounts |
| Persistence | T1136.001 - Create Local Account, T1098 - Account Manipulation |
| Execution | T1059.001 - PowerShell |

---

## Detection Details

### T1110 — Brute Force
- **Tactic:** Credential Access
- **Log Source:** Windows Security Event Log
- **Key Event ID:** 4625 (Failed Logon)
- **Detection Logic:** Multiple failed login attempts from the same source within a short time window
- **Detection File:** [Detections/Failed_login.md](./Detections/Failed_login.md)

---

### T1078 — Valid Accounts
- **Tactic:** Defense Evasion / Persistence
- **Log Source:** Windows Security Event Log
- **Key Event ID:** 4624 (Successful Logon)
- **Detection Logic:** Monitors successful logins to identify unauthorized access using valid credentials
- **Detection File:** [Detections/Successful_login.md](./Detections/Successful_login.md)

---

### T1136.001 — Create Local Account
- **Tactic:** Persistence
- **Log Source:** Windows Security Event Log
- **Key Event ID:** 4720 (User Account Created)
- **Detection Logic:** Alerts when a new local user account is created, especially outside business hours
- **Detection File:** [Detections/User_Creation.md](./Detections/User_Creation.md)

---

### T1098 — Account Manipulation
- **Tactic:** Persistence
- **Log Source:** Windows Security Event Log
- **Key Event ID:** 4732 (Member Added to Security Group)
- **Detection Logic:** Alerts when a user is added to a local security group such as Administrators
- **Detection File:** [Detections/Local_Group_Member_Modification.md](./Detections/Local_Group_Member_Modification.md)

---

### T1059.001 — PowerShell
- **Tactic:** Execution
- **Log Source:** Sysmon
- **Key Event ID:** 1 (Process Creation)
- **Detection Logic:** PowerShell launched with suspicious flags or from unexpected parent processes
- **Detection File:** [Detections/Powershell_Execution.md](./Detections/Powershell_Execution.md)

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Windows Security Event IDs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/security-auditing-overview)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
