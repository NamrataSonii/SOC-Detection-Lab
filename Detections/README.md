# Detections

This folder contains Splunk SPL queries used to detect suspicious activity and security events on Windows machines monitored via Sysmon and Windows Event Logs.

Each detection file includes the SPL query, the event it detects, the MITRE ATT&CK technique it maps to, and investigation steps.

---

## Detection Files

| File | What It Detects | Event ID | MITRE Technique | Tactic |
|------|----------------|----------|-----------------|--------|
| [Failed_login.md](./Failed_login.md) | Multiple failed login attempts | 4625 | T1110 - Brute Force | Credential Access |
| [Successful_login.md](./Successful_login.md) | Successful logins for audit and monitoring | 4624 | T1078 - Valid Accounts | Defense Evasion |
| [User_Creation.md](./User_Creation.md) | New local user account created | 4720 | T1136.001 - Create Local Account | Persistence |
| [Local_Group_Member_Modification.md](./Local_Group_Member_Modification.md) | User added to local security group | 4732 | T1098 - Account Manipulation | Persistence |
| [Powershell_Execution.md](./Powershell_Execution.md) | Suspicious PowerShell process launched | Sysmon ID 1 | T1059.001 - PowerShell | Execution |

---

## Log Sources Used

| Log Source | What It Provides |
|---|---|
| Windows Security Event Log | Login events, account changes, privilege use |
| Sysmon (Operational) | Process creation, network connections, file and registry activity |

---

## How to Use These Detections

1. Make sure Splunk Enterprise is running and receiving logs from the Windows machine
2. Open **Search and Reporting** in Splunk Web
3. Copy the SPL query from any detection file
4. Paste it into the search bar and set the time range
5. Review the results for suspicious activity

---

## Splunk Index Used

All queries in this folder search against the `endpoint` index:

```spl
index=endpoint
```

Make sure your Splunk Universal Forwarder is configured to forward logs to this index. See [Setup/Forwarder-to-Splunk-Config.md](../Setup/Forwarder-to-Splunk-Config.md) for configuration details.

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|--------|--------------------|
| Credential Access | T1110 - Brute Force |
| Defense Evasion | T1078 - Valid Accounts |
| Persistence | T1136.001 - Create Local Account, T1098 - Account Manipulation |
| Execution | T1059.001 - PowerShell |

Full mapping is available in [MITRE-Mapping.md](../MITRE-Mapping.md).

---

## Investigation Tips

- Always check if a **failed login** (Event ID 4625) is followed by a **successful login** (Event ID 4624) — this could indicate a successful brute force
- A **new user creation** (Event ID 4720) outside business hours is a strong indicator of persistence
- **PowerShell** launched with encoded commands or from unusual parent processes should always be investigated
- A user being **added to a local group** (Event ID 4732) like Administrators is a privilege escalation indicator

---

## Screenshots

Evidence screenshots from detections firing in Splunk are in the [Screenshots](../Screenshots/) folder.
