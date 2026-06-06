# SOC Detection Lab

A hands-on Security Operations Center (SOC) home lab built to simulate real-world
attacks, capture Windows security events, and analyze them using Splunk Enterprise
and Sysmon.

---

## Lab Architecture

```
+--------------------------------------------------+
|                  SOC Home Lab                    |
|                                                  |
|  +--------------+        +------------------+   |
|  |  Windows VM  |------->| Splunk Enterprise|   |
|  |  (Target)    |        |    (SIEM)        |   |
|  |              |        |                  |   |
|  |  - Sysmon    |        |  - Log Ingestion |   |
|  |  - UF Agent  |        |  - SPL Queries   |   |
|  |  - Win Logs  |        |  - Dashboards    |   |
|  +--------------+        +------------------+   |
+--------------------------------------------------+
```

---

## Tools & Technologies

| Component | Role |
|-----------|------|
| Splunk Enterprise | SIEM — log ingestion, search, and analysis |
| Splunk Universal Forwarder | Ships Windows logs to Splunk |
| Sysmon (System Monitor) | Deep Windows process and network telemetry |
| Windows Security Event Log | Authentication, account, and audit events |
| MITRE ATT&CK Framework | Threat mapping and detection categorization |

---

## Repository Structure

```
SOC-Detection-Lab/
├── Detections/
│   ├── README.md
│   ├── Failed_login.md
│   ├── Successful_login.md
│   ├── Powershell_Execution.md
│   ├── User_Creation.md
│   └── Local_Group_Member_Modification.md
├── Playbooks/
│   ├── README.md
│   ├── Failed-Login-Playbook.md
│   ├── Successful-Login-Playbook.md
│   ├── Powershell-Execution-Playbook.md
│   ├── User-Creation-Playbook.md
│   └── Local-Group-Modification-Playbook.md
├── Setup/
│   ├── README.md
│   ├── Splunk-Enterprise-Setup.md
│   ├── Splunk-Universal-Forwarder-Setup.md
│   ├── Sysmon-Setup.md
│   └── Forwarder-to-Splunk-Config.md
├── Screenshots/
├── MITRE-Mapping.md
└── README.md
```

---

## Attack Chain Simulation

This lab simulates a complete local privilege escalation attack chain across
a single Windows host. All 5 detections are connected and tell one continuous story:

```
[06/05/2026 05:19 PM]  testuser account CREATED by namra
                              | Event ID 4720
[06/05/2026 05:51 PM]  13 failed login attempts against testuser
                              | Event ID 4625
[06/05/2026 05:53 PM]  SYSTEM service logon on same host
                              | Event ID 4624
[06/06/2026 04:06 AM]  PowerShell launched from Desktop by namra
                              | Sysmon Event ID 1
[06/06/2026 05:25 AM]  testuser added to Administrators group
                              | Event ID 4732
```

Account Creation -> Credential Testing -> Persistence -> Privilege Escalation

---

## Detections

| # | Detection | Event ID | Source | MITRE | Severity |
|---|-----------|----------|--------|-------|----------|
| 1 | [Failed Login Detection](./Detections/Failed_login.md) | 4625 | Security Log | T1110 - Brute Force | High |
| 2 | [Successful Login Detection](./Detections/Successful_login.md) | 4624 | Security Log | T1078 - Valid Accounts | Medium |
| 3 | [PowerShell Execution Detection](./Detections/Powershell_Execution.md) | Sysmon 1 | Sysmon Operational | T1059.001 - PowerShell | High |
| 4 | [User Account Creation Detection](./Detections/User_Creation.md) | 4720 | Security Log | T1136 - Create Account | High |
| 5 | [Local Group Membership Modification](./Detections/Local_Group_Member_Modification.md) | 4732 | Security Log | T1098 - Account Manipulation | Critical |

---

## Key SPL Queries

### Detect brute-force attempts
```spl
index=* EventCode=4625
| stats count by Account_Name, WorkstationName, IpAddress
| where count >= 10
| sort - count
```

### PowerShell with suspicious flags
```spl
source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
Image="*powershell.exe"
(CommandLine="*-enc*" OR CommandLine="*bypass*" OR CommandLine="*hidden*")
| table _time, User, CommandLine, ParentImage
```

### Full attack chain correlation
```spl
source="WinEventLog:Security" EventCode IN (4720, 4625, 4624, 4732)
| eval Action=case(
    EventCode=4720, "Account Created",
    EventCode=4625, "Failed Login",
    EventCode=4624, "Successful Login",
    EventCode=4732, "Added to Admin Group")
| table _time, EventCode, Action, Account_Name, ComputerName
| sort _time
```

---

## Incident Response Playbooks

Each detection in this lab has a matching playbook that documents how a SOC analyst
should triage, investigate, and respond to the alert.

| Playbook | Severity | MITRE Technique |
|----------|----------|-----------------|
| [Failed Login Playbook](./Playbooks/Failed-Login-Playbook.md) | High | T1110 - Brute Force |
| [Successful Login Playbook](./Playbooks/Successful-Login-Playbook.md) | Medium | T1078 - Valid Accounts |
| [PowerShell Execution Playbook](./Playbooks/Powershell-Execution-Playbook.md) | High | T1059.001 - PowerShell |
| [User Creation Playbook](./Playbooks/User-Creation-Playbook.md) | High | T1136.001 - Create Local Account |
| [Local Group Modification Playbook](./Playbooks/Local-Group-Modification-Playbook.md) | High | T1098 - Account Manipulation |

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Technique ID |
|--------|-----------|--------------|
| Credential Access | Brute Force | T1110 |
| Defense Evasion | Valid Accounts | T1078 |
| Execution | PowerShell | T1059.001 |
| Persistence | Create Local Account | T1136.001 |
| Persistence | Account Manipulation | T1098 |

Full mapping available in [MITRE-Mapping.md](./MITRE-Mapping.md)

---

## Setup

Full setup instructions are available in the [Setup](./Setup/) folder covering:

- Splunk Enterprise installation and configuration
- Splunk Universal Forwarder installation
- Sysmon installation with detection config
- Connecting the Forwarder to Splunk

---

## What I Learned

- Configuring Splunk Enterprise and Universal Forwarder for Windows log ingestion
- Deploying and tuning Sysmon for deep endpoint telemetry
- Writing SPL queries to detect real attack techniques
- Mapping detections to the MITRE ATT&CK framework
- Investigating a complete multi-stage attack chain end-to-end
- Correlating events across multiple Event IDs to reconstruct attacker behavior
- Writing incident response playbooks for each detection

---

## Screenshots

Evidence screenshots from detections firing in Splunk are available in the [Screenshots](./Screenshots/) folder.

---

## References

- [Splunk Documentation](https://docs.splunk.com)
- [Sysmon by Sysinternals](https://learn.microsoft.com/sysinternals/downloads/sysmon)
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [Windows Security Event IDs](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Florian Roth Sysmon Config](https://github.com/Neo23x0/sysmon-config)

---
