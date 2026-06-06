# Playbooks

This folder contains incident response playbooks for each detection in this lab. Each playbook provides step-by-step guidance on how a SOC analyst should triage, investigate, respond to, and close an alert.

---

## Playbook Files

| Playbook | Related Detection | Severity | MITRE Technique |
|---|---|---|---|
| [Failed-Login-Playbook.md](./Failed-Login-Playbook.md) | Failed_login.md | High | T1110 - Brute Force |
| [Successful-Login-Playbook.md](./Successful-Login-Playbook.md) | Successful_login.md | Medium | T1078 - Valid Accounts |
| [User-Creation-Playbook.md](./User-Creation-Playbook.md) | User_Creation.md | High | T1136.001 - Create Local Account |
| [Local-Group-Modification-Playbook.md](./Local-Group-Modification-Playbook.md) | Local_Group_Member_Modification.md | High | T1098 - Account Manipulation |
| [Powershell-Execution-Playbook.md](./Powershell-Execution-Playbook.md) | Powershell_Execution.md | High | T1059.001 - PowerShell |

---

## Playbook Structure

Every playbook in this folder follows the same structure:

| Section | Description |
|---|---|
| Alert Details | Severity, log source, event ID, MITRE technique |
| What This Alert Means | Plain explanation of what triggered the alert |
| Step 1 - Initial Triage | First actions to take within 5 minutes |
| Step 2 - Investigation | Deeper Splunk searches and questions to answer |
| Step 3 - Evidence to Collect | What to save before taking action |
| Step 4 - Response Actions | How to contain and remediate the threat |
| Step 5 - Escalation | When to escalate to a senior analyst |
| Step 6 - Resolution | How to close the incident |

---

## How to Use

1. An alert fires in Splunk based on a detection query in the `Detections/` folder
2. Open the matching playbook from this folder
3. Follow each step in order
4. Document your findings at each step
5. Escalate if any escalation criteria are met
6. Close the incident with a summary of what happened and what was done

---

## Notes

- Always collect evidence before taking any response action
- Never delete logs or modify the system before evidence is saved
- When in doubt, escalate — it is always better to over-escalate than to miss a real incident
