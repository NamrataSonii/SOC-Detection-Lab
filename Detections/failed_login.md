# Failed Login Detection

## Objective
Detect and investigate failed login attempts on Windows endpoints to identify potential
brute-force or credential stuffing attacks.

## Event ID
| Event ID | Description |
|----------|-------------|
| 4625 | An account failed to log on |

## SPL Query
```spl
index=* EventCode=4625
| stats count by Account_Name, WorkstationName, IpAddress
| sort - count
```

## Investigation Steps
1. **Identify the target account** — which username is being targeted?
2. **Find the source workstation** — is the origin internal or external?
3. **Count failed attempts** — a high count from one source indicates brute-force activity.
4. **Check timing** — are failures happening in rapid succession?
5. **Correlate with Event ID 4624** — did any failed attempt eventually succeed?

## MITRE ATT&CK Mapping
| Field | Detail |
|-------|--------|
| Tactic | Credential Access |
| Technique | T1110 — Brute Force |
| Sub-techniques | T1110.001 Password Guessing, T1110.003 Password Spraying |

## Response Actions
- Block the source IP if attempts exceed threshold
- Lock the targeted account temporarily
- Notify the user if account belongs to a real person
- Escalate if a successful login (4624) follows the failures
