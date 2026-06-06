# Playbook: Successful Login Detection

## Alert Details

| Field | Details |
|---|---|
| Detection File | [Detections/Successful_login.md](../Detections/Successful_login.md) |
| MITRE Technique | T1078 - Valid Accounts |
| Tactic | Defense Evasion / Persistence / Initial Access |
| Severity | Medium |
| Log Source | Windows Security Event Log |
| Key Event ID | 4624 (Successful Logon) |

---

## What This Alert Means

This alert fires when a successful login is recorded on a Windows machine. On its own, a successful login is normal. However it becomes suspicious when it happens after multiple failed attempts, at unusual times, from an unexpected location, or using an account that should not be logging in interactively. Attackers who successfully compromise credentials will appear in logs as a valid user, making this detection important for catching unauthorized access that bypasses other controls.

---

## Step 1 - Initial Triage (first 5 minutes)

Ask these questions immediately:

- Is this login happening at an unusual time? (midnight, weekends, holidays)
- Is the source IP expected for this user?
- What logon type was used? (Type 3 = network, Type 10 = remote interactive)
- Did multiple failed logins precede this success? (could be a successful brute force)
- Is the account a regular user or a privileged account?

Run this search in Splunk to get an overview:

```spl
index=endpoint EventCode=4624
| table _time, host, user, src_ip, LogonType
| sort - _time
```

---

## Step 2 - Investigation

Dig deeper to understand what happened:

**Check if failed logins preceded this successful login:**
```spl
index=endpoint EventCode=4624 OR EventCode=4625
| stats count by EventCode, user, src_ip
| sort - EventCode
```

If you see many 4625 (failed) events followed by a 4624 (success) for the same user and IP, this is a confirmed brute force success and should be treated as a critical incident.

**Check the logon type to understand how the user logged in:**
```spl
index=endpoint EventCode=4624
| table _time, host, user, src_ip, LogonType
```

| Logon Type | Meaning | Risk |
|---|---|---|
| 2 | Interactive (local keyboard) | Normal |
| 3 | Network (file share, mapped drive) | Medium |
| 7 | Unlock (screen unlock) | Low |
| 10 | RemoteInteractive (RDP) | High |
| 11 | CachedInteractive (cached credentials) | Medium |

Logon Type 10 (RDP) from an unknown IP is very suspicious.

**Check if the login is happening outside business hours:**
```spl
index=endpoint EventCode=4624
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18
| table _time, host, user, src_ip, LogonType
```

**Check what the user did after logging in:**
```spl
index=endpoint user="<username>"
| table _time, EventCode, host, CommandLine
| sort _time
```

Replace `<username>` with the actual username from the alert.

**Check for logins from multiple locations for the same user:**
```spl
index=endpoint EventCode=4624
| stats dc(src_ip) as unique_ips by user
| where unique_ips > 2
```

A user logging in from more than 2 different IPs in a short period is a strong indicator of account compromise.

---

## Step 3 - Evidence to Collect

Save the following before taking any action:

- Screenshot of Splunk search results
- Username that logged in
- Source IP address
- Logon type
- Hostname of the machine that was accessed
- Timestamp of the login
- Whether failed logins preceded this success
- What the user did after logging in
- Whether the same account logged in from multiple IPs

---

## Step 4 - Response Actions

Take these actions based on what you found:

**If failed logins preceded this successful login (brute force success):**
- Disable the compromised account immediately
- Block the source IP at the firewall
- Force a password reset for the account
- Check what the attacker did after logging in
- Notify the account owner

**If the login is from an unexpected IP or location:**
- Contact the user to verify if they logged in from that location
- If the user did not log in, disable the account and reset the password
- Block the suspicious IP

**If the login happened outside business hours:**
- Verify with the user or their manager whether it was expected
- If unexpected, treat it as a potential compromise and disable the account

**If the login appears legitimate:**
- Document the activity
- No action needed but keep monitoring the account

---

## Step 5 - Escalation

Escalate to a senior analyst if any of the following are true:

- Multiple failed logins preceded this success (brute force confirmed)
- The login is from a foreign or completely unexpected IP
- The account that logged in is an Administrator or service account
- The user confirms they did not log in (account is compromised)
- Suspicious activity is detected after the login (new processes, file access, lateral movement)
- The same account logged in from multiple different IPs at the same time

---

## Step 6 - Resolution

Once the threat is contained:

1. Confirm the compromised account password has been reset
2. Confirm the suspicious IP is blocked at the firewall
3. Review what the attacker accessed or changed after logging in
4. Check for persistence mechanisms left behind (new accounts, scheduled tasks, registry changes)
5. Notify the affected user and their manager
6. Document the full timeline of what happened
7. Close the alert with notes on what was found and what action was taken

---

## References

- [MITRE ATT&CK T1078 - Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Windows Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Windows Logon Types](https://learn.microsoft.com/en-us/windows-server/identity/securing-privileged-access/reference-tools-logon-types)
