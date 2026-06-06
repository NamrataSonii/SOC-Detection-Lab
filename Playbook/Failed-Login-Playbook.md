# Playbook: Failed Login / Brute Force Detection

## Alert Details

| Field | Details |
|---|---|
| Detection File | [Detections/Failed_login.md](../Detections/Failed_login.md) |
| MITRE Technique | T1110 - Brute Force |
| Tactic | Credential Access |
| Severity | High |
| Log Source | Windows Security Event Log |
| Key Event ID | 4625 (Failed Logon) |

---

## What This Alert Means

This alert fires when multiple failed login attempts are detected on a Windows machine in a short period of time. This is a common indicator of a brute force attack where an attacker is trying many passwords to gain access to an account.

---

## Step 1 - Initial Triage (first 5 minutes)

Ask these questions immediately:

- How many failed attempts occurred? (5+ in 1 minute is suspicious)
- Which account is being targeted? (admin or service account = critical)
- Where is the source IP coming from? (internal or external network?)
- What time did this happen? (outside business hours = more suspicious)

Run this search in Splunk to get an overview:

```spl
index=endpoint EventCode=4625
| stats count by src_ip, user, host
| sort - count
```

---

## Step 2 - Investigation

Dig deeper to understand what happened:

**Check if a successful login followed the failed attempts:**
```spl
index=endpoint EventCode=4624 OR EventCode=4625
| stats count by EventCode, user, src_ip
| sort - EventCode
```

If Event ID 4624 (success) appears after 4625 (failures) for the same user and IP, the brute force may have succeeded. This is critical — treat it as a confirmed compromise.

**Check how many accounts were targeted:**
```spl
index=endpoint EventCode=4625
| stats dc(user) as unique_accounts by src_ip
| where unique_accounts > 3
```

More than 3 accounts targeted from one IP = credential stuffing or password spraying attack.

**Check the source IP reputation:**
- Search the IP on [VirusTotal](https://www.virustotal.com)
- Search the IP on [AbuseIPDB](https://www.abuseipdb.com)
- Is it from an unexpected country or region?

---

## Step 3 - Evidence to Collect

Save the following before taking any action:

- Screenshot of Splunk search results showing failed login count
- Source IP address and geolocation
- Targeted username(s)
- Timestamp of first and last attempt
- Whether a successful login (Event ID 4624) followed the failures
- Hostname of the targeted machine

---

## Step 4 - Response Actions

Take these actions based on what you found:

**If the attack is still ongoing:**
- Block the source IP at the firewall immediately
- Lock the targeted account temporarily

**If a successful login followed the failed attempts:**
- Disable the compromised account immediately
- Force a password reset
- Check what the attacker did after logging in (look for new processes, files, or network connections)
- Notify the account owner

**If it was just failed attempts with no success:**
- Block the source IP
- Monitor the targeted account for further activity
- Document the incident

---

## Step 5 - Escalation

Escalate to a senior analyst if any of the following are true:

- A successful login followed the failed attempts
- The targeted account is an Administrator or service account
- The source IP is from a foreign or unexpected location
- Multiple machines are being targeted at the same time
- Suspicious activity is found after the login (new processes, file changes)

---

## Step 6 - Resolution

Once the threat is contained:

1. Confirm the source IP is blocked
2. Confirm the affected account password has been reset
3. Verify no further suspicious activity from the same IP or account
4. Document the full timeline of the incident
5. Close the alert with notes on what was found and what action was taken

---

## References

- [MITRE ATT&CK T1110 - Brute Force](https://attack.mitre.org/techniques/T1110/)
- [Windows Event ID 4625](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4625)
- [Windows Event ID 4624](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
