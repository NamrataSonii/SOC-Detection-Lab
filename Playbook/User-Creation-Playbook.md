# Playbook: User Account Creation Detection

## Alert Details

| Field | Details |
|---|---|
| Detection File | [Detections/User_Creation.md](../Detections/User_Creation.md) |
| MITRE Technique | T1136.001 - Create Local Account |
| Tactic | Persistence |
| Severity | High |
| Log Source | Windows Security Event Log |
| Key Event ID | 4720 (User Account Created) |

---

## What This Alert Means

This alert fires when a new local user account is created on a Windows machine. While IT administrators create accounts as part of normal operations, attackers also create new accounts after gaining access to maintain persistence. A backdoor account allows an attacker to return to the system even if their original entry point is discovered and closed. This makes new account creation outside of normal IT workflows a high priority alert.

---

## Step 1 - Initial Triage (first 5 minutes)

Ask these questions immediately:

- Who created the account? (which user performed the action)
- What is the name of the newly created account?
- What machine was this on?
- What time was the account created? (outside business hours = suspicious)
- Was this account creation expected or authorized by IT?

Run this search in Splunk to get an overview:

```spl
index=endpoint EventCode=4720
| table _time, host, user, TargetUserName
| sort - _time
```

---

## Step 2 - Investigation

Dig deeper to understand what happened:

**Check if the new account was immediately added to a privileged group:**
```spl
index=endpoint EventCode=4720 OR EventCode=4732
| table _time, EventCode, host, user, TargetUserName
| sort _time
```

If Event ID 4720 (account created) is followed closely by Event ID 4732 (added to group) for the same account, this is a strong indicator of a backdoor account being set up. Treat this as critical.

**Check if the new account has already logged in:**
```spl
index=endpoint EventCode=4624 user="<new_account_name>"
| table _time, host, user, src_ip, LogonType
| sort _time
```

Replace `<new_account_name>` with the name of the newly created account.

**Check what the account that created the new user was doing before and after:**
```spl
index=endpoint user="<creator_account>"
| table _time, EventCode, host, user, CommandLine
| sort _time
```

Replace `<creator_account>` with the user who created the new account. This helps understand if the creator account itself was compromised.

**Check if multiple accounts were created in a short time:**
```spl
index=endpoint EventCode=4720
| stats count by host, user
| where count > 1
```

Multiple accounts created on the same machine in a short period is a strong indicator of malicious activity.

**Check if the account was created outside business hours:**
```spl
index=endpoint EventCode=4720
| eval hour=strftime(_time, "%H")
| where hour < 8 OR hour > 18
| table _time, host, user, TargetUserName
```

---

## Step 3 - Evidence to Collect

Save the following before taking any action:

- Screenshot of Splunk search results showing the account creation
- Name of the newly created account
- Name of the user who created the account
- Hostname of the affected machine
- Timestamp of the account creation
- Whether the new account was added to any groups
- Whether the new account has already been used to log in
- Whether the account was created outside business hours

---

## Step 4 - Response Actions

Take these actions based on what you found:

**If the account creation was not authorized:**
- Disable the newly created account immediately
- Delete the account after evidence is collected
- Check if the account was added to any privileged groups and remove it
- Investigate how the attacker gained access to create the account

**If the new account was already used to log in:**
- This means the attacker has already used the backdoor
- Isolate the machine from the network immediately
- Check what the attacker did while logged in (processes, files, network connections)
- Escalate to senior analyst

**If the account that created the new user appears compromised:**
- Disable the creator account
- Force a password reset
- Check all activity from that account across all machines

**If the account creation was authorized by IT:**
- Verify directly with the IT team or manager
- Document the verification
- Close the alert as a true negative

---

## Step 5 - Escalation

Escalate to a senior analyst if any of the following are true:

- The new account was added to the Administrators group immediately after creation
- The new account has already been used to log in
- The account that created the new user appears to be compromised
- Multiple new accounts were created in a short period
- The account was created outside business hours with no IT authorization
- There are signs of lateral movement from the affected machine after account creation

---

## Step 6 - Resolution

Once the threat is contained:

1. Confirm the unauthorized account has been disabled and deleted
2. Confirm the account has been removed from any privileged groups
3. Check for any other persistence mechanisms left behind (scheduled tasks, registry run keys, new services)
4. If the creator account was compromised, confirm password has been reset
5. Review all activity performed by the new account and the creator account
6. Verify no further suspicious activity on the affected machine
7. Document the full timeline of the incident
8. Close the alert with notes on what was found and what action was taken

---

## References

- [MITRE ATT&CK T1136.001 - Create Local Account](https://attack.mitre.org/techniques/T1136/001/)
- [Windows Event ID 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
- [Windows Event ID 4732](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732)
