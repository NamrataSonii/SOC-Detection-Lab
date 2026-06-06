# Playbook: Local Group Member Modification

## Alert Details

| Field | Details |
|---|---|
| Detection File | [Detections/Local_Group_Member_Modification.md](../Detections/Local_Group_Member_Modification.md) |
| MITRE Technique | T1098 - Account Manipulation |
| Tactic | Persistence |
| Severity | High |
| Log Source | Windows Security Event Log |
| Key Event ID | 4732 (Member Added to Security-Enabled Local Group) |

---

## What This Alert Means

This alert fires when a user account is added to a local security group on a Windows machine. Attackers do this after gaining initial access to give themselves higher privileges and maintain persistence. The most dangerous scenario is when a regular user account is added to the **Administrators** group, giving the attacker full control over the machine.

---

## Step 1 - Initial Triage (first 5 minutes)

Ask these questions immediately:

- Which group was modified? (Administrators group = critical severity)
- Which account was added to the group?
- Who made the change? (which user performed the action)
- What machine did this happen on?
- What time did it happen? (outside business hours = more suspicious)

Run this search in Splunk to get an overview:

```spl
index=endpoint EventCode=4732
| table _time, host, user, MemberSid, TargetUserName
| sort - _time
```

---

## Step 2 - Investigation

Dig deeper to understand what happened:

**Check which group was modified and who was added:**
```spl
index=endpoint EventCode=4732
| table _time, host, user, MemberSid, TargetUserName, TargetDomainName
```

- `TargetUserName` = the group that was modified (e.g. Administrators)
- `user` = the account that performed the change
- `MemberSid` = the account that was added

**Check if the account that was added is new or unknown:**
```spl
index=endpoint EventCode=4720 OR EventCode=4732
| table _time, EventCode, host, user, TargetUserName
| sort _time
```

If Event ID 4720 (account created) and 4732 (added to group) appear close together for the same account, this is a strong indicator of an attacker creating a backdoor account.

**Check what the added account did after being added to the group:**
```spl
index=endpoint user="<added_account_name>"
| table _time, EventCode, host, user, CommandLine
| sort _time
```

Replace `<added_account_name>` with the actual account name from the alert.

**Check for any logins from the newly added account:**
```spl
index=endpoint EventCode=4624 user="<added_account_name>"
| table _time, host, user, src_ip, LogonType
```

---

## Step 3 - Evidence to Collect

Save the following before taking any action:

- Screenshot of Splunk search results showing the group modification
- Name of the group that was modified
- Name of the account that was added
- Name of the user who performed the change
- Hostname of the affected machine
- Timestamp of the event
- Whether the added account logged in after being added
- Whether the added account was newly created around the same time

---

## Step 4 - Response Actions

Take these actions based on what you found:

**If an unauthorized account was added to the Administrators group:**
- Remove the account from the Administrators group immediately
- Disable the account if it is not a legitimate account
- Check if the account was used to make any changes to the system after being added

**If a newly created account was added to a privileged group:**
- This is a strong indicator of an attacker creating a backdoor
- Disable and delete the account
- Isolate the machine from the network
- Check how the attacker gained access in the first place (look at login events before this activity)

**If a legitimate user made the change:**
- Verify with the IT team or manager whether this change was authorized
- If unauthorized, reverse the change and investigate how it happened
- If authorized, document it and close the alert

---

## Step 5 - Escalation

Escalate to a senior analyst if any of the following are true:

- The account was added to the Administrators group
- The added account was newly created just before this event
- The added account has already logged in and performed actions on the system
- Multiple machines show the same group modification
- The user who made the change claims they did not do it (account may be compromised)
- There are signs of lateral movement from the affected machine

---

## Step 6 - Resolution

Once the threat is contained:

1. Confirm the unauthorized account has been removed from the group
2. Confirm the account is disabled if it was not legitimate
3. Check for any other persistence mechanisms left behind (scheduled tasks, registry run keys, new services)
4. Verify no further suspicious activity from the affected account or machine
5. If a legitimate account was compromised, force a password reset
6. Document the full timeline of the incident
7. Close the alert with notes on what was found and what action was taken

---

## References

- [MITRE ATT&CK T1098 - Account Manipulation](https://attack.mitre.org/techniques/T1098/)
- [Windows Event ID 4732](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4732)
- [Windows Event ID 4720](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4720)
