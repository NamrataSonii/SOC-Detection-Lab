# Forwarder to Splunk Configuration

This document explains how to connect the Splunk Universal Forwarder 
(installed on the Windows machine) to Splunk Enterprise (your SIEM).

---

## Architecture

Windows Machine (Sysmon + Forwarder) ──► Splunk Enterprise (port 9997)

---

## Step 1: Enable Receiving on Splunk Enterprise

1. Open Splunk Web → http://localhost:8000
2. Go to **Settings → Forwarding and Receiving**
3. Click **Configure Receiving → New Receiving Port**
4. Enter port: `9997` → Save

---

## Step 2: Create inputs.conf on Windows Machine

**File Location:**
C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf


**Paste this content:**

```ini
# Windows Security Logs
[WinEventLog://Security]
index = endpoint
sourcetype = WinEventLog:Security
disabled = false

# Windows System Logs
[WinEventLog://System]
index = endpoint
sourcetype = WinEventLog:System
disabled = false

# Windows Application Logs
[WinEventLog://Application]
index = endpoint
sourcetype = WinEventLog:Application
disabled = false

# Sysmon Logs (most important)
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
index = endpoint
sourcetype = XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
renderXml = true
disabled = false
```

---

## Step 3: Create outputs.conf on Windows Machine

**File Location:**
C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf


**Paste this content:**

```ini
[tcpout]
defaultGroup = splunk-indexer

[tcpout:splunk-indexer]
server = <YOUR_SPLUNK_IP>:9997

# Example if Splunk is on same machine:
# server = 127.0.0.1:9997

# Example if Splunk is on another VM:
# server = 192.168.10.10:9997
```

> Replace `<YOUR_SPLUNK_IP>` with the actual IP of your Splunk Enterprise machine.

---

## Step 4: Restart the Forwarder

Open **PowerShell as Administrator** and run:

```powershell
Restart-Service SplunkForwarder
```

Or via Command Prompt:

```cmd
net stop SplunkForwarder
net start SplunkForwarder
```

---

## Step 5: Verify Logs are Reaching Splunk

1. Open Splunk Web → http://localhost:8000
2. Go to **Search & Reporting**
3. Run this search:

```spl
index=endpoint | stats count by sourcetype
```

You should see:
- `WinEventLog:Security`
- `WinEventLog:System`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

---

## Step 6: Create the Index (if not done already)

1. Go to **Settings → Indexes → New Index**
2. Index Name: `endpoint`
3. Leave all other settings as default → Save

---

## Troubleshooting

| Problem | Fix |
|---|---|
| No logs in Splunk | Check forwarder service is running |
| Wrong IP | Verify outputs.conf has correct Splunk IP |
| Port blocked | Allow port 9997 in Windows Firewall |
| Index missing | Create `endpoint` index in Splunk Settings |
