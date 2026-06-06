# Setup Guide — SOC Detection Lab

This folder contains step-by-step instructions to set up the full SOC Detection Lab environment using **Splunk Enterprise**, **Splunk Universal Forwarder**, and **Sysmon** on a Windows machine.

---

## Prerequisites

Before starting, make sure you have:

- A Windows 10/11 VM (target/monitored machine)
- A machine to run Splunk Enterprise (can be the same VM or a separate one)
- VirtualBox or VMware (if using VMs)
- At least 8GB RAM and 50GB disk space
- Internet connection to download tools

---

## Tools Used

| Tool | Purpose | Download |
|------|---------|----------|
| Splunk Enterprise | SIEM — collects and analyzes logs | [Download](https://www.splunk.com/en_us/download/splunk-enterprise.html) |
| Splunk Universal Forwarder | Sends logs from Windows to Splunk | [Download](https://www.splunk.com/en_us/download/universal-forwarder.html) |
| Sysmon | Advanced Windows event logging | [Download](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) |

---

## Lab Architecture

```
┌─────────────────────────────────┐        ┌──────────────────────────┐
│        Windows Machine          │        │     Splunk Enterprise    │
│                                 │        │                          │
│  ┌─────────┐   ┌─────────────┐  │        │  ┌────────────────────┐  │
│  │ Sysmon  │──▶│  Windows    │  │        │  │   Search &         │  │
│  │(logging)│   │  Event Logs │  │        │  │   Reporting        │  │
│  └─────────┘   └──────┬──────┘  │        │  └────────────────────┘  │
│                        │        │        │                          │
│               ┌────────▼──────┐ │        │  ┌────────────────────┐  │
│               │    Splunk     │ │──9997──▶│  │  Indexes           │  │
│               │   Universal  │ │        │  │  (endpoint)        │  │
│               │   Forwarder  │ │        │  └────────────────────┘  │
│               └───────────────┘ │        │                          │
└─────────────────────────────────┘        └──────────────────────────┘
```

---

## Files in This Folder

| File | Description |
|------|-------------|
| `Splunk-Enterprise-Setup.md` | Install and configure Splunk Enterprise |
| `Splunk-Universal-Forwarder-Setup.md` | Install Forwarder on Windows machine |
| `Sysmon-Setup.md` | Install Sysmon with config for detailed logging |
| `Forwarder-to-Splunk-Config.md` | Connect Forwarder to Splunk (inputs.conf & outputs.conf) |

---

## Setup Order

Follow the steps **in this exact order**:

```
Step 1 → Install Splunk Enterprise
Step 2 → Install Splunk Universal Forwarder
Step 3 → Install Sysmon
Step 4 → Configure Forwarder → Splunk connection
Step 5 → Verify logs in Splunk
```

---

## Step 1 — Install Splunk Enterprise

> Full guide: [`Splunk-Enterprise-Setup.md`](./Splunk-Enterprise-Setup.md)

**Quick Summary:**
1. Download and run the Splunk Enterprise installer
2. Set admin credentials
3. Access Splunk Web at `http://localhost:8000`
4. Create an index named `endpoint`
5. Enable receiving on port `9997`

---

## Step 2 — Install Splunk Universal Forwarder

> Full guide: [`Splunk-Universal-Forwarder-Setup.md`](./Splunk-Universal-Forwarder-Setup.md)

**Quick Summary:**
1. Download and run the Universal Forwarder MSI on your Windows machine
2. During install, point to your Splunk Enterprise IP and port `9997`
3. Set a deployment server if applicable

---

## Step 3 — Install Sysmon

> Full guide: [`Sysmon-Setup.md`](./Sysmon-Setup.md)

**Quick Summary:**
1. Download `Sysmon64.exe` from Microsoft Sysinternals
2. Use the config from `Configs/sysmon-config.xml`
3. Install with:
```cmd
sysmon64.exe -accepteula -i Configs\sysmon-config.xml
```
4. Verify logs appear in **Event Viewer → Sysmon/Operational**

---

## Step 4 — Configure Forwarder → Splunk

> Full guide: [`Forwarder-to-Splunk-Config.md`](./Forwarder-to-Splunk-Config.md)

**Quick Summary:**
1. Create `inputs.conf` to collect Security, System, and Sysmon logs
2. Create `outputs.conf` pointing to your Splunk IP on port `9997`
3. Restart the Forwarder service:
```powershell
Restart-Service SplunkForwarder
```

---

## Step 5 — Verify Logs in Splunk

Open Splunk Web and run this search to confirm logs are flowing in:

```spl
index=endpoint | stats count by sourcetype
```

You should see these sourcetypes:

| Sourcetype | What It Contains |
|---|---|
| `WinEventLog:Security` | Login attempts, account changes |
| `WinEventLog:System` | System-level events |
| `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Process creation, network connections, file events |

---

## Key Sysmon Event IDs to Know

| Event ID | Description | Why It Matters |
|----------|-------------|----------------|
| 1 | Process Creation | Detects suspicious processes |
| 3 | Network Connection | Detects C2 communication |
| 7 | Image/DLL Loaded | Detects DLL hijacking |
| 11 | File Created | Detects malware drops |
| 13 | Registry Value Set | Detects persistence |
| 22 | DNS Query | Detects suspicious domains |

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| No logs appearing in Splunk | Check Forwarder service is running: `Get-Service SplunkForwarder` |
| Can't reach Splunk from Forwarder | Make sure port `9997` is open in Windows Firewall |
| Sysmon logs missing | Verify Sysmon is running: `Get-Service Sysmon64` |
| Wrong index | Ensure `index=endpoint` matches in both `inputs.conf` and Splunk |
| Authentication error in Splunk | Re-check admin credentials set during install |

---

## Notes

- If running on a single machine, use `127.0.0.1` as the Splunk IP in `outputs.conf`
- If running on separate VMs, both must be on the same virtual network
- Sysmon config is based on [Olaf Hartong's sysmon-modular](https://github.com/olafhartong/sysmon-modular)

---
