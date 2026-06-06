## Sysmon Setup

**Download:** https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon  
**Config Used:** Olaf Hartong's sysmon-modular (recommended)

### Steps:
1. Download Sysmon64.exe
2. Download sysmon-config.xml (included in Configs/)
3. Install with config:
   `sysmon64.exe -accepteula -i Configs\sysmon-config.xml`
4. Verify in Event Viewer:
   Applications and Service Logs → Microsoft → Windows → Sysmon → Operational

### Key Event IDs Monitored:
| Event ID | Description |
|----------|-------------|
| 1 | Process Creation |
| 3 | Network Connection |
| 7 | Image Loaded |
| 11 | File Created |
| 13 | Registry Value Set |
| 22 | DNS Query |
