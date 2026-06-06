## Splunk Universal Forwarder Setup

**Download:** https://www.splunk.com/en_us/download/universal-forwarder.html  
**Installed On:** Windows 10/11 (target machine)

### Steps:
1. Run the MSI installer
2. During setup, point to Splunk Enterprise IP: `<your-splunk-ip>:9997`
3. Create `inputs.conf` at:
   `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
4. Restart the forwarder service:
   `Restart-Service SplunkForwarder`
