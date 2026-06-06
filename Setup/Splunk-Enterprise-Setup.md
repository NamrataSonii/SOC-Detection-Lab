## Splunk Enterprise Setup

**Download:** https://www.splunk.com/en_us/download/splunk-enterprise.html  
**Version Used:** 9.x  
**Installed On:** Windows Server / Ubuntu (mention your OS)

### Steps:
1. Run the installer and follow the setup wizard
2. Set admin username and password
3. Access Splunk Web at: http://localhost:8000
4. Go to Settings → Indexes → Create new index named `endpoint`
5. Go to Settings → Forwarding and Receiving → Configure Receiving → Add port `9997`
