🛡️ SIEM SOC Dashboard - Home Lab Edition
מערכת SIEM ביתית מלאה - Detection Engine, SOC Dashboard, MITRE ATT&CK Mapping, Telegram AlertsBuilt from scratch with Python, Elasticsearch, Flask & JavaScript



🎯 Project Overview
A fully functional Security Information and Event Management (SIEM) system built for a home lab environment. The system collects Windows logs via Sysmon + Winlogbeat, processes them through a custom Python Detection Engine with 18 MITRE ATT&CK-mapped rules, and displays real-time alerts in a SOC-style web dashboard.




## Architecture

```text
┌──────────────┐     Winlogbeat      ┌──────────────────┐     Python Engine     ┌─────────────┐
│  Windows MA  │ ─── Sysmon logs ─→ │  Elasticsearch   │ ──── 18 Rules ─────→ │  Dashboard  │
│  (Endpoint)  │     Port 9200       │  (Kali Linux)    │    MITRE ATT&CK      │  Flask + JS │
└──────────────┘                     └──────────────────┘                       └─────────────┘
                                                                                       │
                                                                                       │
                                                                                ┌──────┴──────┐
                                                                                │  Telegram   │
                                                                                │  Alerts 📱  │
                                                                                └─────────────┘
```




🔥 Detection Rules (18 Rules — MITRE ATT&CK Mapped)

| Rule | Name                     | Severity |
|------|--------------------------|----------|
| R01  | Suspicious PowerShell    | HIGH     |
| R02  | Hacking Tool Detected    | CRITICAL |
| R03  | Network Scan             | MEDIUM   |
| R04  | New User Created         | HIGH     |
| R05  | Registry Persistence     | HIGH     |
| R06  | C2 Connection            | CRITICAL |
| R07  | Brute Force              | HIGH     |
| R08  | Malicious Macro          | HIGH     |
| R09  | Lateral Movement         | CRITICAL |
| R10  | Scheduled Task           | MEDIUM   |
| R11  | New Service              | HIGH     |
| R12  | Suspicious DNS (C2)      | MEDIUM   |
| R13  | Executable in Temp       | MEDIUM   |
| R14  | Phishing URL             | HIGH     |
| R15  | Ransomware Activity      | CRITICAL |
| R16  | Malware Hash             | CRITICAL |
| R17  | Suspicious Download      | HIGH     |
| R18  | Data Exfiltration        | CRITICAL |


🏗️ Project Structure
siem-project/
├── siem_engine.py          # Main detection engine — polls Elasticsearch, runs rules
├── detection_rules.py      # 18 detection rules with MITRE ATT&CK mapping
├── dashboard.py            # Flask web server — serves dashboard + API
├── generate_alerts.py      # Alert generator for demo/testing (12,000 events)
├── alerts.json             # Alert storage (auto-generated)
├── static/
│   └── index.html          # SOC Dashboard web interface
├── SIEM_Dashboard.jsx      # React version of dashboard (for portfolio)
└── SIEM_Dashboard_Live.html # Standalone demo (no server needed)

🚀 Quick Start
Prerequisites
	∙	Kali Linux VM (or any Linux with Python 3)
	∙	Windows VM with Sysmon installed
	∙	VMware Workstation (both VMs on same subnet)

Step 1 - Install Elasticsearch on Kali
sudo apt update && sudo apt install -y default-jdk
wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-8.12.0-amd64.deb
sudo dpkg -i elasticsearch-8.12.0-amd64.deb


Edit /etc/elasticsearch/elasticsearch.yml:
network.host: 0.0.0.0
xpack.security.enabled: false
xpack.security.enrollment.enabled: false
xpack.security.http.ssl.enabled: false
xpack.security.transport.ssl.enabled: false

# Limit RAM to prevent crashes
echo -e "-Xms512m\n-Xmx512m" | sudo tee /etc/elasticsearch/jvm.options.d/memory.options
sudo systemctl enable elasticsearch && sudo systemctl start elasticsearch



Step 2 - Install Sysmon + Winlogbeat on Windows
:: Install Sysmon
Sysmon64.exe -accepteula -i sysmonconfig-export.xml


Edit winlogbeat.yml:
winlogbeat.event_logs:
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Security
  - name: System

output.elasticsearch:
  hosts: ["<KALI_IP>:9200"]
  index: "winlogbeat-%{+yyyy.MM.dd}"

setup.ilm.enabled: false
setup.template.name: "winlogbeat"
setup.template.pattern: "winlogbeat-*"


.\install-service-winlogbeat.ps1
Start-Service winlogbeat

Step 3 - Start SIEM Engine
cd ~/siem-project
pip3 install elasticsearch requests flask --break-system-packages
python3 siem_engine.py &
python3 dashboard.py &


Step 4 - Open Dashboard
http://localhost:5000



Step 5 - Generate Test Attacks (on Windows)
powershell -ExecutionPolicy Bypass -EncodedCommand SQBFAFgA
net user hacker$ Pass123! /add && net user hacker$ /delete
schtasks /create /tn "evil" /tr "cmd.exe" /sc daily
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v Backdoor /t REG_SZ /d "C:\evil.exe" /f



📱 Telegram Alerts (Optional)
	1.	Create a bot via @BotFather → get Token
	2.	Send a message to the bot → get chat_id from https://api.telegram.org/bot<TOKEN>/getUpdates
	3.	Edit siem_engine.py — replace YOUR_BOT_TOKEN and YOUR_CHAT_ID



🎯 Demo Mode
Run the standalone dashboard without any infrastructure:
# Generate 12,000 realistic alerts
python3 generate_alerts.py

# Start dashboard
python3 dashboard.py



🛠️ Technologies Used

| Component         | Technology                  |
|------------------|-----------------------------|
| Log Collection   | Sysmon + Winlogbeat 8.12.0  |
| Log Storage      | Elasticsearch 8.12.0        |
| Detection Engine | Python 3 (custom rules)     |
| Web Dashboard    | Flask + Vanilla JS          |
| Alert Delivery   | Telegram Bot API            |
| Threat Framework | MITRE ATT&CK                |
| Lab Environment  | VMware Workstation          |



📚 What I Learned
	∙	Building a SIEM pipeline from scratch: collection → storage → detection → visualization
	∙	Writing detection rules based on Windows Event IDs and Sysmon events
	∙	Mapping threats to MITRE ATT&CK framework
	∙	Working with Elasticsearch APIs for log querying
	∙	Full-stack development: Python backend + JS frontend
	∙	Real-world SOC analyst workflow: triage, investigation, response
