# SOC-Threat-Monitoring-Lab
A complete SOC lab with Splunk, Sysmon, Kali Linux, VirusTotal API, MITRE ATT&amp;CK mapping and Jira automation
# SOC Threat Monitoring & IOC Analysis Lab

![Platform](https://img.shields.io/badge/Platform-Splunk-green)
![MITRE](https://img.shields.io/badge/Framework-MITRE%20ATT%26CK-red)
![License](https://img.shields.io/badge/License-MIT-blue)

## Overview
A fully functional Security Operations Center (SOC) home lab that simulates real-world cyber attacks, detects them using Splunk SIEM, enriches IOCs via VirusTotal, maps to MITRE ATT&CK, and auto-creates Jira incident tickets using Python automation.

---

## Architecture
Kali Linux (Attacker) ──► Windows 10 (Victim) ──► Splunk SIEM (Host)
192.168.168.128              192.168.168.130         192.168.168.1
│
Sysmon + UF
│
┌─────────▼─────────┐
│   Splunk Indexes   │
│  wineventlog       │
│  sysmon            │
└─────────┬─────────┘
│
┌─────────▼─────────┐
│  Python Automation │
│  soc_automation.py │
└──┬────────────┬───┘
│            │
VirusTotal API      Jira API
(IOC Enrichment)  (Auto Tickets)
---

## Tools & Technologies
| Tool | Purpose |
|------|---------|
| Splunk SIEM | Log ingestion, detection, reporting |
| Sysmon v15.20 | Endpoint telemetry on Windows 10 |
| Splunk Universal Forwarder | Log shipping to Splunk |
| Kali Linux | Attack simulation |
| VirusTotal API | IOC enrichment |
| Jira | Incident ticket management |
| Python 3 | SOC automation script |
| MITRE ATT&CK | Threat classification framework |

---

## MITRE ATT&CK Coverage
| Technique | ID | Tactic | Severity |
|-----------|----|--------|----------|
| Brute Force | T1110 | Credential Access | HIGH |
| Command & Scripting Interpreter | T1059 | Execution | HIGH |
| Application Layer Protocol | T1071 | Command & Control | HIGH |

---

## Detection Rules

### T1110 - Brute Force Detection
- **Source:** `index=wineventlog EventCode=4625`
- **Logic:** More than 5 failed logins from same source IP
- **Result:** Detected Kali (192.168.168.128) with 14 failed attempts
- **SPL File:** `brute_force_T1110.spl`

### T1059 - Suspicious Process Execution
- **Source:** `index=sysmon EventCode=1`
- **Logic:** Detects PowerShell, CMD, WScript, MSHTA executions
- **Result:** 22 suspicious process events detected
- **SPL File:** `suspicious_process_T1059.spl`

### T1071 - Network Beaconing
- **Source:** `index=sysmon EventCode=3`
- **Logic:** Repeated outbound connections to external IPs
- **Result:** OneDrive.Sync.exe → 150.171.110.81:443 → 12 connections
- **SPL File:** `network_beaconing_T1071.spl`

---

## Automation Pipeline
Splunk Alert Triggered
↓
Python script pulls alert data
↓
VirusTotal API enriches IOC
↓
MITRE ATT&CK technique mapped
↓
Jira ticket auto-created with full details
### Auto-created Jira Tickets
| Ticket | Severity | Description |
|--------|----------|-------------|
| SCRUM-5 | HIGH | T1110 - Brute Force from 192.168.168.128 |
| SCRUM-6 | HIGH | T1071 - Beaconing from 150.171.110.81 |
| SCRUM-7 | MEDIUM | T1059 - Suspicious Process from 192.168.168.130 |

---

## Setup Instructions

### 1. Prerequisites
- VMware Workstation
- Kali Linux VM
- Windows 10 VM
- Splunk (host machine)

### 2. Splunk Configuration
- Create indexes: `wineventlog`, `sysmon`
- Enable receiving on port `9997`

### 3. Windows 10 VM
- Install Sysmon v15.20 with SwiftOnSecurity config
- Install Splunk Universal Forwarder
- Configure `inputs.conf` and `outputs.conf` (see repo files)
- Set SplunkForwarder service to run as `LocalSystem`

### 4. Python Automation
```bash
pip install requests jira
```
- Add your API keys to `soc_automation.py`
- Run: `python soc_automation.py`

---

## Repository Structure
SOC-Threat-Monitoring-Lab/
├── soc_automation.py            # Main automation script
├── inputs.conf                  # Splunk UF input config
├── outputs.conf                 # Splunk UF output config
├── brute_force_T1110.spl        # SPL query - Brute Force
├── suspicious_process_T1059.spl # SPL query - Process Execution
├── network_beaconing_T1071.spl  # SPL query - Beaconing
└── README.md
## Author
**Himanshu Raj Singh**
GitHub: [himanshu1174](https://github.com/himanshu1174)
