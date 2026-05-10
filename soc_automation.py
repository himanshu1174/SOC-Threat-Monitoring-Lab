import requests
import json
from jira import JIRA
from datetime import datetime


JIRA_URL     = "https://hr478867.atlassian.net"
JIRA_EMAIL   = "hr478867@gmail.com"
JIRA_TOKEN   = "y JIRA TOKEN"       
VT_API_KEY   = "Vt API KEY"  
JIRA_PROJECT = "SCRUM"

# --- MITRE ATT&CK MAPPING --- #
MITRE_MAP = {
    "brute_force": {
        "id":     "T1110",
        "name":   "Brute Force",
        "tactic": "Credential Access",
        "desc":   "Adversary attempting to gain access by trying many passwords"
    },
    "suspicious_process": {
        "id":     "T1059",
        "name":   "Command and Scripting Interpreter",
        "tactic": "Execution",
        "desc":   "Adversary abusing PowerShell/CMD to execute malicious commands"
    },
    "beaconing": {
        "id":     "T1071",
        "name":   "Application Layer Protocol",
        "tactic": "Command and Control",
        "desc":   "Adversary communicating with C2 server over standard protocols"
    }
}


# FUNCTION 1: Check IOC on VirusTotal

def check_virustotal(ioc, ioc_type="ip"):
    print(f"\n[*] Checking VirusTotal for {ioc_type}: {ioc}")
    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"

        headers  = {"x-apikey": VT_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data       = response.json()
            stats      = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)

            print(f"    [+] Malicious  : {malicious}")
            print(f"    [+] Suspicious : {suspicious}")
            print(f"    [+] Harmless   : {harmless}")
            print(f"    [+] Reputation : {reputation}")

            return {
                "malicious":  malicious,
                "suspicious": suspicious,
                "harmless":   harmless,
                "reputation": reputation,
                "vt_link":    f"https://www.virustotal.com/gui/ip-address/{ioc}"
            }

        elif response.status_code == 404:
            print("    [-] IOC not found in VirusTotal")
            return {"malicious": 0, "suspicious": 0,
                    "harmless": 0, "reputation": 0,
                    "vt_link": "Not found"}
        else:
            print(f"    [!] VT API error: {response.status_code} — skipping VT")
            return None

    except Exception as e:
        print(f"    [!] VT check failed: {e} — skipping VT")
        return None


# FUNCTION 2: Determine Severity
# ============================================================
def get_severity(alert_type, vt_data):
    if vt_data and vt_data.get("malicious", 0) > 5:
        return "Critical"
    elif alert_type == "brute_force":
        return "High"
    elif alert_type == "beaconing":
        return "High"
    elif alert_type == "suspicious_process":
        return "Medium"
    return "Low"

# ============================================================
# FUNCTION 3: Create Jira Ticket
# ============================================================
def create_jira_ticket(alert_type, ioc, source_ip,
                       hostname, event_count, vt_data):
    print(f"\n[*] Connecting to Jira...")
    try:
        jira = JIRA(
            server=JIRA_URL,
            basic_auth=(JIRA_EMAIL, JIRA_TOKEN)
        )
        print("    [+] Jira connected successfully")
    except Exception as e:
        print(f"    [!] Jira connection failed: {e}")
        return None

    mitre     = MITRE_MAP.get(alert_type, MITRE_MAP["brute_force"])
    severity  = get_severity(alert_type, vt_data)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build VirusTotal section
    if vt_data:
        vt_section = f"""
*VirusTotal Analysis:*
- Malicious Detections : {vt_data.get('malicious', 'N/A')}
- Suspicious           : {vt_data.get('suspicious', 'N/A')}
- Harmless             : {vt_data.get('harmless', 'N/A')}
- Reputation Score     : {vt_data.get('reputation', 'N/A')}
- VT Report Link       : {vt_data.get('vt_link', 'N/A')}
"""
    else:
        vt_section = "\n*VirusTotal:* Not available\n"

    # Build ticket description
    description = f"""
h2. SOC ALERT — {mitre['name']}

*Alert Generated:* {timestamp}
*Severity:* {severity}
*Host:* {hostname}

----

h3. Incident Details

| Field          | Value                                      |
| Alert Type     | {alert_type.replace('_', ' ').title()}     |
| Source IP      | {source_ip}                                |
| IOC            | {ioc}                                      |
| Hostname       | {hostname}                                 |
| Event Count    | {event_count}                              |
| Detection Time | {timestamp}                                |

----

h3. MITRE ATT&CK Mapping

| Field       | Value                            |
| Technique   | {mitre['id']} - {mitre['name']} |
| Tactic      | {mitre['tactic']}               |
| Description | {mitre['desc']}                 |

----

h3. Threat Intelligence
{vt_section}

----

h3. Recommended Actions

# Isolate affected host: {hostname}
# Block source IP at firewall: {source_ip}
# Collect memory dump and forensic logs
# Review all authentication logs for {source_ip}
# Check lateral movement from {hostname}
# Update firewall and IDS/IPS rules
# Document findings and close with RCA

----

h3. References
- MITRE ATT&CK : https://attack.mitre.org/techniques/{mitre['id']}/
- Splunk Query  : index=wineventlog EventCode=4625 Source_Network_Address={source_ip}
- Lab GitHub    : https://github.com/himanshu1174/SOC-Threat-Monitoring-Lab

----
_Auto-generated by SOC Automation Script | Himanshu Raj Singh_
"""

    print(f"\n[*] Creating Jira ticket...")
    try:
        issue = jira.create_issue(
            project     = JIRA_PROJECT,
            summary     = f"[{severity.upper()}] {mitre['id']} - {mitre['name']} detected from {source_ip} on {hostname}",
            description = description,
            issuetype   = {"name": "Task"}
        )
        print(f"    [+] Ticket created : {issue.key}")
        print(f"    [+] URL            : {JIRA_URL}/browse/{issue.key}")
        return issue.key

    except Exception as e:
        print(f"    [!] Ticket creation failed: {e}")
        return None

# ============================================================
# MAIN — Simulated Splunk Alerts
# ============================================================
def main():
    print("=" * 60)
    print("  SOC THREAT MONITORING & IOC ANALYSIS LAB")
    print("  Splunk → VirusTotal → MITRE ATT&CK → Jira")
    print("=" * 60)

    # Alerts detected from your real Splunk lab
    alerts = [
        {
            "alert_type":  "brute_force",
            "ioc":         "192.168.168.128",
            "source_ip":   "192.168.168.128",
            "hostname":    "DESKTOP-5K4TE4R",
            "event_count": 14
        },
        {
            "alert_type":  "beaconing",
            "ioc":         "150.171.110.81",
            "source_ip":   "150.171.110.81",
            "hostname":    "DESKTOP-5K4TE4R",
            "event_count": 12
        },
        {
            "alert_type":  "suspicious_process",
            "ioc":         "192.168.168.130",
            "source_ip":   "192.168.168.130",
            "hostname":    "DESKTOP-5K4TE4R",
            "event_count": 22
        }
    ]

    for alert in alerts:
        print(f"\n{'='*60}")
        print(f"[!] ALERT : {alert['alert_type'].upper()}")
        print(f"    IOC         : {alert['ioc']}")
        print(f"    Source IP   : {alert['source_ip']}")
        print(f"    Host        : {alert['hostname']}")
        print(f"    Event Count : {alert['event_count']}")

        # Step 1: VirusTotal enrichment
        vt_data = check_virustotal(alert["ioc"])

        # Step 2: Create Jira ticket
        ticket = create_jira_ticket(
            alert_type  = alert["alert_type"],
            ioc         = alert["ioc"],
            source_ip   = alert["source_ip"],
            hostname    = alert["hostname"],
            event_count = alert["event_count"],
            vt_data     = vt_data
        )

        if ticket:
            print(f"\n    ✅ Incident response initiated: {ticket}")
        else:
            print(f"\n    ❌ Ticket creation failed for {alert['ioc']}")

    print(f"\n{'='*60}")
    print("  AUTOMATION COMPLETE")
    print("=" * 60)

if __name__ == "__main__":
    main()
