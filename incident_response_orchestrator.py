#!/usr/bin/env python3
"""
DefenseOps Lab - Incident Response Orchestrator Tool
Author: Sanni Idris
Repo: https://github.com/Specia-cipher/defenseops-lab
"""

import sys
import json
import argparse
from datetime import datetime

# ANSI colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Response playbooks for incidents
PLAYBOOKS = {
    "malware": [
        "Isolate infected systems",
        "Run antivirus scans and remove malware",
        "Change passwords on affected accounts",
        "Review firewall rules to block C2 servers"
    ],
    "unauthorized_access": [
        "Lock affected user accounts",
        "Reset compromised credentials",
        "Review and tighten access controls",
        "Enable multi-factor authentication"
    ],
    "data_breach": [
        "Identify compromised data",
        "Notify relevant stakeholders and regulatory bodies",
        "Strengthen perimeter security",
        "Perform forensic investigation"
    ],
    "dos_attack": [
        "Enable rate limiting on services",
        "Blacklist attacking IP addresses",
        "Work with ISP for traffic filtering",
        "Scale infrastructure if necessary"
    ]
}


def banner():
    print(f"""{YELLOW}
===============================================
 🛡️ DefenseOps: Incident Response Orchestrator
===============================================
{RESET}""")


def load_incidents(filename):
    try:
        with open(filename, "r") as f:
            incidents = json.load(f)
        return incidents
    except Exception as e:
        print(f"{RED}[!] Failed to load incidents: {e}{RESET}")
        sys.exit(1)


def respond_to_incidents(incidents, auto_remediate=False):
    responses = []
    for incident in incidents.get("incidents", []):
        incident_type = incident.get("type")
        host = incident.get("host", "Unknown")
        detected_at = incident.get("detected_at", "Unknown")
        playbook = PLAYBOOKS.get(incident_type, ["No playbook available for this type."])

        print(f"[+] Incident: {incident_type.upper()} on {host} (Detected: {detected_at})")
        for step in playbook:
            print(f"    - {step}")

        if auto_remediate:
            print(f"{GREEN}[+] Auto-remediation triggered for {incident_type} on {host}{RESET}")
        else:
            print(f"{YELLOW}[~] Manual remediation required for {incident_type} on {host}{RESET}")

        responses.append({
            "incident": incident,
            "playbook": playbook,
            "auto_remediated": auto_remediate
        })

    return responses


def save_report(responses, output_file):
    try:
        now = datetime.utcnow().isoformat()
        report = {
            "generated_at": now,
            "responses": responses
        }
        with open(output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"{GREEN}[+] JSON report saved as {output_file}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Failed to save report: {e}{RESET}")


def main():
    banner()
    parser = argparse.ArgumentParser(description="DefenseOps Incident Response Orchestrator")
    parser.add_argument("incident_file", help="JSON file containing detected incidents")
    parser.add_argument("--auto-remediate", action="store_true", help="Perform automatic remediation")
    parser.add_argument("--json", metavar="FILE", help="Save response report as JSON")
    args = parser.parse_args()

    incidents = load_incidents(args.incident_file)
    responses = respond_to_incidents(incidents, auto_remediate=args.auto_remediate)

    if args.json:
        save_report(responses, args.json)


if __name__ == "__main__":
    main()
