#!/usr/bin/env python3

import argparse
import json
import os
import sys
import datetime
import time

# ANSI colors for CLI
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BLUE = "\033[94m"
RESET = "\033[0m"

def banner():
    print(f"""{BLUE}
===============================================
 🛡️ DefenseOps: Incident Response Orchestrator
===============================================
{RESET}""")

def load_incidents(file_path):
    if not os.path.exists(file_path):
        print(f"{RED}[!] Incident file not found: {file_path}{RESET}")
        sys.exit(1)
    with open(file_path, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"{RED}[!] Failed to parse JSON incidents in {file_path}{RESET}")
            sys.exit(1)

def triage_incident(incident):
    print(f"{YELLOW}[+] Triage: {incident['id']} - {incident['description']}{RESET}")
    time.sleep(1)  # Simulate time for triage

def isolate_system(system):
    print(f"{RED}[!] Isolating system: {system}{RESET}")
    time.sleep(1)  # Simulate isolation step

def remediate_issue(incident):
    print(f"{GREEN}[+] Remediating: {incident['remediation']}{RESET}")
    time.sleep(1)  # Simulate remediation step

def orchestrate_response(incidents, dry_run=False):
    for incident in incidents:
        triage_incident(incident)
        if not dry_run:
            isolate_system(incident["affected_system"])
            remediate_issue(incident)
        else:
            print(f"{YELLOW}[~] Dry run: No isolation or remediation performed for {incident['id']}{RESET}")

def save_report(incidents, file_path):
    now = datetime.datetime.utcnow().isoformat()
    report = {
        "orchestrated_at": now,
        "total_incidents": len(incidents),
        "incidents": incidents
    }
    with open(file_path, "w") as f:
        json.dump(report, f, indent=4)
    print(f"{GREEN}[+] Incident response report saved as {file_path}{RESET}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="DefenseOps Incident Response Orchestrator")
    parser.add_argument("incidents_file", help="JSON file with incidents")
    parser.add_argument("--dry-run", action="store_true", help="Simulate response without making changes")
    parser.add_argument("--report", help="Save orchestration report to JSON")
    args = parser.parse_args()

    incidents = load_incidents(args.incidents_file)
    orchestrate_response(incidents, dry_run=args.dry_run)

    if args.report:
        save_report(incidents, args.report)

if __name__ == "__main__":
    main()
