#!/usr/bin/env python3
import argparse
import re
import os
import sys
from datetime import datetime
from firewall_manager_tool import add_rule

SIGNATURES_FILE = "signatures.conf"
ALERTS_FILE = "alerts.log"

def load_signatures():
    if not os.path.exists(SIGNATURES_FILE):
        return []
    with open(SIGNATURES_FILE, "r") as f:
        return [line.strip() for line in f if line.strip()]

def save_signature(pattern):
    with open(SIGNATURES_FILE, "a") as f:
        f.write(pattern + "\n")

def flush_signatures():
    open(SIGNATURES_FILE, "w").close()
    print("[+] All signatures flushed.")

def log_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(ALERTS_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def view_alerts():
    if not os.path.exists(ALERTS_FILE):
        print("[!] No alerts logged yet.")
        return
    with open(ALERTS_FILE, "r") as f:
        alerts = f.read()
        print("\n--- Alerts Log ---")
        print(alerts.strip() if alerts.strip() else "[!] No alerts logged yet.")
        print("-------------------\n")

def clear_alerts():
    open(ALERTS_FILE, "w").close()
    print("[+] Alerts log cleared.")

def scan_log(file_path, dry_run=False):
    if not os.path.exists(file_path):
        print("[-] Log file not found.")
        return
    signatures = load_signatures()
    if not signatures:
        print("[-] No signatures loaded. Add some first.")
        return

    total_lines = 0
    alerts_triggered = 0
    ips_blocked = set()

    print(f"[+] Scanning: {file_path}")
    with open(file_path, "r") as f:
        for idx, line in enumerate(f, 1):
            total_lines += 1
            for sig in signatures:
                if re.search(sig, line):
                    alert_msg = f"ALERT! Signature match on line {idx}: {line.strip()}"
                    print(f"[!] {alert_msg}")
                    log_alert(alert_msg)
                    alerts_triggered += 1

                    # Auto-block IP if detected
                    ip_match = re.search(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", line)
                    if ip_match:
                        ip = ip_match.group()
                        if ip not in ips_blocked:
                            if not dry_run:
                                add_rule(f"block {ip}")
                            ips_blocked.add(ip)
                            print(f"[+] IP {'(dry run) would block' if dry_run else 'blocked'}: {ip}")
                    break

    print("\nScan Summary")
    print(f"• Total lines scanned: {total_lines}")
    print(f"• Alerts triggered: {alerts_triggered}")
    print(f"• IPs {'to be blocked' if dry_run else 'auto-blocked'}: {len(ips_blocked)}")

def interactive_menu():
    while True:
        print("\nDefenseOps IDS Tool")
        print("--------------------")
        print("1. Add Signature")
        print("2. List Signatures")
        print("3. Flush Signatures")
        print("4. Scan Log File")
        print("5. View Alerts")
        print("6. Clear Alerts")
        print("7. Exit")
        choice = input("Select option: ").strip()

        if choice == "1":
            pattern = input("Enter regex pattern to add: ").strip()
            save_signature(pattern)
            print(f"[+] Signature added: {pattern}")
        elif choice == "2":
            sigs = load_signatures()
            if sigs:
                print("\n--- Signatures ---")
                for idx, sig in enumerate(sigs, 1):
                    print(f"{idx}. {sig}")
                print("------------------")
            else:
                print("[!] No signatures found.")
        elif choice == "3":
            flush_signatures()
        elif choice == "4":
            file_path = input("Enter path to log file: ").strip()
            dry = input("Dry run? (y/N): ").lower() == "y"
            scan_log(file_path, dry_run=dry)
        elif choice == "5":
            view_alerts()
        elif choice == "6":
            clear_alerts()
        elif choice == "7":
            print("[+] Exiting IDS Tool.")
            break
        else:
            print("[-] Invalid option.")

def cli_mode():
    parser = argparse.ArgumentParser(description="DefenseOps IDS Tool")
    parser.add_argument("--add", help="Add a signature pattern")
    parser.add_argument("--list", action="store_true", help="List all signatures")
    parser.add_argument("--flush", action="store_true", help="Flush all signatures")
    parser.add_argument("--scan", metavar="LOGFILE", help="Scan a log file")
    parser.add_argument("--view-alerts", action="store_true", help="View alerts log")
    parser.add_argument("--clear-alerts", action="store_true", help="Clear alerts log")
    parser.add_argument("--dry-run", action="store_true", help="Dry run: no firewall actions")
    args = parser.parse_args()

    if args.add:
        save_signature(args.add)
        print(f"[+] Signature added: {args.add}")
    elif args.list:
        sigs = load_signatures()
        if sigs:
            print("\n--- Signatures ---")
            for idx, sig in enumerate(sigs, 1):
                print(f"{idx}. {sig}")
            print("------------------")
        else:
            print("[!] No signatures found.")
    elif args.flush:
        flush_signatures()
    elif args.scan:
        scan_log(args.scan, dry_run=args.dry_run)
    elif args.view_alerts:
        view_alerts()
    elif args.clear_alerts:
        clear_alerts()
    else:
        interactive_menu()

if __name__ == "__main__":
    cli_mode()
