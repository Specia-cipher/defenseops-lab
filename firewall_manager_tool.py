#!/usr/bin/env python3
import argparse
import os
import sys

FIREWALL_RULES_FILE = "firewall_rules.conf"

def load_rules():
    if not os.path.exists(FIREWALL_RULES_FILE):
        return []
    with open(FIREWALL_RULES_FILE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def save_rules(rules):
    with open(FIREWALL_RULES_FILE, "w") as f:
        for rule in rules:
            f.write(rule + "\n")

def list_rules():
    rules = load_rules()
    if not rules:
        print("[*] No firewall rules found.")
    else:
        print("[+] Current Firewall Rules:")
        for idx, rule in enumerate(rules, 1):
            print(f"  {idx}. {rule}")

def add_rule(rule):
    rules = load_rules()
    if rule in rules:
        print("[-] Rule already exists.")
    else:
        rules.append(rule)
        save_rules(rules)
        print(f"[+] Rule added: {rule}")

def delete_rule(rule):
    rules = load_rules()
    if rule in rules:
        rules.remove(rule)
        save_rules(rules)
        print(f"[+] Rule deleted: {rule}")
    else:
        print("[-] Rule not found.")

def flush_rules():
    save_rules([])
    print("[+] All firewall rules cleared.")

def main():
    parser = argparse.ArgumentParser(description="Firewall Manager Tool")
    subparsers = parser.add_subparsers(dest="command")

    # List rules
    subparsers.add_parser("list", help="List all firewall rules")

    # Add rule
    add_parser = subparsers.add_parser("add", help="Add a new firewall rule")
    add_parser.add_argument("rule", help="Firewall rule to add (e.g., block 192.168.1.100)")

    # Delete rule
    del_parser = subparsers.add_parser("delete", help="Delete an existing firewall rule")
    del_parser.add_argument("rule", help="Firewall rule to delete")

    # Flush rules
    subparsers.add_parser("flush", help="Clear all firewall rules")

    args = parser.parse_args()

    if args.command == "list":
        list_rules()
    elif args.command == "add":
        add_rule(args.rule)
    elif args.command == "delete":
        delete_rule(args.rule)
    elif args.command == "flush":
        flush_rules()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
