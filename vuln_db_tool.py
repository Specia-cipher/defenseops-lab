#!/usr/bin/env python3
import json
import os
import argparse

DB_FILE = "vuln_database.json"

def load_db():
    if not os.path.exists(DB_FILE):
        return []
    with open(DB_FILE, "r") as f:
        return json.load(f)

def save_db(data):
    with open(DB_FILE, "w") as f:
        json.dump(data, f, indent=4)

def add_entry(port, service, description, cve=None):
    db = load_db()
    entry = {
        "port": port,
        "service": service,
        "description": description,
        "cve": cve
    }
    db.append(entry)
    save_db(db)
    print(f"[+] Added vulnerability: Port {port} - {service}")

def list_entries():
    db = load_db()
    if not db:
        print("[!] No vulnerabilities in database.")
        return
    print("--- Vulnerability Database ---")
    for idx, v in enumerate(db, start=1):
        print(f"{idx}. Port: {v['port']}, Service: {v['service']}, Description: {v['description']}, CVE: {v.get('cve', 'N/A')}")
    print("------------------------------")

def delete_entry(index):
    db = load_db()
    if 0 < index <= len(db):
        removed = db.pop(index - 1)
        save_db(db)
        print(f"[+] Removed: Port {removed['port']} - {removed['service']}")
    else:
        print("[-] Invalid index.")

def search_entry(term):
    db = load_db()
    results = [v for v in db if str(v["port"]) == term or term.lower() in v["service"].lower()]
    if not results:
        print("[-] No matching entries found.")
        return
    print("--- Search Results ---")
    for v in results:
        print(f"Port: {v['port']}, Service: {v['service']}, Description: {v['description']}, CVE: {v.get('cve', 'N/A')}")
    print("----------------------")

def parse_args():
    parser = argparse.ArgumentParser(description="Vulnerability Database Manager")
    subparsers = parser.add_subparsers(dest="command")

    add_parser = subparsers.add_parser("add", help="Add a vulnerability")
    add_parser.add_argument("port", type=int, help="Port number")
    add_parser.add_argument("service", help="Service name")
    add_parser.add_argument("description", help="Vulnerability description")
    add_parser.add_argument("--cve", help="Optional CVE ID")

    subparsers.add_parser("list", help="List all vulnerabilities")

    delete_parser = subparsers.add_parser("delete", help="Delete a vulnerability")
    delete_parser.add_argument("index", type=int, help="Index of entry to delete")

    search_parser = subparsers.add_parser("search", help="Search vulnerabilities")
    search_parser.add_argument("term", help="Port or service to search for")

    return parser.parse_args()

def main():
    args = parse_args()
    if args.command == "add":
        add_entry(args.port, args.service, args.description, args.cve)
    elif args.command == "list":
        list_entries()
    elif args.command == "delete":
        delete_entry(args.index)
    elif args.command == "search":
        search_entry(args.term)
    else:
        print("[-] No valid command provided. Use --help for options.")

if __name__ == "__main__":
    main()
