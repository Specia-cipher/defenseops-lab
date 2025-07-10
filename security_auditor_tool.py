#!/usr/bin/env python3
import os
import sys
import json
import argparse
import datetime
import subprocess

# Colors
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def banner():
    print(f"""{YELLOW}
===============================================
 🛡️ DefenseOps: Security Auditor Tool
===============================================
{RESET}""")

def is_docker():
    try:
        with open('/proc/1/cgroup', 'rt') as ifh:
            return 'docker' in ifh.read()
    except:
        return False

def find_world_writable():
    print("[+] Checking for world-writable files...")
    ww_files = []
    for root, dirs, files in os.walk("."):
        for name in files:
            try:
                path = os.path.join(root, name)
                mode = os.stat(path).st_mode
                if mode & 0o002:
                    ww_files.append(path)
            except:
                continue
    if ww_files:
        print(f"{RED}[!] Found world-writable files:{RESET}")
        for f in ww_files:
            print(f"    - {f}")
    else:
        print(f"{GREEN}✓ No world-writable files found.{RESET}")
    return ww_files

def find_suid_binaries():
    print("[+] Checking for SUID binaries...")
    suid_bins = []
    try:
        output = subprocess.getoutput("find / -perm -4000 -type f 2>/dev/null")
        suid_bins = output.splitlines()
    except:
        pass

    if suid_bins:
        print(f"{RED}[!] Found SUID binaries:{RESET}")
        for b in suid_bins:
            print(f"    - {b}")
    else:
        print(f"{GREEN}✓ No SUID binaries found.{RESET}")
    return suid_bins

def check_telnet():
    print("[+] Checking telnet service status...")
    try:
        status = subprocess.getoutput("systemctl is-active telnet")
    except:
        status = "unknown"
    print(f"[+] Telnet status: {status}")
    return status

def save_json(data, filename):
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)
        print(f"{GREEN}[+] JSON report saved as {filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Failed to save JSON report: {e}{RESET}")

def main():
    parser = argparse.ArgumentParser(description="DefenseOps Security Auditor Tool")
    parser.add_argument('--json', help="Save results to JSON file")
    args = parser.parse_args()

    banner()
    docker_env = is_docker()
    print(f"[+] Environment: {'Docker' if docker_env else 'Non-Docker'}")

    ww_files = find_world_writable()
    suid_bins = find_suid_binaries() if docker_env else []
    telnet_status = check_telnet()

    now = datetime.datetime.utcnow().isoformat()
    summary = {
        "scanned_at": now,
        "system_type": "Docker" if docker_env else "Non-Docker",
        "world_writable": ww_files,
        "suid_binaries": suid_bins,
        "telnet_status": telnet_status
    }

    print(f"""
===== Audit Summary =====
World-writable files: {len(ww_files)}
SUID binaries:        {len(suid_bins)}
Telnet service:       {telnet_status}
=========================""")
    
    if args.json:
        save_json(summary, args.json)

if __name__ == "__main__":
    main()
