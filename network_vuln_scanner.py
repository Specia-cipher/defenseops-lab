import sys
import json
import socket
import argparse
import shutil
import subprocess
from datetime import datetime

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def banner():
    print(f"""{YELLOW}
==========================================
 🛡️ DefenseOps: Network Vulnerability Scanner
==========================================
{RESET}""")

def is_docker_native():
    """Check if nmap is installed (Docker-friendly environment)"""
    return shutil.which("nmap") is not None

def native_scan(targets, ports):
    """Run nmap scan"""
    print(f"{GREEN}[+] Native scan enabled (Docker/Desktop){RESET}")
    for target in targets:
        print(f"[+] Scanning {target} with nmap...")
        try:
            subprocess.run(
                ["nmap", "-p", ports, target],
                check=True
            )
        except subprocess.CalledProcessError:
            print(f"{RED}[!] Nmap scan failed for {target}{RESET}")

def simulated_scan(targets, ports):
    """Fallback simulated scan"""
    print(f"{YELLOW}[!] Simulated scan (Termux/mobile){RESET}")
    open_ports = {}
    for target in targets:
        open_ports[target] = []
        for port in range(1, 1025):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports[target].append(port)
                    print(f"{GREEN}[+] {target}:{port} OPEN{RESET}")
                sock.close()
            except socket.error:
                print(f"{RED}[!] Could not connect to {target}{RESET}")
    return open_ports

def save_report(report, filename):
    now = datetime.utcnow().isoformat()
    data = {
        "report_generated": now,
        "scan_results": report
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{GREEN}[+] Report saved to {filename}{RESET}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("targets_file", help="File with targets")
    parser.add_argument("--ports", default="1-1024", help="Ports to scan (default: 1-1024)")
    parser.add_argument("--report", help="Save report to JSON")
    args = parser.parse_args()

    try:
        with open(args.targets_file, "r") as f:
            targets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[!] Targets file not found: {args.targets_file}{RESET}")
        sys.exit(1)

    if is_docker_native():
        native_scan(targets, args.ports)
    else:
        results = simulated_scan(targets, args.ports)
        if args.report:
            save_report(results, args.report)

if __name__ == "__main__":
    main()
