#!/usr/bin/env python3
import socket
import argparse
import json
from datetime import datetime

def scan_port(host, port, timeout=1):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((host, port))
            if result == 0:
                try:
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = s.recv(1024).decode(errors="ignore").strip()
                except Exception:
                    banner = "No banner"
                return (port, banner)
    except Exception:
        pass
    return None

def scan_host(host, start_port, end_port, quiet=False):
    print(f"[+] Starting scan on {host}:{start_port}-{end_port}")
    open_ports = []
    for port in range(start_port, end_port + 1):
        result = scan_port(host, port)
        if result:
            port, banner = result
            open_ports.append({"port": port, "banner": banner})
            if not quiet:
                print(f"[OPEN] {host}:{port} - {banner}")
    print(f"[+] Scan complete: {len(open_ports)} open ports found")
    return open_ports

def save_report(host, open_ports, filename, json_format=False):
    if json_format:
        report = {
            "host": host,
            "scan_time": datetime.now().isoformat(),
            "open_ports": open_ports
        }
        with open(filename, "w") as f:
            json.dump(report, f, indent=4)
    else:
        with open(filename, "w") as f:
            f.write(f"Scan Report for {host}\n")
            f.write(f"Generated: {datetime.now()}\n\n")
            for entry in open_ports:
                f.write(f"Port {entry['port']} - {entry['banner']}\n")
    print(f"[+] Report saved to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Network Vulnerability Scanner")
    parser.add_argument("target", help="Target hostname or IP address")
    parser.add_argument("--ports", help="Port range (default: 1-1024)", default="1-1024")
    parser.add_argument("--quiet", action="store_true", help="Show only open ports")
    parser.add_argument("--report", help="Save scan results to file")
    parser.add_argument("--json", action="store_true", help="Save report in JSON format")
    args = parser.parse_args()

    start_port, end_port = map(int, args.ports.split("-"))
    open_ports = scan_host(args.target, start_port, end_port, args.quiet)

    if args.report:
        save_report(args.target, open_ports, args.report, args.json)

if __name__ == "__main__":
    main()
