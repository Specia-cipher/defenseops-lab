#!/usr/bin/env python3
import os
import sys
import json
import re
from collections import Counter
from datetime import datetime

# Define critical patterns (case-insensitive)
CRITICAL_PATTERNS = [
    r"SQL injection",
    r"MALWARE",
    r"Port scan",
    r"Failed login"
]

def load_alerts(directory):
    """Load all alert files in a directory"""
    alerts = []
    for filename in os.listdir(directory):
        path = os.path.join(directory, filename)
        if os.path.isfile(path) and filename.endswith(".txt"):
            with open(path) as f:
                lines = [line.strip() for line in f if line.strip()]
                tool_name = filename.replace("_alerts.txt", "")
                for line in lines:
                    # Determine if this alert is critical
                    critical = any(re.search(pat, line, re.IGNORECASE) for pat in CRITICAL_PATTERNS)
                    alerts.append({"tool": tool_name, "alert": line, "critical": critical})
    return alerts

def extract_ips(alerts):
    """Extract IPs from alert messages"""
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ips = []
    for entry in alerts:
        ips.extend(ip_pattern.findall(entry["alert"]))
    return ips

def summarize_alerts(alerts):
    """Generate statistics and summaries"""
    summary = {
        "total_alerts": len(alerts),
        "critical_alerts": 0,
        "alerts_per_tool": {},
        "critical_per_tool": {},
        "top_ips": [],
        "top_messages": [],
        "top_critical_messages": []
    }

    # Alerts per tool
    tool_counter = Counter([entry["tool"] for entry in alerts])
    summary["alerts_per_tool"] = dict(tool_counter)

    # Critical alerts per tool
    critical_counter = Counter([entry["tool"] for entry in alerts if entry["critical"]])
    summary["critical_per_tool"] = dict(critical_counter)
    summary["critical_alerts"] = sum(critical_counter.values())

    # Top IPs
    ips = extract_ips(alerts)
    ip_counter = Counter(ips)
    summary["top_ips"] = ip_counter.most_common(5)

    # Top alert messages
    alert_texts = [entry["alert"] for entry in alerts]
    msg_counter = Counter(alert_texts)
    summary["top_messages"] = msg_counter.most_common(5)

    # Top critical messages
    critical_texts = [entry["alert"] for entry in alerts if entry["critical"]]
    critical_counter_msg = Counter(critical_texts)
    summary["top_critical_messages"] = critical_counter_msg.most_common(5)

    return summary

def save_summary(summary, filename="alert_summary.json"):
    with open(filename, "w") as f:
        json.dump(summary, f, indent=4)
    print(f"[+] Summary saved to {filename}")

def print_summary(summary):
    print("\n=== Alert Correlation Summary ===")
    print(f"Total alerts: {summary['total_alerts']}")
    print(f"Total CRITICAL alerts: {summary['critical_alerts']}\n")

    print("Alerts per tool:")
    for tool, count in summary["alerts_per_tool"].items():
        crit = summary["critical_per_tool"].get(tool, 0)
        print(f"  {tool}: {count} alerts ({crit} critical)")

    if summary["top_ips"]:
        print("\nTop IPs:")
        for ip, count in summary["top_ips"]:
            print(f"  {ip}: {count}")

    if summary["top_messages"]:
        print("\nTop alert messages:")
        for msg, count in summary["top_messages"]:
            print(f"  {count}x -> {msg}")

    if summary["top_critical_messages"]:
        print("\nTop CRITICAL messages:")
        for msg, count in summary["top_critical_messages"]:
            print(f"  {count}x -> {msg}")

    print("="*50 + "\n")

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <alerts_directory>")
        sys.exit(1)

    alerts_dir = sys.argv[1]
    if not os.path.isdir(alerts_dir):
        print(f"[!] Directory not found: {alerts_dir}")
        sys.exit(1)

    alerts = load_alerts(alerts_dir)
    if not alerts:
        print("[!] No alerts found in directory.")
        sys.exit(0)

    summary = summarize_alerts(alerts)
    print_summary(summary)
    save_summary(summary)

if __name__ == "__main__":
    main()
