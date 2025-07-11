#!/usr/bin/env python3
"""
DefenseOps Security Auditor - Atomic JSON Edition
"""
import os
import json
import argparse
from datetime import datetime
from pathlib import Path

SCAN_EXCLUSIONS = {
    '/proc', '/sys', '/dev', '/run',
    '/boot', '/snap', '/var/lib/docker'
}

def scan_system(root="/", max_depth=10):
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Skip excluded paths
        if any(Path(dirpath).is_relative_to(Path(ex)) for ex in SCAN_EXCLUSIONS):
            dirnames[:] = []  # Don't recurse
            continue

        # Limit recursion depth
        depth = dirpath.count(os.sep) - root.count(os.sep)
        if depth > max_depth:
            dirnames[:] = []
            continue

        for filename in filenames:
            path = os.path.join(dirpath, filename)
            try:
                mode = os.stat(path).st_mode
                if mode & 0o4000:  # SUID
                    findings.append({
                        "type": "suid_binary",
                        "path": path,
                        "severity": "high"
                    })
                elif mode & 0o0002:  # World-writable
                    findings.append({
                        "type": "world_writable",
                        "path": path,
                        "severity": "medium"
                    })
            except Exception:
                continue

    return findings

def save_report(data, output_file):
    """Atomic JSON write with temp file"""
    temp_file = f"{output_file}.tmp"
    try:
        with open(temp_file, 'w') as f:
            json.dump({
                "meta": {
                    "scanned_at": datetime.utcnow().isoformat(),
                    "scanner": "DefenseOps-Auditor-v3"
                },
                "findings": data
            }, f, indent=2)
        os.rename(temp_file, output_file)
    except Exception as e:
        if os.path.exists(temp_file):
            os.unlink(temp_file)
        raise e

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", help="Output JSON file")
    args = parser.parse_args()

    findings = scan_system()

    if args.json:
        save_report(findings, args.json)
    else:
        print(json.dumps({"findings": findings}, indent=2))
