#!/usr/bin/env python3
import requests
import argparse
import json
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from datetime import datetime

# Defensive test payloads (non-destructive)
TEST_PAYLOADS = {
    "SQLi_Test": "' OR '1'='1",
    "XSS_Test": "<DefenseOps-Test>"
}

HEADERS = {
    "User-Agent": "DefenseOps-Lab-Scanner/1.0"
}

def inject_payload(url, payload):
    """Safely injects payload into URL parameters."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    for param in qs:
        qs[param] = payload
    new_query = urlencode(qs, doseq=True)
    injected_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
    return injected_url

def test_url(target_url, quiet=False):
    """Scan a single URL for weak reflections of payloads."""
    alerts = []
    try:
        for vuln_name, payload in TEST_PAYLOADS.items():
            test_url = inject_payload(target_url, payload) if "?" in target_url else target_url
            response = requests.get(test_url, headers=HEADERS, timeout=5)
            content = response.text

            if payload in content:
                alert = f"[!] Potential {vuln_name} detected: payload reflected at {test_url}"
                alerts.append(alert)
                if not quiet: print(alert)
    except requests.RequestException as e:
        if not quiet: print(f"[!] Error scanning {target_url}: {e}")
    return alerts

def scan_targets(file, quiet=False):
    """Scan all URLs from a file."""
    results = {}
    with open(file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    for url in targets:
        if not url.startswith("http"):
            url = "http://" + url
        print(f"[+] Scanning {url}...")
        results[url] = test_url(url, quiet)
    return results

def save_report(results, filename, as_json=False):
    now = datetime.utcnow().isoformat()
    if as_json:
        with open(filename, 'w') as f:
            json.dump({"scanned_at": now, "results": results}, f, indent=2)
        print(f"[+] JSON report saved to {filename}")
    else:
        with open(filename, 'w') as f:
            f.write(f"Web Vulnerability Scan Report - {now}\n")
            f.write("=" * 50 + "\n")
            for url, alerts in results.items():
                f.write(f"\nTarget: {url}\n")
                for alert in alerts:
                    f.write(f"{alert}\n")
        print(f"[+] Report saved to {filename}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DefenseOps Lab - Web Vulnerability Scanner")
    parser.add_argument("target_file", help="File containing target URLs (one per line)")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    parser.add_argument("--report", help="Save scan results to a report file")
    parser.add_argument("--json", action="store_true", help="Save report in JSON format")

    args = parser.parse_args()

    print("[+] Starting Web Vulnerability Scan (Defensive Mode)...")
    results = scan_targets(args.target_file, quiet=args.quiet)
    total_alerts = sum(len(alerts) for alerts in results.values())
    print(f"[+] Scan complete: {total_alerts} potential issues detected across {len(results)} targets")

    if args.report:
        save_report(results, args.report, as_json=args.json)
