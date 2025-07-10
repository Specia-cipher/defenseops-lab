import sys
import json
import argparse
from datetime import datetime
import shutil
import os

# ANSI colors for user-friendly CLI
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

# Default compliance rules
COMPLIANCE_RULES = {
    "sshd_config": [
        ("PermitRootLogin yes", "PermitRootLogin no", "Disable root login for SSH"),
        ("PasswordAuthentication yes", "PasswordAuthentication no", "Enforce SSH key authentication")
    ],
    "apache2.conf": [
        ("Options Indexes", "Options -Indexes", "Disable directory listing in Apache"),
        ("ServerTokens Full", "ServerTokens Prod", "Minimize Apache version exposure"),
        ("ServerSignature On", "ServerSignature Off", "Disable server signature leakage")
    ],
    "nginx.conf": [
        ("autoindex on", "autoindex off", "Disable directory listing in Nginx")
    ]
}

def banner():
    print(f"""{YELLOW}
===============================================
 🛡️ DefenseOps: Configuration Compliance Checker
===============================================
{RESET}""")

def load_custom_rules(rules_file):
    if not os.path.exists(rules_file):
        print(f"{RED}[!] Custom rules file not found: {rules_file}{RESET}")
        print(f"{YELLOW}[!] Falling back to built-in compliance rules.{RESET}")
        return COMPLIANCE_RULES, "default"
    if os.stat(rules_file).st_size == 0:
        print(f"{RED}[!] Custom rules file is empty!{RESET}")
        print(f"{YELLOW}[!] Falling back to built-in compliance rules.{RESET}")
        return COMPLIANCE_RULES, "default"
    try:
        with open(rules_file, "r") as f:
            return json.load(f), "custom"
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Failed to parse custom rules JSON: {e}{RESET}")
        print(f"{YELLOW}[!] Falling back to built-in compliance rules.{RESET}")
        return COMPLIANCE_RULES, "default"

def validate_rules(rules_file):
    """Validate custom rules JSON."""
    if not os.path.exists(rules_file):
        print(f"{RED}[!] Rules file not found: {rules_file}{RESET}")
        sys.exit(1)
    if os.stat(rules_file).st_size == 0:
        print(f"{RED}[!] Rules file is empty: {rules_file}{RESET}")
        sys.exit(1)
    try:
        with open(rules_file, "r") as f:
            json.load(f)
        print(f"{GREEN}[✓] Custom rules JSON is valid.{RESET}")
    except json.JSONDecodeError as e:
        print(f"{RED}[!] Invalid JSON format: {e}{RESET}")
        sys.exit(1)

def scan_file(filename, rules, auto_fix=False):
    print(f"[+] Scanning: {filename}")
    issues_found = False
    if not os.path.exists(filename):
        print(f"{RED}[!] File not found: {filename}{RESET}")
        return False
    with open(filename, "r") as file:
        content = file.read()
    backup_file = filename + ".bak"
    shutil.copy(filename, backup_file)
    print(f"[+] Backup created: {backup_file}")

    for bad, good, desc in rules.get(os.path.basename(filename), []):
        if bad in content:
            print(f"{RED}[!] Non-compliance detected: {desc}{RESET}")
            issues_found = True
            if auto_fix:
                content = content.replace(bad, good)
                print(f"{GREEN}[+] Auto-fixed: {desc}{RESET}")

    if auto_fix and issues_found:
        with open(filename, "w") as f:
            f.write(content)
    elif not issues_found:
        print(f"{GREEN}  ✓ No issues detected.{RESET}")

    return issues_found

def main():
    parser = argparse.ArgumentParser(description="DefenseOps Config Compliance Checker")
    parser.add_argument("configs", nargs="*", help="Configuration files to scan")
    parser.add_argument("--auto-fix", action="store_true", help="Automatically fix non-compliance")
    parser.add_argument("--rules", help="Path to custom JSON rules file")
    parser.add_argument("--json", help="Save results to JSON file")
    parser.add_argument("--validate-rules", metavar="RULES_FILE", help="Validate a custom rules JSON file and exit")
    args = parser.parse_args()

    banner()

    if args.validate_rules:
        validate_rules(args.validate_rules)
        sys.exit(0)

    if not args.configs:
        print(f"{RED}[!] No configuration files specified for scanning.{RESET}")
        parser.print_help()
        sys.exit(1)

    rules, rules_source = load_custom_rules(args.rules) if args.rules else (COMPLIANCE_RULES, "default")

    summary = {}
    for cfg in args.configs:
        issues = scan_file(cfg, rules, auto_fix=args.auto_fix)
        summary[cfg] = "Issues found" if issues else "Compliant"

    print("\n===== Compliance Summary =====")
    for k, v in summary.items():
        print(f"- {k}: {v}")
    print("=" * 30)

    if args.json:
        now = datetime.utcnow().isoformat()
        report = {
            "scanned_at": now,
            "rules_source": rules_source,
            "summary": summary
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] JSON report saved as {args.json}")

if __name__ == "__main__":
    main()
