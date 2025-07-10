#!/usr/bin/env python3
import argparse
import re
import sys
import json

DEFAULT_PATTERNS = [
    r'failed', r'unauthorized', r'invalid', r'error', r'alert',
    r'critical', r'root login', r'sudo', r'permission denied'
]

def highlight(text, color_code):
    """Return text wrapped in ANSI color codes."""
    return f"\033[{color_code}m{text}\033[0m"

def load_patterns(custom_patterns):
    """Combine default and custom patterns."""
    if custom_patterns:
        try:
            with open(custom_patterns, 'r') as f:
                extra_patterns = [line.strip() for line in f if line.strip()]
            print(highlight(f"[+] Loaded {len(extra_patterns)} custom patterns", "92"))  # Green
            return DEFAULT_PATTERNS + extra_patterns
        except Exception as e:
            print(highlight(f"[-] Failed to load custom patterns: {e}", "31"))
            sys.exit(1)
    return DEFAULT_PATTERNS

def scan_log(file_path, patterns, quiet=False):
    """Scan the log file and highlight suspicious lines."""
    suspicious_entries = []
    total_lines = 0
    suspicious_count = 0

    print(highlight(f"\n[+] Scanning: {file_path}", "94"))  # Blue
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                suspicious = any(re.search(p, line, re.IGNORECASE) for p in patterns)
                if suspicious:
                    suspicious_entries.append({"line": line_num, "text": line.strip()})
                    print(highlight(f"[!] Line {line_num}: {line.strip()}", "91"))  # Red
                    suspicious_count += 1
                elif not quiet:
                    print(highlight(f"    Line {line_num}: {line.strip()}", "90"))  # Grey
    except FileNotFoundError:
        print(highlight("[-] Log file not found.", "31"))
        sys.exit(1)
    except Exception as e:
        print(highlight(f"[-] Error reading log: {e}", "31"))
        sys.exit(1)

    return suspicious_entries, total_lines, suspicious_count

def save_report(suspicious_entries, total_lines, suspicious_count, output_file, json_format=False):
    """Save suspicious entries and summary to a report file."""
    try:
        if json_format:
            data = {
                "summary": {
                    "total_lines": total_lines,
                    "suspicious_lines": suspicious_count,
                    "percent_suspicious": round((suspicious_count / total_lines) * 100, 2)
                },
                "suspicious_entries": suspicious_entries
            }
            with open(output_file, 'w') as f:
                json.dump(data, f, indent=4)
        else:
            with open(output_file, 'w') as f:
                f.write("Log Analyzer Report\n")
                f.write("===================\n")
                f.write(f"Total lines scanned: {total_lines}\n")
                f.write(f"Suspicious lines: {suspicious_count}\n")
                f.write(f"Percent suspicious: {round((suspicious_count / total_lines) * 100, 2)}%\n\n")
                f.write("Suspicious Entries:\n")
                for entry in suspicious_entries:
                    f.write(f"Line {entry['line']}: {entry['text']}\n")
        print(highlight(f"[+] Report saved to {output_file}", "92"))  # Green
    except Exception as e:
        print(highlight(f"[-] Failed to save report: {e}", "31"))

def parse_args():
    parser = argparse.ArgumentParser(
        description="Log Analyzer Tool - Highlight suspicious activity in log files."
    )
    parser.add_argument("logfile", help="Path to the log file to scan.")
    parser.add_argument(
        "--patterns", "-p", help="Path to file containing custom regex patterns (one per line)."
    )
    parser.add_argument(
        "--quiet", "-q", action="store_true",
        help="Suppress normal lines and only show suspicious entries."
    )
    parser.add_argument(
        "--report", "-r", help="Path to save report (e.g., report.txt or report.json)."
    )
    parser.add_argument(
        "--json", action="store_true", help="Save report in JSON format."
    )
    return parser.parse_args()

def main():
    args = parse_args()
    patterns = load_patterns(args.patterns)
    suspicious_entries, total_lines, suspicious_count = scan_log(
        args.logfile, patterns, quiet=args.quiet
    )

    print(highlight("\nScan Summary", "96"))  # Cyan
    print(f"Total lines scanned: {total_lines}")
    print(f"Suspicious lines: {suspicious_count}")
    print(f"Percent suspicious: {round((suspicious_count / total_lines) * 100, 2)}%")

    if args.report:
        save_report(
            suspicious_entries, total_lines, suspicious_count,
            args.report, json_format=args.json
        )

if __name__ == "__main__":
    main()
