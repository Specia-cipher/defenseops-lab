# DefenseOps Lab

DefenseOps Lab is a modular cybersecurity toolkit designed for detection, analysis, and response. Built for flexibility and extensibility, this suite empowers security engineers and DevSecOps professionals to secure systems, analyze logs, and automate responses.  

> 💡 **NOTE:** Some tools simulate security behavior due to mobile constraints. Fully operational on desktop/laptop systems.  

---

## 🛠️ Tools Overview

The suite includes **10 modular tools**:  
1. Log Analyzer Tool  
2. Firewall Manager Tool  
3. Intrusion Detection System (IDS) Tool  
4. Vulnerability Scanner Tool  
5. Vulnerability Database Manager Tool  
6. Threat Intelligence Feed Tool  
7. Web Vulnerability Scanner Tool 
8. Configuration Compliance Checker
9. Security auditor tool  
10. Incident Response Orchestrator 
---

## 📦 Installation

Clone the repository:  
```bash
git clone https://github.com/Specia-cipher/defenseops-lab.git
cd defenseops-lab

Ensure you have Python 3.8+ installed. Install dependencies:

pip install -r requirements.txt


---

🔥 1. Log Analyzer Tool

Description

Scans log files for suspicious patterns (e.g., unauthorized access, disk errors) and provides summaries.

Usage

python log_analyzer_tool.py testlog.txt
python log_analyzer_tool.py testlog.txt --quiet
python log_analyzer_tool.py testlog.txt --patterns custom_patterns.txt
python log_analyzer_tool.py testlog.txt --report report.txt

Example Output

[+] Scanning: testlog.txt
[!] Line 2: Unauthorized access attempt
[+] Report saved to report.txt

Notes

Simulated logs are provided for testing.


🔗 LinkedIn | 🔗 GitHub


---

🛡️ 2. Firewall Manager Tool

Description

Manages firewall rules: add, list, delete, and flush rules dynamically.

Usage

python firewall_manager_tool.py add "block 192.168.1.100"
python firewall_manager_tool.py delete "block 192.168.1.100"
python firewall_manager_tool.py list
python firewall_manager_tool.py flush

Example Output

[+] Rule added: block 192.168.1.100
[+] All firewall rules cleared.

Notes

Simulated firewall actions on mobile (real blocking requires desktop environment).


🔗 LinkedIn | 🔗 GitHub


---

🔒 3. IDS Tool

Description

Scans logs for known attack signatures. On detection, it triggers an alert and blocks malicious IPs via the firewall.

Usage

python ids_tool.py --add "Failed password"
python ids_tool.py --scan test_ids.log
python ids_tool.py --view-alerts

Example Output

[!] ALERT! Signature match on line 2: Failed password
[+] IP blocked: 192.168.1.50
Integrates with Firewall Manager Tool.

Alerts are logged for later review.


🔗 LinkedIn | 🔗 GitHub


---

🕵️ 4. Web Vulnerability Scanner (web_vuln_scanner_tool.py)

Description
Performs defensive scans of web applications for OWASP Top 10 vulnerabilities such as SQL Injection, XSS, etc.

Usage

python web_vuln_scanner_tool.py <targets_file> [--report <file>]

Example

python web_vuln_scanner_tool.py test_web_targets.txt --report web_scan.txt

Sample Output

[+] Starting Web Vulnerability Scan (Defensive Mode)...
[+] Scanning http://testphp.vulnweb.com/artists.php?id=1...
[+] Scanning http://example.com/page?name=test...
[+] Scan complete: 0 potential issues detected across 2 targets
[+] Report saved to web_scan.txt



---

📂 5. Vulnerability Database Manager Tool

Description

Manage known vulnerabilities (add, search, delete).

Usage

python vuln_db_tool.py add 22 ssh "OpenSSH vulnerable to CVE-2024-1234"
python vuln_db_tool.py list
python vuln_db_tool.py search ssh
python vuln_db_tool.py delete 1

Example Output

--- Vulnerability Database ---
1. Port: 22, Service: ssh, CVE: CVE-2024-1234

🔗 LinkedIn | 🔗 GitHub


---

🌐 6. Threat Intelligence Feed Tool

Description

Fetches and parses threat intel feeds (e.g., IP blocklists).

Usage

python threat_feed_tool.py --fetch
python threat_feed_tool.py --view

Example Output

[+] Fetching threat feeds...
    ✔ Success
[+] Threat feeds saved to threat_feed.json

Notes

Feeds stored locally for offline analysis.


🔗 LinkedIn | 🔗 GitHub


---
7. Network Vulnerability Scanner (network_vuln_scanner_tool.py)

Description
Scans a list of target hosts for open ports and known vulnerabilities using a local vulnerability database.

Usage

python network_vuln_scanner_tool.py <targets_file> [--ports PORTS] [--quiet] [--report <file>] [--json]

Example

python network_vuln_scanner_tool.py test_targets.txt --report scan_results.txt

Sample Output

[+] Starting scan on test_targets.txt:1-1024
[+] Scan complete: 0 open ports found
[+] Report saved to scan_results.txt


---


🚀 Upcoming Tools (8-10)

8. Configuration Compliance Checker (config_compliance_checker.py)

Description
Scans system configuration files (e.g., sshd_config, apache2.conf, nginx.conf) for compliance with security best practices. Supports auto-fixing misconfigurations and custom rule sets via JSON.


---

Usage

# Scan using default compliance rules
python config_compliance_checker.py sshd_config apache2.conf nginx.conf

# Auto-fix non-compliance
python config_compliance_checker.py sshd_config apache2.conf nginx.conf --auto-fix

# Use custom rules from JSON file
python config_compliance_checker.py sshd_config apache2.conf nginx.conf --rules my_rules.json

# Save compliance results as JSON report
python config_compliance_checker.py sshd_config apache2.conf nginx.conf --json compliance_report.json

# Combine custom rules, auto-fix, and report
python config_compliance_checker.py sshd_config apache2.conf nginx.conf --rules my_rules.json --auto-fix --json custom_compliance.json


---

Example Output

===============================================
 🛡️ DefenseOps: Configuration Compliance Checker
===============================================

[+] Scanning: sshd_config
[+] Backup created: sshd_config.bak
[!] Non-compliance detected: Disable root login for SSH
[+] Auto-fixed: Disable root login for SSH
[!] Non-compliance detected: Enforce SSH key authentication
[+] Auto-fixed: Enforce SSH key authentication
[+] Scanning: apache2.conf
[+] Backup created: apache2.conf.bak
[!] Non-compliance detected: Disable directory listing in Apache
[+] Auto-fixed: Disable directory listing in Apache
[+] Scanning: nginx.conf
[+] Backup created: nginx.conf.bak
[!] Non-compliance detected: Disable directory listing in Nginx
[+] Auto-fixed: Disable directory listing in Nginx

===== Compliance Summary =====
- sshd_config: Issues fixed
- apache2.conf: Issues fixed
- nginx.conf: Issues fixed
==============================
[+] JSON report saved as compliance_report.json


---

Notes

If --rules JSON file is malformed or missing, falls back to built-in rules automatically.

Backups (.bak) are created before auto-fix.

Perfect for CI/CD pipelines to enforce security compliance.

Simulated changes on mobile; real effect on Linux desktop/server.


🔗 LinkedIn | 🔗 GitHub

---

🔐 9. Security Auditor Tool (security_auditor_tool.py)

**Description**  
Performs a comprehensive security audit of the host system. Checks for:  
- World-writable files (potential security risks)  
- SUID binaries (privilege escalation risks)  
- Telnet service status (legacy service exposure)  
- Awareness of Docker environments for cloud-native auditing

**Usage**
```bash
python security_auditor_tool.py
python security_auditor_tool.py --json audit_report.json

Example Output

===============================================
 🛡️ DefenseOps: Security Auditor Tool
===============================================

[+] Environment: Non-Docker
[+] Checking for world-writable files...
[!] Found world-writable files:
    - ./world_writable.txt
[+] Checking telnet service status...
[+] Telnet status: /data/data/com.termux/files/usr/bin/sh: 1: systemctl: not found

===== Audit Summary =====
World-writable files: 1
SUID binaries:        0
Telnet service:       /data/data/com.termux/files/usr/bin/sh: 1: systemctl: not found
=========================

[+] JSON report saved as audit_report.json

JSON Report Example

{
  "scanned_at": "2025-07-10T10:42:01.109895",
  "system_type": "Non-Docker",
  "world_writable": ["./world_writable.txt"],
  "suid_binaries": [],
  "telnet_status": "/data/data/com.termux/files/usr/bin/sh: 1: systemctl: not found"
}

Notes

Auto-detects Docker environments and adjusts behavior.

Falls back gracefully in mobile/non-systemd environments.

Simulated elements (e.g., Telnet) are fully operational when containerized.


🔗 LinkedIn | 🔗 GitHub


---




---

👨‍💻 About the Author

Built with ❤️ by Sanni Idris.
Full repo: Specia-cipher/defenseops-lab


---
