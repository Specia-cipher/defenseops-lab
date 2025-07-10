# 🛡️ DefenseOps-Lab

A modular **DevSecOps lab** designed for hands-on mastery of **defensive security operations**.  

This lab features **10 standalone tools** covering system hardening, auditing, vulnerability management, and incident response – each with clean CLI interfaces and JSON support.  

Built and tested in a **mobile lab (Termux)** with Docker-ready configurations for future containerization.  

---

## 🚀 Quick Start

```bash
git clone https://github.com/Specia-cipher/defenseops-lab.git
cd defenseops-lab
python3 <tool_name>.py --help

📦 Example:

python3 security_auditor_tool.py --json audit_report.json


---

🛠️ Tools Overview


---

1️⃣ Configuration Compliance Checker

Scans system configurations (SSH, Apache, Nginx) for security misconfigurations and can auto-fix them.

python3 config_compliance_checker.py sshd_config apache2.conf nginx.conf --auto-fix --json compliance_report.json

📦 Sample Output:

[+] Scanning: sshd_config
[!] Non-compliance detected: Disable root login for SSH
[+] Auto-fixed: Disable root login for SSH
[+] JSON report saved as compliance_report.json

📑 Sample JSON Excerpt:

{
  "scanned_at": "2025-07-10T09:30:01Z",
  "file": "sshd_config",
  "issues_fixed": [
    "Disable root login for SSH",
    "Enforce SSH key authentication"
  ]
}

🔖 Built with ❤️ by Sanni Idris


---

2️⃣ Log Analyzer Tool

Detects suspicious activity in system logs using signature-based detection.

python3 log_analyzer_tool.py testlog.txt patterns.txt

📦 Sample Output:

[!] Suspicious pattern found: Failed password from 192.168.1.50
[+] Scan complete. See report.txt

📑 Sample Report Excerpt (report.txt):

Detected Patterns:
- Failed password from 192.168.1.50
- SQL injection attempt on /login

🔖 Built with ❤️ by Sanni Idris


---

3️⃣ Firewall Manager Tool

Applies and verifies firewall rules from a predefined config.

python3 firewall_manager_tool.py firewall_rules.conf

📦 Sample Output:

[+] Rule applied: Allow SSH
[+] Rule applied: Deny all inbound except port 80/443

🔖 Built with ❤️ by Sanni Idris


---

4️⃣ IDS Tool

Scans system logs for intrusion attempts using predefined signatures.

python3 ids_tool.py test_ids.log signatures.conf

📦 Sample Output:

[!] Alert: Possible brute force detected from 10.0.0.5
[+] Alerts saved to alerts.log

📑 Sample Alerts (alerts.log):

Brute force attempt detected from 10.0.0.5 on SSH port.
Port scan detected from 192.168.1.77

🔖 Built with ❤️ by Sanni Idris


---

5️⃣ Vulnerability Database Tool

Checks installed software against a local CVE database.

python3 vuln_db_tool.py vuln_database.json

📦 Sample Output:

[!] Vulnerability found: CVE-2023-1234 – Critical – OpenSSH 8.1

📑 Sample JSON Excerpt:

{
  "vulnerabilities": [
    {
      "cve": "CVE-2023-1234",
      "severity": "Critical",
      "affected_version": "OpenSSH 8.1"
    }
  ]
}

🔖 Built with ❤️ by Sanni Idris


---

6️⃣ Threat Feed Tool

Parses threat intelligence feeds and alerts on known Indicators of Compromise (IOCs).

python3 threat_feed_tool.py threat_feed.json

📦 Sample Output:

[!] Malicious IP detected: 185.199.110.153
[+] Malicious hash detected: e99a18c428cb38d5f260853678922e03

🔖 Built with ❤️ by Sanni Idris


---

7️⃣ Network Vulnerability Scanner

Performs basic port scans on targets from a file.

python3 network_vuln_scanner_tool.py test_targets.txt

📦 Sample Output:

[+] Open ports found: 22 (SSH), 80 (HTTP)

🔖 Built with ❤️ by Sanni Idris


---

8️⃣ Security Auditor Tool

Audits systems for weak configurations like world-writable files and SUID binaries.
📌 Simulation Note: SUID checks simulated in Termux.

python3 security_auditor_tool.py --json audit_report.json

📦 Sample Output:

[!] Found world-writable files: ./world_writable.txt
[!] Found SUID binaries: ./suid_dummy

🔖 Built with ❤️ by Sanni Idris


---

9️⃣ Incident Response Orchestrator

Triage and recommend responses for incidents.

python3 incident_response_orchestrator.py incidents.json --json orchestrator_report.json

📦 Sample Output:

[+] Incident: MALWARE on host-1
    - Isolate infected systems
    - Run antivirus scans and remove malware

🔖 Built with ❤️ by Sanni Idris


---

🔟 Web Vulnerability Scanner

Scans target websites for common OWASP Top 10 vulnerabilities.

python3 web_vuln_scanner_tool.py test_web_targets.txt

📦 Sample Output:

[!] XSS vulnerability detected on http://example.com/login

🔖 Built with ❤️ by Sanni Idris


---

🐳 Docker Support (Planned)

This lab is Docker-ready with a Dockerfile and docker-compose.yml included.
Deployment and containerization coming soon.

docker-compose up --build


---

⚡ Notes

🔥 Simulation: Some checks (SUID, systemctl) are simulated in Termux/mobile lab.

☁️ Cloud Native: Docker and CI/CD integration are next steps.



---

👨‍💻 About the Author

🔖 Built with ❤️ by Sanni Babatunde Idris 

Github: github.com/Specia-cipher/defenseops-lab/
Linkedin: https://www.linkedin.com/in/sanni-idris-89917a262?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app
Gmail: sannifreelancer6779@gmail.com
