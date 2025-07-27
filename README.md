# 🛡️ DefenseOps-Lab: Hands-on Defensive Security Operations Lab

A modular DevSecOps lab designed for hands-on mastery of defensive security operations. This lab features 10 standalone Python-based tools covering system hardening, auditing, vulnerability management, and incident response – each with clean CLI interfaces and JSON support.

Built and tested in a mobile lab (Termux) with Docker-ready configurations for containerized deployments, ensuring reproducibility and portability.

---

## 📑 Table of Contents

* [Overview](#overview)
* [Quick Start](#quick-start)
* [Tools Overview](#tools-overview)
    * [1️⃣ Configuration Compliance Checker](#1-configuration-compliance-checker)
    * [2️⃣ Log Analyzer Tool](#2-log-analyzer-tool)
    * [3️⃣ Firewall Manager Tool](#3-firewall-manager-tool)
    * [4️⃣ IDS Tool](#4-ids-tool)
    * [5️⃣ Vulnerability Database Tool](#5-vulnerability-database-tool)
    * [6️⃣ Threat Feed Tool](#6-threat-feed-tool)
    * [7️⃣ Network Vulnerability Scanner](#7-network-vulnerability-scanner)
    * [8️⃣ Security Auditor Tool](#8-security-auditor-tool)
    * [9️⃣ Incident Response Orchestrator](#9-incident-response-orchestrator)
    * [🔟 Web Vulnerability Scanner](#10-web-vulnerability-scanner)
* [🐳 Containerized Tools](#-containerized-tools)
* [⚡ Notes & Future Work](#-notes--future-work)
* [👨‍💻 About the Author](#-about-the-author)

---

## Overview

DefenseOps-Lab is crafted for practical learning and application in the defensive security domain. It provides a robust environment to:

* **Implement System Hardening:** Apply and verify secure configurations.
* **Automate Auditing:** Scan for misconfigurations and vulnerabilities.
* **Enhance Detection & Response:** Identify threats and orchestrate incident handling.
* **Practice DevSecOps Principles:** Leverage containerization for isolated and reproducible testing.

## 🚀 Quick Start

To get started with any tool:

```bash
git clone [https://github.com/Specia-cipher/defenseops-lab.git](https://github.com/Specia-cipher/defenseops-lab.git)
cd defenseops-lab
python3 <tool_name>.py --help
```

**Example:**

```bash
python3 security_auditor_tool.py --json audit_report.json
```

## 🛠️ Tools Overview

All tools can run as standalone Python scripts or in containerized form (see [🐳 Containerized Tools](#-containerized-tools)).

### 1️⃣ Configuration Compliance Checker

Scans system configurations (SSH, Apache, Nginx) for security misconfigurations and can auto-fix them.

```bash
python3 config_compliance_checker.py sshd_config apache2.conf nginx.conf --auto-fix --json compliance_report.json
```

**📦 Sample Output:**

```
[+] Scanning: sshd_config
[!] Non-compliance detected: Disable root login for SSH
[+] Auto-fixed: Disable root login for SSH
[+] JSON report saved as compliance_report.json
```

**📑 Sample JSON Excerpt:**

```json
{
  "scanned_at": "2025-07-10T09:30:01Z",
  "file": "sshd_config",
  "issues_fixed": [
    "Disable root login for SSH",
    "Enforce SSH key authentication"
  ]
}
```

### 2️⃣ Log Analyzer Tool

Detects suspicious activity in system logs using signature-based detection.

```bash
python3 log_analyzer_tool.py testlog.txt --patterns patterns.txt
```

**📦 Sample Output:**

```
[+] Loaded 1 custom patterns

[+] Scanning: testlog.txt
[!] Line 1: This is a test log entry.

Scan Summary
Total lines scanned: 1
Suspicious lines: 1
Percent suspicious: 100.0%
```

**📑 Sample Report Excerpt (report.txt):**

```
Detected Patterns:
Failed password from 192.168.1.50
SQL injection attempt on /login
```

### 3️⃣ Firewall Manager Tool

Applies and verifies firewall rules from a predefined config.

```bash
python3 firewall_manager_tool.py firewall_rules.conf
```

**📦 Sample Output:**

```
[+] Rule applied: Allow SSH
[+] Rule applied: Deny all inbound except port 80/443
```

### 4️⃣ IDS Tool

Scans system logs for intrusion attempts using predefined signatures.

```bash
python3 ids_tool.py test_ids.log signatures.conf
```

**📦 Sample Output:**

```
[!] Alert: Possible brute force detected from 10.0.0.5
[+] Alerts saved to alerts.log
```

**📑 Sample Alerts (alerts.log):**

```
Brute force attempt detected from 10.0.0.5 on SSH port.
Port scan detected from 192.168.1.77
```

### 5️⃣ Vulnerability Database Tool

Checks installed software against a local CVE database.

```bash
python3 vuln_db_tool.py vuln_database.json
```

**📦 Sample Output:**

```
[!] Vulnerability found: CVE-2023-1234 – Critical – OpenSSH 8.1
```

**📑 Sample JSON Excerpt:**

```json
{
  "vulnerabilities": [
    {
      "cve": "CVE-2023-1234",
      "severity": "Critical",
      "affected_version": "OpenSSH 8.1"
    }
  ]
}
```

### 6️⃣ Threat Feed Tool

Parses threat intelligence feeds and alerts on known Indicators of Compromise (IOCs).

```bash
python3 threat_feed_tool.py threat_feed.json
```

**📦 Sample Output:**

```
[!] Malicious IP detected: 185.199.110.153
[+] Malicious hash detected: e99a18c428cb38d5f260853678922e03
```

### 7️⃣ Network Vulnerability Scanner

Performs basic port scans on targets from a file.

```bash
python3 network_vuln_scanner_tool.py test_targets.txt
```

**📦 Sample Output:**

```
[+] Open ports found: 22 (SSH), 80 (HTTP)
```

### 8️⃣ Security Auditor Tool

Audits systems for weak configurations like world-writable files and SUID binaries.

**📌 Note:** SUID checks are simulated when running in Termux/mobile lab environments.

```bash
python3 security_auditor_tool.py --json audit_report.json
```

**📦 Sample Output:**

```
[!] Found world-writable files: ./world_writable.txt
[!] Found SUID binaries: ./suid_dummy
```

### 9️⃣ Incident Response Orchestrator

Triages incidents and recommends response actions.

```bash
python3 incident_response_orchestrator.py incidents.json --json orchestrator_report.json
```

**📦 Sample Output:**

```
[+] Incident: MALWARE on host-1
- Isolate infected systems
- Run antivirus scans and remove malware
```

### 🔟 Web Vulnerability Scanner

Scans target websites for common OWASP Top 10 vulnerabilities.

```bash
python3 web_vuln_scanner_tool.py test_web_targets.txt
```

**📦 Sample Output:**

```
[!] XSS vulnerability detected on [http://example.com/login](http://example.com/login)
```

## 🐳 Containerized Tools

The following tools are Dockerized for isolated, reproducible testing and deployment.

* **Log Analyzer Tool**
    ```bash
    docker build -t log_analyzer_tool -f Dockerfile.log_analyzer .
    docker run --rm -v "$(pwd):/app" log_analyzer_tool testlog.txt --patterns patterns.txt
    ```
* **Firewall Manager Tool**
    ```bash
    docker build -t firewall_manager_tool ./docker/firewall_manager
    docker run --rm firewall_manager_tool firewall_rules.conf
    ```
* **Security Auditor Tool**
    ```bash
    docker build -t security_auditor_tool ./docker/security_auditor
    docker run --rm security_auditor_tool --json audit_report.json
    ```
* **Network Vulnerability Scanner**
    ```bash
    docker build -t network_vuln_scanner_tool ./docker/network_scanner
    docker run --rm network_vuln_scanner_tool test_targets.txt
    ```

### Deploy All Tools with Docker Compose

This lab includes a `Dockerfile` and `docker-compose.yml` for easy deployment.

```bash
docker-compose up --build
```

This spins up all containerized tools in their own isolated environments.

**Why Docker?**
✅ Isolation of tools from host OS
✅ Easy reproducibility across environments
✅ Portability for cloud-native deployments

*Standalone Python scripts remain fully functional for environments where Docker is not preferred.*

## ⚡ Notes & Future Work

* **🔥 Simulation:** Some checks (e.g., SUID, `systemctl` interactions) are simulated when running in Termux/mobile lab environments to ensure broad compatibility.
* **☁️ Cloud Native:** Additional Dockerization and CI/CD integration are ongoing to further enhance cloud-native deployment capabilities.
* **⏳ Coming Soon:**
    * Threat Feed Tool (Docker support in progress)

## 👨‍💻 About the Author

Built with ❤️ by **Sanni Babatunde Idris**

* **GitHub:** [github.com/Specia-cipher/defenseops-lab](https://github.com/Specia-cipher/defenseops-lab)
* **LinkedIn:** [linkedin.com/in/sanni-idris-89917a262](https://linkedin.com/in/sanni-idris-89917a262)
* **Email:** [sannifreelancer6779@gmail.com](mailto:sannifreelancer6779@gmail.com)
