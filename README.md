# DefenseOps Lab  

A modular, containerized security operations toolkit designed for research, experimentation, and education. DefenseOps Lab brings together multiple security tools—ranging from IDS and vulnerability scanners to incident response orchestration—under one roof. Each tool can be run independently or combined into a larger workflow using Docker Compose.  

---

## Table of Contents  

1. [Overview](#overview)  
2. [Quick Start](#quick-start)  
   - [Run with Python](#run-with-python)  
   - [Run with Docker](#run-with-docker)  
3. [Tools Overview](#tools-overview)  
   - [1. Intrusion Detection System (IDS)](#1-intrusion-detection-system-ids)  
   - [2. Firewall Manager](#2-firewall-manager)  
   - [3. Network Vulnerability Scanner](#3-network-vulnerability-scanner)  
   - [4. Web Vulnerability Scanner](#4-web-vulnerability-scanner)  
   - [5. Vulnerability Database](#5-vulnerability-database)  
   - [6. Security Auditor](#6-security-auditor)  
   - [7. Log Analyzer](#7-log-analyzer)  
   - [8. Threat Feed Integration](#8-threat-feed-integration)  
   - [9. Incident Response Orchestrator](#9-incident-response-orchestrator)  
   - [10. Alert Correlator](#10-alert-correlator)  
4. [Containerized Tools](#containerized-tools)  
5. [Docker Compose](#docker-compose)  
6. [Future Work](#future-work)  
7. [About](#about)  

---

## Overview  

DefenseOps Lab is built to simulate a lightweight SOC (Security Operations Center). It provides:  

- **Standalone tools** for specific tasks (IDS, scanners, log analysis).  
- **Containerized deployment** for each tool.  
- **Composable architecture** using Docker Compose to run the entire stack.  
- **Educational value** for anyone learning security automation, DevSecOps, or tool orchestration.  

---

## Quick Start  

### Run with Python  

Each tool can be run directly:  

```bash
python3 ids_tool.py
python3 network_vuln_scanner_tool.py
python3 alert_correlator_tool.py ./dummy_alerts
```

Dependencies are listed in `requirements.txt`:  

```bash
pip install -r requirements.txt
```  

---

### Run with Docker  

Each tool has its own Dockerfile. Example (IDS):  

```bash
docker build -t defenseops-ids -f Dockerfile.ids .
docker run --rm defenseops-ids
```  

---

## Tools Overview  

### 1. Intrusion Detection System (IDS)  
- File: `ids_tool.py`  
- Purpose: Monitors and flags suspicious patterns in logs using rule-based signatures.  

### 2. Firewall Manager  
- File: `firewall_manager_tool.py`  
- Purpose: Loads firewall rules (`firewall_rules.conf`) and simulates enforcement.  

### 3. Network Vulnerability Scanner  
- File: `network_vuln_scanner_tool.py`  
- Purpose: Uses Nmap to identify open ports and services.  

### 4. Web Vulnerability Scanner  
- File: `web_vuln_scanner_tool.py`  
- Purpose: Scans target URLs for SQLi, XSS, and common web flaws.  

### 5. Vulnerability Database  
- File: `vuln_db_tool.py`  
- Purpose: Stores and queries vulnerabilities against CVE and whitelist datasets.  

### 6. Security Auditor  
- File: `security_auditor_tool.py`  
- Purpose: Audits system configurations for misconfigurations and weak settings.  

### 7. Log Analyzer  
- File: `log_analyzer_tool.py`  
- Purpose: Processes raw logs and extracts attack trends, patterns, and frequency.  

### 8. Threat Feed Integration  
- File: `threat_feed_tool.py`  
- Purpose: Enriches local alerts with external threat intelligence (IP/domain feeds).  

### 9. Incident Response Orchestrator  
- File: `incident_response_orchestrator.py`  
- Purpose: Automates response steps (block IP, escalate, generate report).  

### 10. Alert Correlator  
- File: `alert_correlator_tool.py`  
- Purpose: Aggregates alerts, finds relationships, and produces summaries (`alert_summary.json`).  

---

## Containerized Tools  

Each tool has a corresponding Dockerfile:  

- `Dockerfile.ids`  
- `Dockerfile.firewall`  
- `Dockerfile.network`  
- `Dockerfile.web_vuln_scanner`  
- `Dockerfile.vuln_db`  
- `Dockerfile.security_auditor`  
- `Dockerfile.log_analyzer`  
- `Dockerfile.threat_feed`  
- `Dockerfile.incident_response`  
- `Dockerfile.alert_correlator`  

---

## Docker Compose  

Run the entire DefenseOps Lab stack with:  

```bash
docker-compose up --build
```  

This spins up all 10 tools as services, wired together for a lab-like environment.  

---

## Future Work  

- Streamlined dashboards for visualization.  
- REST API layer for tool integration.  
- Enhanced alert correlation with ML models.  
- Optimized builds for resource-limited environments.  

---

## About  

DefenseOps Lab is developed for security research, DevSecOps practice, and applied cybersecurity learning.  
Author: **Special Agent** (@Specia-cipher)  
Built with ❤️ by Sanni Babatunde Idris
GitHub: github.com/Specia-cipher/defenseops-lab
LinkedIn: linkedin.com/in/sanni-idris-89917a262 
Email: sannifreelancer6779@gmail.com 
