# DefenseOps Lab 🛡️🔐

A practical cybersecurity toolkit for log analysis and firewall rule management. Built for defenders, analysts, and DevSecOps engineers to respond swiftly to threats.

---

## 🚀 Tools in this Lab

### 1️⃣ Log Analyzer Tool
- Scans log files for suspicious activity.
- Supports custom regex patterns.
- Generates clean text or JSON reports.

📦 Features:
- Quiet mode for cleaner output.
- Custom pattern support (`--patterns patterns.txt`).
- Output reports in text or JSON.

---

### 2️⃣ Firewall Manager Tool
- Simple CLI tool to manage firewall rules.
- Add, list, delete, and flush rules stored in `firewall_rules.conf`.

📦 Features:
- Add rules: `python firewall_manager_tool.py add "block 192.168.1.100"`
- List rules: `python firewall_manager_tool.py list`
- Delete rules: `python firewall_manager_tool.py delete "block 192.168.1.100"`
- Flush all rules: `python firewall_manager_tool.py flush`

---

## 💡 Why DefenseOps Lab?
This project demonstrates practical defensive security tooling that can be run in lightweight environments (even Termux!). Perfect for learning or rapid response.

---

## 📂 Files
- `log_analyzer_tool.py`
- `firewall_manager_tool.py`
- `firewall_rules.conf` (auto-generated)
- `.gitignore`

---

## 🌐 Author
**Sanni Idris (Specia-cipher)**  
🔗 [GitHub](https://github.com/Specia-cipher) | 🔗 [LinkedIn](https://www.linkedin.com/in/sanniidris)


---

🛡️ Intrusion Detection System (IDS) Tool

The IDS Tool acts as a lightweight intrusion detection system for log monitoring and automated threat response. It scans system logs for suspicious patterns, triggers alerts, and works seamlessly with the Firewall Manager to block offending IP addresses in real time.

Features

Add, list, and remove custom detection signatures.

Scan log files for signature matches.

Auto-block offending IPs by integrating with firewall_manager_tool.py.

Supports --dry-run mode for simulation without modifying firewall rules.

Maintains an alerts log for incident tracking.

Quickly view and clear alerts with --view-alerts and --clear-alerts.


Usage Examples

# Add signatures
python ids_tool.py --add "Failed password"
python ids_tool.py --add "Unauthorized access"

# List signatures
python ids_tool.py --list

# Scan a log file and auto-block IPs
python ids_tool.py --scan /var/log/auth.log

# Simulate scan without blocking IPs
python ids_tool.py --scan /var/log/auth.log --dry-run

# View past alerts
python ids_tool.py --view-alerts

# Clear alerts log
python ids_tool.py --clear-alerts


📌 **Author**  
- [Specia-cipher on GitHub](https://github.com/Specia-cipher)  


- [Sanni Idris on LinkedIn](https://www.linkedin.com/in/sanni-idris)

sannifreelancer@gmail.com
