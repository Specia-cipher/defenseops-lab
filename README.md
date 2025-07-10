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
