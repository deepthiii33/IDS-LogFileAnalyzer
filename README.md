# IDS-LogFileAnalyzer

A lightweight Intrusion Detection System (IDS) Log File Analyzer built in Python. This tool parses and analyzes web server and authentication logs to identify suspicious activities, including brute-force attempts, HTTP errors, and access to sensitive files.

## 📌 Features
- Analyze Apache/Nginx access logs
- Detect SSH brute-force attacks
- Identify suspicious file access attempts
- Summary reports with top IPs and HTTP errors
- CSV Alerts generated for further inspection

## 🛠 Requirements
- Python 3.x
- Modules: `re`, `csv`, `os`, `collections`

## 🚀 Usage
```bash
python scripts/log_analyzer.py
```
