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
python log_analyzer.py
```

## Add your log files

Place your log files inside the logs/ directory.

> ⚠️ Note: The logs/ directory is excluded from this Git . Do not upload sensitive logs to GitHub.

## 4. View results

- 📄 Terminal Summary: Displays key findings
- 📂 Detailed Outputs: Saved to output/
   - alerts_combined.csv
   - ssh_failed_logins.csv

## Example Output
![](https://github.com/deepthiii33/IDS-LogFileAnalyzer/blob/main/screenshots/output(1).png)
![](https://github.com/deepthiii33/IDS-LogFileAnalyzer/blob/main/screenshots/output(2).png)

## Privacy Note
 > ⚠️ Do not commit or push real logs to public repositories. Always verify your .gitignore before pushing.

## Conclusion
This project is a foundational tool for learning log analysis and basic intrusion detection. While it’s designed for educational purposes and small-scale usage, it can serve as a starting point for building more advanced IDS tools.
