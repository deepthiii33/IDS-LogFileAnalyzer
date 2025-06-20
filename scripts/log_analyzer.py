import os
import re
import csv
import json
from collections import defaultdict, Counter
from colorama import Fore, Style, init

# Initialize colorama for colored output in CLI
init(autoreset=True)

# Directory Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
OUTPUT_DIR = os.path.join(BASE_DIR, "output")
BLACKLIST_FILE = os.path.join(OUTPUT_DIR, "blacklisted_ips.json")
ALERTS_CSV = os.path.join(OUTPUT_DIR, "alerts_combined.csv")
SSH_FAILED_LOGINS_CSV = os.path.join(OUTPUT_DIR, "ssh_failed_logins.csv")

os.makedirs(OUTPUT_DIR, exist_ok=True)

# Suspicious files to monitor
SUSPICIOUS_FILES = [
    "/bWAPP/login.php",
    "/bWAPP/portal.php",
]

# Load Blacklisted IPs
def load_blacklist():
    if os.path.exists(BLACKLIST_FILE):
        with open(BLACKLIST_FILE) as f:
            return set(json.load(f))
    return set()

blacklisted_ips = load_blacklist()

# Initialize Counters
ip_counter = Counter()
suspicious_file_counter = Counter()
http_error_counter = Counter()
ssh_failed_login_counter = defaultdict(int)
detailed_ssh_attempts = []
alerts = []

# Process Apache access logs
def process_access_log(filepath):
    log_pattern = re.compile(r'(?P<ip>\S+) - - \[(?P<date>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) (?P<proto>\S+)" (?P<status>\d{3})')
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = log_pattern.search(line)
            if match:
                ip = match.group("ip")
                path = match.group("path")
                status = match.group("status")

                ip_counter[ip] += 1

                if path in SUSPICIOUS_FILES:
                    suspicious_file_counter[path] += 1
                    alerts.append({
                        "Type": "Suspicious File",
                        "IP": ip,
                        "HTTP_Status": status,
                        "Path": path,
                        "Description": "Suspicious File Access"
                    })

                if status.startswith("4") or status.startswith("5"):
                    http_error_counter[status] += 1
                    alerts.append({
                        "Type": "HTTP Error",
                        "IP": ip,
                        "HTTP_Status": status,
                        "Path": path,
                        "Description": "Suspicious HTTP Status"
                    })

# Process SSH logs
def process_auth_log(filepath):
    ssh_pattern = re.compile(r"Failed password for .* from (?P<ip>\d+\.\d+\.\d+\.\d+)")
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            match = ssh_pattern.search(line)
            if match:
                ip = match.group("ip")
                ssh_failed_login_counter[ip] += 1
                detailed_ssh_attempts.append({
                    "IP": ip,
                    "Log_Line": line.strip()
                })

# Save outputs
def save_alerts():
    with open(ALERTS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["Type", "IP", "HTTP_Status", "Path", "Description"])
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert)

def save_ssh_failed_logins():
    with open(SSH_FAILED_LOGINS_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["IP", "Log_Line"])
        writer.writeheader()
        for entry in detailed_ssh_attempts:
            writer.writerow(entry)

# Display Summary in Clean Format
def display_summary():
    print(Fore.CYAN + "\n======================= SUMMARY =======================")

    # Top 5 IP addresses
    print(Fore.BLUE + "\nTop 5 IPs by Access Count:")
    print(Fore.YELLOW + "-" * 55)
    print(f"{'IP Address':<20} {'Status':<12} {'Requests':>10}")
    print(Fore.YELLOW + "-" * 55)
    for ip, count in ip_counter.most_common(5):
        status = "Blacklisted" if ip in blacklisted_ips else "Unknown"
        color = Fore.RED if status == "Blacklisted" else Fore.GREEN
        print(f"{color}{ip:<20} {status:<12} {count:>10}")

    # Suspicious Files
    print(Fore.BLUE + "\nSuspicious Files Accessed:")
    print(Fore.YELLOW + "-" * 55)
    print(f"{'File Path':<40} {'Hits':>10}")
    print(Fore.YELLOW + "-" * 55)
    for path, hits in suspicious_file_counter.most_common(5):
        print(f"{Fore.MAGENTA}{path:<40} {hits:>10}")

    # HTTP Errors
    print(Fore.BLUE + "\nHTTP Errors (4xx/5xx):")
    print(Fore.YELLOW + "-" * 55)
    print(f"{'HTTP Status':<20} {'Count':>10}")
    print(Fore.YELLOW + "-" * 55)
    for status, count in http_error_counter.most_common():
        print(f"{Fore.RED}{status:<20} {count:>10}")

    # SSH Brute Force Attempts
    print(Fore.BLUE + "\nSSH Brute Force Attempts:")
    print(Fore.YELLOW + "-" * 55)
    print(f"{'IP Address':<20} {'Attempts':>10}")
    print(Fore.YELLOW + "-" * 55)
    for ip, count in ssh_failed_login_counter.items():
        color = Fore.RED if ip in blacklisted_ips else Fore.MAGENTA
        print(f"{color}{ip:<20} {count:>10}")

    print(Fore.GREEN + f"\n[INFO] Detailed output saved to: {OUTPUT_DIR}")
    print(Fore.CYAN + "=" * 55)

def display_alerts():
    print(Fore.CYAN + "\n====================== ALERTS ======================")
    if alerts:
        with open(ALERTS_CSV, "r") as f:
            print(Fore.YELLOW + f.read())
    else:
        print(Fore.GREEN + "No alerts detected.")
    print(Fore.CYAN + "=" * 55)

def display_blacklisted_ips():
    print(Fore.CYAN + "\n================ Blacklisted IPs ==================")
    if blacklisted_ips:
        for ip in blacklisted_ips:
            print(Fore.RED + ip)
    else:
        print(Fore.GREEN + "No blacklisted IPs found.")
    print(Fore.CYAN + "=" * 55)

def main():
    # Process logs
    filenames = os.listdir(LOGS_DIR)
    filepaths = [os.path.join(LOGS_DIR, filename) for filename in filenames]
    print(Fore.GREEN + f"\n[INFO] Processing logs: {', '.join(filenames)}\n")

    for filepath in filepaths:
        if "access" in filepath:
            process_access_log(filepath)
        elif "auth" in filepath:
            process_auth_log(filepath)

    # Save outputs and display everything
    save_alerts()
    save_ssh_failed_logins()
    display_summary()
    display_alerts()
    display_blacklisted_ips()

if __name__ == "__main__":
    main()
    print(Fore.GREEN + "\n✅ All Done.")
    input(Fore.CYAN + "Press Enter to exit...")

