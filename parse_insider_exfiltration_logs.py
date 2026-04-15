import re
import datetime

# Focus on data volume anomalies and destination reputation
DETECTION_PATTERNS = {
    "large_egress": r"bytes_sent=(\d{7,})",  # Detects transfers > 1MB
    "cloud_storage_pivot": r"(drive\\.google\\.com|dropbox\\.com|mega\\.nz)",
    "unauthorized_auth": r"status=401.*user=([a-zA-Z0-9._%+-]+)",
}

CORPORATE_DOMAINS = ["corp.example.com", "internal.example.com"]

# Helper to check if a domain is non-corporate
def is_non_corporate(domain):
    return not any(domain.endswith(corp) for corp in CORPORATE_DOMAINS)

# We target specific sensitive business keywords in the file paths
SENSITIVE_TARGETS = r"(financial_records|payroll|client_list|business_strategy|mergers|tax|board_minutes|strategy)"

def is_off_hours(timestamp):
    hour = int(timestamp.split()[1].split(":")[0])
    return hour < 6

def is_service_account(user):
    return user.startswith("svc_")

def is_cloud_pivot(path):
    return any(domain in path for domain in ["drive.google.com", "dropbox.com", "mega.nz"])

def detect_insider_threat(log_line):
    # Parse fields
    parts = log_line.split("|")
    timestamp = parts[0].strip()
    user = "unknown"
    path = "unknown"
    bytes_sent = 0
    for part in parts:
        if "user=" in part:
            user = part.split("user=")[1].strip()
        if "path=" in part:
            path = part.split("path=")[1].strip()
        if "bytes_sent=" in part:
            bytes_sent = int(part.split("bytes_sent=")[1].strip())
    # Red flag detection
    red_flags = []
    if re.search(SENSITIVE_TARGETS, path, re.IGNORECASE):
        red_flags.append("Sensitive Directory Access")
    if bytes_sent > 524288000:
        red_flags.append("High Volume Egress")
    if is_off_hours(timestamp):
        red_flags.append("Off-Hours Activity")
    if is_service_account(user):
        red_flags.append("Service Account Usage")
    if is_cloud_pivot(path):
        red_flags.append("Cloud Storage Pivot")
    return {
        "user": user,
        "timestamp": timestamp,
        "path": path,
        "bytes_sent": bytes_sent,
        "red_flags": red_flags,
        "is_threat": bool(red_flags)
    }

def extract_signals(log_line):
    return detect_insider_threat(log_line)

def main():
    import sys
    for line in sys.stdin:
        result = extract_signals(line.strip())
        if result["is_threat"]:
            print(f"{line.strip()} | Detected: {result['red_flags']} | User: {result['user']} | Bytes: {result['bytes_sent']}")

if __name__ == "__main__":
    main()
