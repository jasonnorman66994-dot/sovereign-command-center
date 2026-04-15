# Log Parsing Extension: Mailbox Rules & Device Fingerprints
# This script parses mailbox rule creation and device fingerprint logs for BEC/insider threat detection.

import csv
import re
from datetime import datetime

MAILBOX_RULE_REGEX = re.compile(r'RULE CREATED user=(?P<user>[^ ]+) action=(?P<action>[^ ]+) pattern="(?P<pattern>[^"]+)"(?: folder="(?P<folder>[^"]+)")?')
DEVICE_FINGERPRINT_REGEX = re.compile(r'WARNING: OAuth token used from new device fingerprint: (?P<fingerprint>[A-Z0-9\-]+)')


def parse_mailbox_rules(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'action', 'pattern', 'folder']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            match = MAILBOX_RULE_REGEX.search(line)
            if match:
                ts = extract_timestamp(line)
                row = match.groupdict()
                row['timestamp'] = ts
                writer.writerow(row)

def parse_device_fingerprints(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'fingerprint']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            match = DEVICE_FINGERPRINT_REGEX.search(line)
            if match:
                ts = extract_timestamp(line)
                user = extract_user(line)
                writer.writerow({'timestamp': ts, 'user': user, 'fingerprint': match.group('fingerprint')})

def extract_timestamp(line):
    # Example: Apr 14 06:06:10
    try:
        dt = datetime.strptime(line[:15], '%b %d %H:%M:%S')
        # Use current year for demo
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return ''

def extract_user(line):
    m = re.search(r'user=([^ ]+)', line)
    return m.group(1) if m else ''

if __name__ == '__main__':
    with open('sample_bec.log') as f:
        lines = f.readlines()
    parse_mailbox_rules(lines, 'mailbox_rules.csv')
    parse_device_fingerprints(lines, 'device_fingerprints.csv')
    print('Parsed mailbox_rules.csv and device_fingerprints.csv')
