# Log Parser: Vendor Compromise (Scenario 6)
# Parses vendor mailbox telemetry, content inspection, and user action logs

import csv
import re
from datetime import datetime

VENDOR_MAILBOX_RULE_REGEX = re.compile(r'indicator=mailbox_rule_forwarding target=(?P<target>[^ ]+)')
VENDOR_LOGIN_REGION_REGEX = re.compile(r'indicator=login_from_country=(?P<region>[^ ]+)')
BANKING_CHANGE_REGEX = re.compile(r'anomaly: banking details changed')
URGENCY_LANGUAGE_REGEX = re.compile(r'anomaly: payment urgency language detected')
USER_ACTION_REGEX = re.compile(r'user_action: (?P<user>[^ ]+) (?P<action>opened|replied)')


def parse_vendor_mailbox_telemetry(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'vendor', 'indicator', 'target', 'region']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            if 'mailbox_rule_forwarding' in line:
                m = VENDOR_MAILBOX_RULE_REGEX.search(line)
                if m:
                    writer.writerow({'timestamp': ts, 'vendor': extract_vendor(line), 'indicator': 'mailbox_rule_forwarding', 'target': m.group('target'), 'region': ''})
            elif 'login_from_country' in line:
                m = VENDOR_LOGIN_REGION_REGEX.search(line)
                if m:
                    writer.writerow({'timestamp': ts, 'vendor': extract_vendor(line), 'indicator': 'login_from_country', 'target': '', 'region': m.group('region')})

def parse_content_inspection(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'anomaly']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            if BANKING_CHANGE_REGEX.search(line) or URGENCY_LANGUAGE_REGEX.search(line):
                writer.writerow({'timestamp': ts, 'anomaly': line.strip()})

def parse_user_action(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'action']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = USER_ACTION_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'user': m.group('user'), 'action': m.group('action')})

def extract_vendor(line):
    m = re.search(r'vendor=([^ ]+)', line)
    return m.group(1) if m else ''

def extract_timestamp(line):
    try:
        dt = datetime.strptime(line[:15], '%b %d %H:%M:%S')
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return ''

if __name__ == '__main__':
    with open('sample_vendor_compromise.log') as f:
        lines = f.readlines()
    parse_vendor_mailbox_telemetry(lines, 'vendor_mailbox_telemetry.csv')
    parse_content_inspection(lines, 'content_inspection.csv')
    parse_user_action(lines, 'user_action.csv')
    print('Parsed vendor_mailbox_telemetry.csv, content_inspection.csv, user_action.csv')
