# Log Parser: Insider Misuse (Scenario 7)
# Parses privilege escalation, file access, ZIP creation, upload, and UEBA logs

import csv
import re
from datetime import datetime

ROLE_CHANGE_REGEX = re.compile(r'ROLE CHANGE user=(?P<user>[^ ]+) old_role="(?P<old_role>[^"]+)" new_role="(?P<new_role>[^"]+)"')
ROLE_WARNING_REGEX = re.compile(r'WARNING: Role change not approved')
FILE_ACCESS_REGEX = re.compile(r'FILE ACCESS user=(?P<user>[^ ]+) path="(?P<path>[^"]+)" action=(?P<action>[^ ]+)')
ZIP_CREATED_REGEX = re.compile(r'ZIP CREATED user=(?P<user>[^ ]+) path="(?P<path>[^"]+)" contents=(?P<contents>\d+) files')
UPLOAD_REGEX = re.compile(r'UPLOAD user=(?P<user>[^ ]+) dest="(?P<dest>[^"]+)" size=(?P<size>\d+)MB')
UEBA_REGEX = re.compile(r'anomaly_score=(?P<score>[\d\.]+) user=(?P<user>[^ ]+) reason="(?P<reason>[^"]+)"')


def parse_role_changes(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'old_role', 'new_role', 'approved']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        approved = True
        for line in log_lines:
            ts = extract_timestamp(line)
            m = ROLE_CHANGE_REGEX.search(line)
            if m:
                approved = not ROLE_WARNING_REGEX.search(line)
                writer.writerow({'timestamp': ts, 'user': m.group('user'), 'old_role': m.group('old_role'), 'new_role': m.group('new_role'), 'approved': approved})

def parse_file_access(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'path', 'action']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = FILE_ACCESS_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'user': m.group('user'), 'path': m.group('path'), 'action': m.group('action')})

def parse_zip_created(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'path', 'contents']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = ZIP_CREATED_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'user': m.group('user'), 'path': m.group('path'), 'contents': m.group('contents')})

def parse_uploads(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'dest', 'size']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = UPLOAD_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'user': m.group('user'), 'dest': m.group('dest'), 'size': m.group('size')})

def parse_ueba(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'anomaly_score', 'reason']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = UEBA_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'user': m.group('user'), 'anomaly_score': m.group('score'), 'reason': m.group('reason')})

def extract_timestamp(line):
    try:
        dt = datetime.strptime(line[:15], '%b %d %H:%M:%S')
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return ''

if __name__ == '__main__':
    with open('sample_insider_misuse.log') as f:
        lines = f.readlines()
    parse_role_changes(lines, 'role_changes.csv')
    parse_file_access(lines, 'file_access.csv')
    parse_zip_created(lines, 'zip_created.csv')
    parse_uploads(lines, 'uploads.csv')
    parse_ueba(lines, 'ueba.csv')
    print('Parsed role_changes.csv, file_access.csv, zip_created.csv, uploads.csv, ueba.csv')
