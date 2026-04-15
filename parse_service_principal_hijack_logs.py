# Log Parser: Cloud Workload Compromise (Scenario 10)
# Parses cloudapi, iam, compute, storage, and ueba logs for SPN hijack detection

import csv
import re
from datetime import datetime

SPN_LOGIN_REGEX = re.compile(r'SERVICE PRINCIPAL LOGIN spn="(?P<spn>[^"]+)" method="(?P<method>[^"]+)" ip=(?P<ip>[^ ]+)')
OLD_SECRET_REGEX = re.compile(r'Secret used is older than (?P<days>\d+) days')
ROLE_ASSIGN_REGEX = re.compile(r'ROLE ASSIGNMENT spn="(?P<spn>[^"]+)" role="(?P<role>[^"]+)" scope="(?P<scope>[^"]+)"')
ROLE_ASSIGN_WARN_REGEX = re.compile(r'SPN attempted to assign itself a new role')
VM_LIST_REGEX = re.compile(r'VM LIST spn="(?P<spn>[^"]+)" region="(?P<region>[^"]+)"')
VM_START_REGEX = re.compile(r'VM START spn="(?P<spn>[^"]+)" vm="(?P<vm>[^"]+)"')
VM_EXT_REGEX = re.compile(r'VM EXTENSION INSTALL spn="(?P<spn>[^"]+)" extension="(?P<ext>[^"]+)" payload="(?P<payload>[^"]+)"')
BLOB_DL_REGEX = re.compile(r'BLOB DOWNLOAD spn="(?P<spn>[^"]+)" container="(?P<container>[^"]+)" size=(?P<size>[\d\.]+)GB')
NEW_SECRET_REGEX = re.compile(r'NEW SECRET CREATED spn="(?P<spn>[^"]+)" secret_id="(?P<secret_id>[^"]+)" lifetime="(?P<lifetime>[^"]+)"')
UEBA_REGEX = re.compile(r'anomaly_score=(?P<score>[\d\.]+) entity="(?P<entity>[^"]+)" reason="(?P<reason>[^"]+)"')


def parse_spn_logins(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'spn', 'method', 'ip', 'old_secret']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        old_secret = ''
        for line in log_lines:
            ts = extract_timestamp(line)
            m = SPN_LOGIN_REGEX.search(line)
            if m:
                old_secret_match = OLD_SECRET_REGEX.search(line)
                old_secret = old_secret_match.group('days') if old_secret_match else ''
                writer.writerow({'timestamp': ts, 'spn': m.group('spn'), 'method': m.group('method'), 'ip': m.group('ip'), 'old_secret': old_secret})

def parse_role_assignments(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'spn', 'role', 'scope', 'self_assign']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = ROLE_ASSIGN_REGEX.search(line)
            if m:
                self_assign = bool(ROLE_ASSIGN_WARN_REGEX.search(line))
                writer.writerow({'timestamp': ts, 'spn': m.group('spn'), 'role': m.group('role'), 'scope': m.group('scope'), 'self_assign': self_assign})

def parse_vm_activity(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'spn', 'region', 'vm', 'extension', 'payload']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m_list = VM_LIST_REGEX.search(line)
            m_start = VM_START_REGEX.search(line)
            m_ext = VM_EXT_REGEX.search(line)
            if m_list:
                writer.writerow({'timestamp': ts, 'spn': m_list.group('spn'), 'region': m_list.group('region'), 'vm': '', 'extension': '', 'payload': ''})
            if m_start:
                writer.writerow({'timestamp': ts, 'spn': m_start.group('spn'), 'region': '', 'vm': m_start.group('vm'), 'extension': '', 'payload': ''})
            if m_ext:
                writer.writerow({'timestamp': ts, 'spn': m_ext.group('spn'), 'region': '', 'vm': '', 'extension': m_ext.group('ext'), 'payload': m_ext.group('payload')})

def parse_blob_downloads(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'spn', 'container', 'size']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = BLOB_DL_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'spn': m.group('spn'), 'container': m.group('container'), 'size': m.group('size')})

def parse_new_secrets(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'spn', 'secret_id', 'lifetime']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = NEW_SECRET_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'spn': m.group('spn'), 'secret_id': m.group('secret_id'), 'lifetime': m.group('lifetime')})

def parse_ueba(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'entity', 'anomaly_score', 'reason']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = UEBA_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'entity': m.group('entity'), 'anomaly_score': m.group('score'), 'reason': m.group('reason')})

def extract_timestamp(line):
    try:
        dt = datetime.strptime(line[:15], '%b %d %H:%M:%S')
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return ''

if __name__ == '__main__':
    with open('sample_service_principal_hijack.log') as f:
        lines = f.readlines()
    parse_spn_logins(lines, 'spn_logins.csv')
    parse_role_assignments(lines, 'role_assignments.csv')
    parse_vm_activity(lines, 'vm_activity.csv')
    parse_blob_downloads(lines, 'blob_downloads.csv')
    parse_new_secrets(lines, 'new_secrets.csv')
    parse_ueba(lines, 'ueba.csv')
    print('Parsed spn_logins.csv, role_assignments.csv, vm_activity.csv, blob_downloads.csv, new_secrets.csv, ueba.csv')
