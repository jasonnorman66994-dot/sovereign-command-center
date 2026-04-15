# Log Parser: Lateral Movement via Compromised OAuth App (Scenario 9)
# Parses idp, graphapi, and ueba logs for app escalation and lateral movement

import csv
import re
from datetime import datetime

APP_PERM_CHANGE_REGEX = re.compile(r'APP PERMISSION CHANGE app="(?P<app>[^"]+)" scopes_added="(?P<scopes>[^"]+)"')
PERM_ESCALATION_REGEX = re.compile(r'Permission escalation requested by non-admin user=(?P<user>[^ ]+)')
TOKEN_USED_REGEX = re.compile(r'ACCESS TOKEN USED app="(?P<app>[^"]+)" user=(?P<user>[^ ]+) action="(?P<action>[^"]+)" ip=(?P<ip>[^ ]+)')
API_CALL_REGEX = re.compile(r'API CALL app="(?P<app>[^"]+)" action="(?P<action>[^"]+)"(?: repo="(?P<repo>[^"]+)")?(?: user=(?P<user>[^ ]+))?(?: size=(?P<size>[\d\.]+)MB)?')
REFRESH_TOKEN_REGEX = re.compile(r'REFRESH TOKEN ISSUED app="(?P<app>[^"]+)" lifetime="(?P<lifetime>\d+) days" user=(?P<user>[^ ]+)')
UEBA_REGEX = re.compile(r'anomaly_score=(?P<score>[\d\.]+) entity="(?P<entity>[^"]+)" reason="(?P<reason>[^"]+)"')


def parse_app_perm_changes(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'app', 'scopes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = APP_PERM_CHANGE_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'app': m.group('app'), 'scopes': m.group('scopes')})

def parse_perm_escalations(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = PERM_ESCALATION_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'user': m.group('user')})

def parse_token_used(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'app', 'user', 'action', 'ip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = TOKEN_USED_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'app': m.group('app'), 'user': m.group('user'), 'action': m.group('action'), 'ip': m.group('ip')})

def parse_api_calls(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'app', 'action', 'repo', 'user', 'size']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = API_CALL_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'app': m.group('app'), 'action': m.group('action'), 'repo': m.group('repo') or '', 'user': m.group('user') or '', 'size': m.group('size') or ''})

def parse_refresh_tokens(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'app', 'lifetime', 'user']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = REFRESH_TOKEN_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'app': m.group('app'), 'lifetime': m.group('lifetime'), 'user': m.group('user')})

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
    with open('sample_lateral_movement_oauth.log') as f:
        lines = f.readlines()
    parse_app_perm_changes(lines, 'app_perm_changes.csv')
    parse_perm_escalations(lines, 'perm_escalations.csv')
    parse_token_used(lines, 'token_used.csv')
    parse_api_calls(lines, 'api_calls.csv')
    parse_refresh_tokens(lines, 'refresh_tokens.csv')
    parse_ueba(lines, 'ueba.csv')
    print('Parsed app_perm_changes.csv, perm_escalations.csv, token_used.csv, api_calls.csv, refresh_tokens.csv, ueba.csv')
