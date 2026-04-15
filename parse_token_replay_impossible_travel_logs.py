# Log Parser: Impossible Travel + Token Replay (Scenario 8)
# Parses authz, graphapi, and ueba logs for session hijack detection

import csv
import re
from datetime import datetime

LOGIN_REGEX = re.compile(r'LOGIN SUCCESS user=(?P<user>[^ ]+) ip=(?P<ip>[^ ]+) location="(?P<location>[^"]+)" device="(?P<device>[^"]+)" token_id="(?P<token>[^"]+)"')
SESSION_START_REGEX = re.compile(r'SESSION START user=(?P<user>[^ ]+) token_id="(?P<token>[^"]+)"')
TOKEN_REPLAY_REGEX = re.compile(r'Token replay detected for token_id="(?P<token>[^"]+)"')
API_CALL_REGEX = re.compile(r'API CALL user=(?P<user>[^ ]+) token_id="(?P<token>[^"]+)" action="(?P<action>[^"]+)"(?: repo="(?P<repo>[^"]+)")?(?: project="(?P<project>[^"]+)")?(?: size=(?P<size>[\d\.]+)GB)?')
UEBA_REGEX = re.compile(r'anomaly_score=(?P<score>[\d\.]+) user=(?P<user>[^ ]+) reason="(?P<reason>[^"]+)"')


def parse_logins(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'ip', 'location', 'device', 'token_id']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = LOGIN_REGEX.search(line)
            if m:
                writer.writerow({
                    'timestamp': ts,
                    'user': m.group('user'),
                    'ip': m.group('ip'),
                    'location': m.group('location'),
                    'device': m.group('device'),
                    'token_id': m.group('token')
                })

def parse_token_replay(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'token_id']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = TOKEN_REPLAY_REGEX.search(line)
            if m:
                writer.writerow({'timestamp': ts, 'token_id': m.group('token')})

def parse_api_calls(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'token_id', 'action', 'repo', 'project', 'size']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            ts = extract_timestamp(line)
            m = API_CALL_REGEX.search(line)
            if m:
                writer.writerow({
                    'timestamp': ts,
                    'user': m.group('user'),
                    'token_id': m.group('token'),
                    'action': m.group('action'),
                    'repo': m.group('repo') or '',
                    'project': m.group('project') or '',
                    'size': m.group('size') or ''
                })

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
    with open('sample_token_replay.log') as f:
        lines = f.readlines()
    parse_logins(lines, 'logins.csv')
    parse_token_replay(lines, 'token_replay.csv')
    parse_api_calls(lines, 'api_calls.csv')
    parse_ueba(lines, 'ueba.csv')
    print('Parsed logins.csv, token_replay.csv, api_calls.csv, ueba.csv')
