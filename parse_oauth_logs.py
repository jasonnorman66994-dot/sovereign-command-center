# Log Parser: OAuth Consent & Token Activity
# Parses OAuth consent logs and token activity for Scenario 5 (OAuth Abuse)

import csv
import re
from datetime import datetime

OAUTH_CONSENT_REGEX = re.compile(r'USER CONSENT user=(?P<user>[^ ]+) app="(?P<app>[^"]+)" scopes="(?P<scopes>[^"]+)"')
OAUTH_PUBLISHER_REGEX = re.compile(r'App "(?P<app>[^"]+)" publisher=(?P<publisher>[^ ]+)')
TOKEN_ACTIVITY_REGEX = re.compile(r'ACCESS TOKEN USED app="(?P<app>[^"]+)" user=(?P<user>[^ ]+) action=(?P<action>[^ ]+) ip=(?P<ip>[^ ]+)')


def parse_oauth_consents(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'app', 'scopes', 'publisher']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        publisher_map = {}
        for line in log_lines:
            consent = OAUTH_CONSENT_REGEX.search(line)
            publisher = OAUTH_PUBLISHER_REGEX.search(line)
            ts = extract_timestamp(line)
            if consent:
                app = consent.group('app')
                publisher_val = publisher.group('publisher') if publisher and publisher.group('app') == app else ''
                writer.writerow({
                    'timestamp': ts,
                    'user': consent.group('user'),
                    'app': app,
                    'scopes': consent.group('scopes'),
                    'publisher': publisher_val
                })

def parse_token_activity(log_lines, output_csv):
    with open(output_csv, 'w', newline='') as csvfile:
        fieldnames = ['timestamp', 'user', 'app', 'action', 'ip']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for line in log_lines:
            match = TOKEN_ACTIVITY_REGEX.search(line)
            if match:
                ts = extract_timestamp(line)
                writer.writerow({
                    'timestamp': ts,
                    'user': match.group('user'),
                    'app': match.group('app'),
                    'action': match.group('action'),
                    'ip': match.group('ip')
                })

def extract_timestamp(line):
    try:
        dt = datetime.strptime(line[:15], '%b %d %H:%M:%S')
        return dt.replace(year=datetime.now().year).isoformat()
    except Exception:
        return ''

if __name__ == '__main__':
    with open('sample_oauth_abuse.log') as f:
        lines = f.readlines()
    parse_oauth_consents(lines, 'oauth_consents.csv')
    parse_token_activity(lines, 'token_activity.csv')
    print('Parsed oauth_consents.csv and token_activity.csv')
