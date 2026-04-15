# Real-Time Alerting to Slack/Telegram
# Sends alerts for new critical/high incidents to Slack and Telegram

import csv
import time
import requests

INCIDENT_FILES = [
    'incidents_scenario1.csv',
    'incidents_scenario2.csv',
    'incidents_scenario3.csv',
    'incidents_scenario4.csv',
    'incidents_scenario5.csv',
    'incidents_scenario6.csv',
    'incidents_scenario7.csv'
]

SLACK_WEBHOOK_URL = 'https://hooks.slack.com/services/XXX/YYY/ZZZ'
TELEGRAM_BOT_TOKEN = '123456789:ABCDEF...'
TELEGRAM_CHAT_ID = '987654321'

seen = set()

while True:
    for fname in INCIDENT_FILES:
        try:
            with open(fname) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    key = (fname, row.get('evidence', ''), row.get('severity', ''))
                    if key in seen:
                        continue
                    seen.add(key)
                    if row.get('severity', '').lower() in ['critical', 'high']:
                        msg = f"*SOC Alert:* {row.get('scenario', fname)}\n*Severity:* {row.get('severity')}\n*Evidence:* {row.get('evidence')}"
                        # Slack
                        requests.post(SLACK_WEBHOOK_URL, json={"text": msg})
                        # Telegram
                        telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
                        requests.post(telegram_url, data={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"})
                        print(f"Alert sent for {row.get('scenario', fname)}")
        except FileNotFoundError:
            continue
    time.sleep(60)
