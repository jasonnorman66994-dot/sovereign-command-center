# Real-Time Alerting Script (Email/Slack/Teams)
# Monitors incident CSVs for new critical/high events and sends alerts

import csv
import time
import smtplib
from email.mime.text import MIMEText

INCIDENT_FILES = [
    'incidents_scenario1.csv',
    'incidents_scenario2.csv',
    'incidents_scenario3.csv',
    'incidents_scenario4.csv',
    'incidents_scenario5.csv',
    'incidents_scenario6.csv'
]

ALERT_EMAIL = 'soc-alerts@example.com'
SMTP_SERVER = 'smtp.example.com'
ALERT_RECIPIENTS = ['soc_team@example.com']

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
                        msg = MIMEText(f"ALERT: {row.get('scenario', fname)}\nSeverity: {row.get('severity')}\nEvidence: {row.get('evidence')}")
                        msg['Subject'] = f"SOC Alert: {row.get('scenario', fname)} ({row.get('severity')})"
                        msg['From'] = ALERT_EMAIL
                        msg['To'] = ', '.join(ALERT_RECIPIENTS)
                        with smtplib.SMTP(SMTP_SERVER) as server:
                            server.sendmail(ALERT_EMAIL, ALERT_RECIPIENTS, msg.as_string())
                        print(f"Alert sent for {row.get('scenario', fname)}")
        except FileNotFoundError:
            continue
    time.sleep(60)  # Check every minute
