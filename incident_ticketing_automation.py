# Automated Incident Ticketing (Jira/ServiceNow Example)
# Creates a ticket for each new critical/high incident

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
    'incidents_scenario7.csv',
    'incidents_scenario8.csv'
]

JIRA_URL = 'https://yourcompany.atlassian.net/rest/api/2/issue'
JIRA_AUTH = ('jira_user', 'jira_api_token')
JIRA_PROJECT = 'SOC'

SERVICENOW_URL = 'https://yourcompany.service-now.com/api/now/table/incident'
SERVICENOW_AUTH = ('sn_user', 'sn_api_token')

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
                        summary = f"SOC Alert: {row.get('scenario', fname)} ({row.get('severity')})"
                        description = f"Evidence: {row.get('evidence')}"
                        # Jira
                        jira_payload = {
                            "fields": {
                                "project": {"key": JIRA_PROJECT},
                                "summary": summary,
                                "description": description,
                                "issuetype": {"name": "Incident"}
                            }
                        }
                        requests.post(JIRA_URL, json=jira_payload, auth=JIRA_AUTH)
                        # ServiceNow
                        sn_payload = {
                            "short_description": summary,
                            "description": description,
                            "urgency": "1",
                            "impact": "1"
                        }
                        requests.post(SERVICENOW_URL, json=sn_payload, auth=SERVICENOW_AUTH)
                        print(f"Ticket created for {row.get('scenario', fname)}")
        except FileNotFoundError:
            continue
    time.sleep(60)
