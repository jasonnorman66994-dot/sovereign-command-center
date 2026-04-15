# End-of-Day Summary Automation Script
# Aggregates incident classifications, severity, and evidence for executive/audit reporting

import csv
import json
from collections import defaultdict

INCIDENT_FILES = [
    'incidents_scenario1.csv',
    'incidents_scenario2.csv',
    'incidents_scenario3.csv',
    'incidents_scenario4.csv',
    'incidents_scenario5.csv'
]

SEVERITY_MAP = {'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}

summary = defaultdict(lambda: {'count': 0, 'max_severity': 'Low', 'evidence': []})

for fname in INCIDENT_FILES:
    try:
        with open(fname) as f:
            reader = csv.DictReader(f)
            for row in reader:
                scenario = row.get('scenario', 'Unknown')
                severity = row.get('severity', 'Low')
                summary[scenario]['count'] += 1
                if SEVERITY_MAP[severity] > SEVERITY_MAP[summary[scenario]['max_severity']]:
                    summary[scenario]['max_severity'] = severity
                summary[scenario]['evidence'].append(row.get('evidence', ''))
    except FileNotFoundError:
        continue

output = []
for scenario, data in summary.items():
    output.append({
        'scenario': scenario,
        'incident_count': data['count'],
        'max_severity': data['max_severity'],
        'evidence_samples': data['evidence'][:3]
    })

with open('end_of_day_summary.json', 'w') as f:
    json.dump(output, f, indent=2)

print('End-of-day summary written to end_of_day_summary.json')
