# Scenario Chaining & Automation Framework
# Chains multiple scenarios, triggers injects, and aggregates results for continuous SOC simulation

import os
import subprocess
import json
from datetime import datetime

SCENARIO_SCRIPTS = [
    'parse_mail_log.py',
    'parse_windows_event_logs.ps1',
    'parse_mailbox_rules_and_fingerprints.py',
    'parse_oauth_logs.py',
    'parse_vendor_compromise_logs.py'
]

EVAL_HARNESSES = [
    'scenario5_oauth_abuse_eval_harness.json',
    'scenario6_vendor_compromise_eval_harness.json'
]

SUMMARY_SCRIPT = 'end_of_day_summary_automation.py'

results = {}

for script in SCENARIO_SCRIPTS:
    ext = os.path.splitext(script)[1]
    if ext == '.py':
        subprocess.run(['python', script])
    elif ext == '.ps1':
        subprocess.run(['pwsh', '-File', script])

for harness in EVAL_HARNESSES:
    with open(harness) as f:
        results[harness] = json.load(f)

if os.path.exists(SUMMARY_SCRIPT):
    subprocess.run(['python', SUMMARY_SCRIPT])

with open('scenario_chain_results.json', 'w') as f:
    json.dump(results, f, indent=2)

print('Scenario chaining complete. Results in scenario_chain_results.json')
