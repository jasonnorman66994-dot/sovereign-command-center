# Scenario Chaining Logic for Red/Blue Team Exercises
# Chains scenarios, randomizes injects, and logs results for adversarial simulation

import random
import subprocess
import json
from datetime import datetime

SCENARIOS = [
    'scenario1_spam_burst',
    'scenario2_malware_attachment',
    'scenario3_unauthorized_access',
    'scenario4_bec',
    'scenario5_oauth_abuse',
    'scenario6_vendor_compromise',
    'scenario7_impossible_travel',
    'scenario8_insider_exfiltration'
]

SCENARIO_SCRIPTS = {
    'scenario1_spam_burst': 'parse_mail_log.py',
    'scenario2_malware_attachment': 'parse_mail_log.py',
    'scenario3_unauthorized_access': 'parse_windows_event_logs.ps1',
    'scenario4_bec': 'parse_mailbox_rules_and_fingerprints.py',
    'scenario5_oauth_abuse': 'parse_oauth_logs.py',
    'scenario6_vendor_compromise': 'parse_vendor_compromise_logs.py',
    'scenario7_impossible_travel': 'parse_mail_log.py',
    'scenario8_insider_exfiltration': 'parse_mail_log.py'
}

results = []
random.shuffle(SCENARIOS)

for scenario in SCENARIOS:
    script = SCENARIO_SCRIPTS[scenario]
    ext = script.split('.')[-1]
    if ext == 'py':
        subprocess.run(['python', script])
    elif ext == 'ps1':
        subprocess.run(['pwsh', '-File', script])
    results.append({
        'scenario': scenario,
        'timestamp': datetime.now().isoformat(),
        'status': 'executed'
    })

with open('red_blue_team_scenario_log.json', 'w') as f:
    json.dump(results, f, indent=2)

print('Red/Blue team scenario chaining complete. Log in red_blue_team_scenario_log.json')
