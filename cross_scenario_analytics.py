# Unified Cross-Scenario Analytics Script
# Aggregates and correlates signals, actions, and risk across all scenarios for advanced reporting

import json
import glob
from collections import defaultdict

EVAL_HARNESS_FILES = glob.glob('scenario*_eval_harness.json')  # Includes Scenario 11 automatically
SUMMARY_FILES = glob.glob('end_of_day_summary.json')

analytics = defaultdict(lambda: {'signals': set(), 'actions': set(), 'risk_levels': set(), 'classifications': set()})

for harness_file in EVAL_HARNESS_FILES:
    with open(harness_file) as f:
        data = json.load(f)
        # Primary schema: scenario_id + expected
        if data.get('scenario_id') and data.get('expected'):
            scenario_id = data['scenario_id']
            expected = data['expected']
            analytics[scenario_id]['signals'].update(expected.get('signals', []))
            analytics[scenario_id]['actions'].update(expected.get('actions', []))
            analytics[scenario_id]['risk_levels'].add(expected.get('risk_level', ''))
            analytics[scenario_id]['classifications'].add(expected.get('classification', ''))
            continue

        # Alternate schema: scenario + scoring_logic + automated_responses/actions
        if data.get('scenario'):
            scenario_id = str(data['scenario']).upper()
            scoring = data.get('scoring_logic', {})
            weight_keys = list(scoring.get('weights', {}).keys())
            response_block = data.get('automated_responses', data.get('automated_actions', []))
            actions = [x.get('action', '') for x in response_block if isinstance(x, dict)]

            analytics[scenario_id]['signals'].update(weight_keys)
            analytics[scenario_id]['actions'].update([a for a in actions if a])
            if scoring.get('thresholds', {}).get('critical') is not None:
                analytics[scenario_id]['risk_levels'].add('Critical')
            analytics[scenario_id]['classifications'].add('Behavioral Exfiltration Risk Scoring')

# Optionally, aggregate incident counts and max severity from end_of_day_summary.json
if SUMMARY_FILES:
    with open(SUMMARY_FILES[0]) as f:
        summary = json.load(f)
        for entry in summary:
            scenario = entry.get('scenario')
            if scenario in analytics:
                analytics[scenario]['incident_count'] = entry.get('incident_count', 0)
                analytics[scenario]['max_severity'] = entry.get('max_severity', '')

output = {}
for scenario in sorted(analytics.keys()):
    v = analytics[scenario]
    output[scenario] = {
        kk: sorted(list(vv)) if isinstance(vv, set) else vv
        for kk, vv in v.items()
    }

with open('cross_scenario_analytics.json', 'w') as f:
    json.dump(output, f, indent=2)

print('Cross-scenario analytics written to cross_scenario_analytics.json')
