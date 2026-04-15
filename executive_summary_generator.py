# Automated Executive Summary Generator
# Produces a Markdown executive summary from cross-scenario analytics and end-of-day summary

import json
from datetime import datetime
import re


# Scenario 11 is included automatically if present in analytics JSON
with open('cross_scenario_analytics.json') as f:
    analytics = json.load(f)

try:
    with open('end_of_day_summary.json') as f:
        summary = json.load(f)
except FileNotFoundError:
    summary = []


def scenario_sort_key(scenario_name):
    match = re.search(r"SCENARIO_?(\d+)", scenario_name or "")
    return int(match.group(1)) if match else 999


def terminal_scenario_entry(analytics_payload):
    ranked = sorted(
        analytics_payload.items(),
        key=lambda item: (
            scenario_sort_key(item[0]),
            len(item[1].get('signals', [])),
            len(item[1].get('actions', [])),
        ),
        reverse=True,
    )
    return ranked[0] if ranked else (None, None)

lines = [f"# SOC Executive Summary — {datetime.now().strftime('%Y-%m-%d')}\n"]

terminal_scenario, terminal_payload = terminal_scenario_entry(analytics)
if terminal_scenario and terminal_payload:
    terminal_classification = ', '.join(terminal_payload.get('classifications', [])) or 'Terminal catastrophic incident'
    terminal_signals = len(terminal_payload.get('signals', []))
    terminal_actions = len(terminal_payload.get('actions', []))
    terminal_risk = ', '.join(terminal_payload.get('risk_levels', [])) or 'Unknown'
    lines.append('## Terminal Incident\n')
    lines.append(
        f"{terminal_scenario} is the worst-day-of-the-year event in this SOC training universe: "
        f"a {terminal_classification.lower()} requiring immediate containment, executive escalation, "
        f"forensic preservation, and continuity actions across the full environment.\n\n"
    )
    lines.append(
        f"- Risk posture: {terminal_risk}\n"
        f"- Detection pressure: {terminal_signals} primary signals\n"
        f"- Required response tracks: {terminal_actions} coordinated action(s)\n\n"
    )

lines.append("## Scenario Overview\n")
lines.append("| Scenario | Incidents | Max Severity | Classification |\n|----------|-----------|--------------|----------------|\n")
for scenario, data in sorted(analytics.items(), key=lambda item: scenario_sort_key(item[0])):
    incidents = len(data.get('signals', []))
    max_sev = ', '.join(data.get('risk_levels', []))
    classification = ', '.join(data.get('classifications', []))
    lines.append(f"| {scenario} | {incidents} | {max_sev} | {classification} |\n")

lines.append("\n## Key Signals and Actions by Scenario\n")
for scenario, data in sorted(analytics.items(), key=lambda item: scenario_sort_key(item[0])):
    lines.append(f"### {scenario}\n")
    lines.append(f"**Signals:** {', '.join(data.get('signals', []))}\n")
    lines.append(f"**Actions:** {', '.join(data.get('actions', []))}\n\n")

lines.append("---\n*Generated automatically by SOC analytics pipeline.*\n")

with open('executive_summary.md', 'w') as f:
    f.writelines(lines)

print('Executive summary written to executive_summary.md')
