from datetime import datetime
import json

ANALYTICS_FILE = "cross_scenario_analytics.json"
KPI_FILE = "chain_kpis.json"
OUT_FILE = "mission_control_deck.md"

with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
    analytics = json.load(f)
with open(KPI_FILE, "r", encoding="utf-8") as f:
    kpis = json.load(f)

rows = []
for scenario, payload in analytics.items():
    risk_levels = payload.get("risk_levels", [])
    risk = risk_levels[0] if risk_levels else "Low"
    rows.append((risk, len(payload.get("signals", [])), scenario, payload))
rows.sort(key=lambda row: ({"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(row[0], 0), row[1], row[2]), reverse=True)

lines = [
    "---\n",
    "marp: true\n",
    "theme: default\n",
    f"paginate: true\nheadingDivider: 2\n---\n\n",
    f"# Mission Control Deck\n\nGenerated {datetime.now().strftime('%Y-%m-%d')}\n",
    "\n## Program KPIs\n",
    f"- Scenario coverage: {kpis.get('scenario_count', 0)}\n",
    f"- Critical scenarios: {kpis.get('critical_scenarios', 0)}\n",
    f"- Avg dwell time: {kpis.get('average_dwell_time_minutes', 0)} minutes\n",
    f"- Avg response latency: {kpis.get('average_estimated_response_latency_minutes', 0)} minutes\n",
    f"- Avg containment latency: {kpis.get('average_estimated_containment_latency_minutes', 0)} minutes\n",
]

lines.append("\n## Severity Overview\n")
lines.append("| Scenario | Risk | Signals | Actions |\n|---|---|---:|---:|\n")
for risk, signal_count, scenario, payload in rows:
    lines.append(f"| {scenario} | {risk} | {signal_count} | {len(payload.get('actions', []))} |\n")

for risk, signal_count, scenario, payload in rows[:6]:
    lines.append(f"\n## {scenario}\n")
    lines.append(f"- Risk: {risk}\n")
    lines.append(f"- Top signals: {', '.join(payload.get('signals', [])[:3])}\n")
    lines.append(f"- Top actions: {', '.join(payload.get('actions', [])[:3])}\n")

with open(OUT_FILE, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"Wrote {OUT_FILE}")
