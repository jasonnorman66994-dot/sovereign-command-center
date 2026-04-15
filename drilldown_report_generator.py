import json
from datetime import datetime

INPUT_FILE = "cross_scenario_analytics.json"
MD_OUT = "drilldown_report.md"
CSV_OUT = "drilldown_report.csv"

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    analytics = json.load(f)

rows = []
for scenario, data in analytics.items():
    signals = data.get("signals", [])
    actions = data.get("actions", [])
    risk = ", ".join(data.get("risk_levels", []))
    cls = ", ".join(data.get("classifications", []))
    rows.append(
        {
            "scenario": scenario,
            "signal_count": len(signals),
            "action_count": len(actions),
            "risk": risk,
            "classification": cls,
            "top_signals": "; ".join(signals[:3]),
            "top_actions": "; ".join(actions[:3]),
        }
    )

RISK_PRIORITY = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "": 0,
}


def risk_rank(value):
    # Keep ordering deterministic even if multiple labels are present
    labels = [x.strip() for x in str(value).split(",") if x.strip()]
    if not labels:
        return 0
    return max(RISK_PRIORITY.get(label, 0) for label in labels)


rows.sort(
    key=lambda r: (risk_rank(r["risk"]), r["signal_count"], r["action_count"], r["scenario"]),
    reverse=True,
)

with open(CSV_OUT, "w", encoding="utf-8") as f:
    f.write("scenario,signal_count,action_count,risk,classification,top_signals,top_actions\n")
    for r in rows:
        f.write(
            f"{r['scenario']},{r['signal_count']},{r['action_count']},{r['risk']},"
            f"\"{r['classification']}\",\"{r['top_signals']}\",\"{r['top_actions']}\"\n"
        )

lines = [f"# SOC Drill-Down Report — {datetime.now().strftime('%Y-%m-%d')}\n\n"]
lines.append("## Scenario Prioritization\n\n")
lines.append("| Scenario | Risk | Signals | Actions | Classification |\n")
lines.append("|---|---|---:|---:|---|\n")
for r in rows:
    lines.append(
        f"| {r['scenario']} | {r['risk']} | {r['signal_count']} | {r['action_count']} | {r['classification']} |\n"
    )

lines.append("\n## Drill-Down Highlights\n\n")
for r in rows:
    lines.append(f"### {r['scenario']}\n")
    lines.append(f"- Top signals: {r['top_signals']}\n")
    lines.append(f"- Top actions: {r['top_actions']}\n")

with open(MD_OUT, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"Wrote {MD_OUT} and {CSV_OUT}")
