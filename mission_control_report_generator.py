from datetime import datetime
import json

SECTIONS = [
    ("Executive Summary", "executive_summary.md"),
    ("Drill-Down Report", "drilldown_report.md"),
    ("Chain Timeline", "multi_scenario_chain_timeline.md"),
    ("Incident Attack Graph", "incident_attack_graph.md"),
    ("Red Team Deliverable Package", "red_team_deliverable_package.md"),
    ("Campaign Launcher Manifest", "campaign_launcher_manifest.md"),
    ("Chain KPIs", "chain_kpis.md"),
]

OUT_FILE = "mission_control_report.md"
ANALYTICS_FILE = "cross_scenario_analytics.json"
KPI_FILE = "chain_kpis.json"


def read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except UnicodeDecodeError:
        with open(path, "r", encoding="cp1252", errors="replace") as f:
            return f.read().strip()
    except FileNotFoundError:
        return f"[Missing file: {path}]"


def load_analytics():
    try:
        with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def load_kpis():
    try:
        with open(KPI_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def severity_rank(level):
    return {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}.get(level, 0)


def scorebar(level):
    bars = {"Critical": "[####]", "High": "[### ]", "Medium": "[##  ]", "Low": "[#   ]"}
    return bars.get(level, "[    ]")


lines = [f"# Mission Control Unified Report — {datetime.now().strftime('%Y-%m-%d')}\n\n"]
lines.append("This report combines executive narrative, prioritized drill-down, chain timeline, and KPI metrics.\n\n")

analytics = load_analytics()
kpis = load_kpis()
if analytics:
    containment = kpis.get("estimated_containment_latency_minutes", {})
    scenario_rows = []
    for scenario, payload in analytics.items():
        risk_levels = payload.get("risk_levels", [])
        risk = risk_levels[0] if risk_levels else "Low"
        signal_count = len(payload.get("signals", []))
        containment_minutes = containment.get(scenario, -1)
        scenario_rows.append((severity_rank(risk), containment_minutes, signal_count, scenario, risk))
    scenario_rows.sort(key=lambda row: (row[0], row[1], row[2], row[3]), reverse=True)

    lines.append("## Severity Scorecard\n\n")
    lines.append("| Scenario | Severity | Scorebar | Signals | Containment Latency |\n")
    lines.append("|---|---|---|---:|---:|\n")
    for _, containment_minutes, signal_count, scenario, risk in scenario_rows:
        latency_text = "n/a" if containment_minutes < 0 else containment_minutes
        lines.append(f"| {scenario} | {risk} | {scorebar(risk)} | {signal_count} | {latency_text} |\n")
    lines.append("\n")

for title, file_name in SECTIONS:
    lines.append(f"## {title}\n\n")
    lines.append(read_text(file_name))
    lines.append("\n\n")

with open(OUT_FILE, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"Wrote {OUT_FILE}")
