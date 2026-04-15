from datetime import datetime
import json
import re

ANALYTICS_FILE = "cross_scenario_analytics.json"
KPI_FILE = "chain_kpis.json"
TIMELINE_FILE = "multi_scenario_chain_timeline.md"
GRAPH_FILE = "incident_attack_graph.json"
RED_TEAM_FILE = "red_team_deliverable_package.json"
LAUNCHER_FILE = "campaign_launcher_manifest.json"
OUT_FILE = "mission_control_presentation.md"


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def load_text(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read().strip()


def scenario_sort_key(scenario_name):
    match = re.search(r"SCENARIO_?(\d+)", scenario_name or "")
    return int(match.group(1)) if match else 999


def terminal_scenario_entry(analytics_payload):
    ranked = sorted(
        analytics_payload.items(),
        key=lambda item: (
            scenario_sort_key(item[0]),
            len(item[1].get("signals", [])),
            len(item[1].get("actions", [])),
        ),
        reverse=True,
    )
    return ranked[0] if ranked else (None, None)


analytics = load_json(ANALYTICS_FILE)
kpis = load_json(KPI_FILE)
timeline = load_text(TIMELINE_FILE)
graph = load_json(GRAPH_FILE)
red_team = load_json(RED_TEAM_FILE)
launcher = load_json(LAUNCHER_FILE)

critical_rows = []
for scenario, payload in analytics.items():
    risk = ", ".join(payload.get("risk_levels", [])) or "Low"
    critical_rows.append((risk, len(payload.get("signals", [])), scenario, payload))
critical_rows.sort(key=lambda row: (row[0] == "Critical", row[1], row[2]), reverse=True)

terminal_scenario, terminal_payload = terminal_scenario_entry(analytics)
terminal_classification = (
    ', '.join(terminal_payload.get('classifications', []))
    if terminal_payload else 'Terminal catastrophic incident'
)

lines = [
    "---\n",
    "marp: true\n",
    "theme: default\n",
    "paginate: true\n",
    "title: Mission Control SOC Brief\n",
    "---\n\n",
    f"# Mission Control SOC Brief\n\nGenerated {datetime.now().strftime('%Y-%m-%d')}\n\n",
    "---\n\n",
    "## Executive Posture\n\n",
    f"- Scenario coverage: {kpis.get('scenario_count', 0)}\n",
    f"- Critical scenarios: {kpis.get('critical_scenarios', 0)}\n",
    f"- Avg response latency: {kpis.get('average_estimated_response_latency_minutes', 'n/a')} minutes\n",
    f"- Avg containment latency: {kpis.get('average_estimated_containment_latency_minutes', 'n/a')} minutes\n",
    f"- Highest signal density: {kpis.get('highest_signal_density', {}).get('scenario', 'n/a')}\n",
    "\n---\n\n",
    "## Terminal Incident\n\n",
]

if terminal_scenario and terminal_payload:
    lines.extend([
        f"- Worst-day-of-the-year trigger: {terminal_scenario}\n",
        f"- Classification: {terminal_classification}\n",
        f"- Detection pressure: {len(terminal_payload.get('signals', []))} primary signals\n",
        f"- Response load: {len(terminal_payload.get('actions', []))} coordinated actions\n",
        "- Operating mode: war-room coordination, continuity activation, forensic preservation, and full-scope compromise assessment\n",
        "\n---\n\n",
    ])

lines.extend([
    "## Critical Scenario Priority\n\n",
    "| Scenario | Risk | Signals | Actions |\n",
    "|---|---|---:|---:|\n",
])

for risk, signal_count, scenario, payload in critical_rows[:8]:
    lines.append(f"| {scenario} | {risk} | {signal_count} | {len(payload.get('actions', []))} |\n")

lines.extend([
    "\n---\n\n",
    "## Chain Timeline\n\n",
    timeline,
    "\n\n---\n\n",
    "## Incident Graph Backbone\n\n",
    f"- Graph nodes: {graph.get('summary', {}).get('node_count', 0)}\n",
    f"- Graph edges: {graph.get('summary', {}).get('edge_count', 0)}\n",
    f"- Terminal graph path: {graph.get('summary', {}).get('terminal_scenario', 'n/a')}\n",
    f"- Ontology node types: {len(graph.get('ontology', {}).get('node_types', []))}\n",
    f"- Ontology relationship types: {len(graph.get('ontology', {}).get('relationship_types', []))}\n",
    "- Use shared entities like users, OAuth apps, service principals, identity providers, nodes, workloads, and TPMs as correlation pivots.\n",
    "\n\n---\n\n",
    "## Campaign Modes and Package 8\n\n",
    "- One scenario at a time: focused drill execution by scenario and control objective\n",
    "- Multi-scenario chains: run correlated escalation paths (e.g., 3 -> 5 -> 9 -> 14)\n",
    "- Full-spectrum campaign: Scenario 1 -> 20 in sequence (simulated, synthetic, safe)\n",
    f"- Package 8 deliverables: {len(red_team.get('red_team_deliverable_package', {}).get('deliverables', []))} documented artifacts\n",
    f"- Launcher profiles: {len(launcher.get('profiles', []))} machine-runnable entries\n",
    "\n\n---\n\n",
    "## Latency Highlights\n\n",
])

for scenario, minutes in sorted(kpis.get("estimated_containment_latency_minutes", {}).items(), key=lambda item: item[1], reverse=True):
    lines.append(f"- {scenario}: containment latency {minutes} min\n")

lines.extend([
    "\n---\n\n",
    "## Recommended Board-Level Actions\n\n",
    f"- Treat {terminal_classification.lower()} as the terminal planning case: pre-authorize cross-domain containment, executive escalation, and emergency credential rotation before detonation\n",
    "- Freeze high-risk CI/CD and AI-assisted release paths on integrity drift\n",
    "- Prioritize controls that reduce containment time in cloud and cluster scenarios\n",
    "- Treat federation trust and machine identities as first-class breach surfaces\n",
])

with open(OUT_FILE, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"Wrote {OUT_FILE}")
