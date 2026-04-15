import json
from datetime import datetime
import re

ANALYTICS_FILE = "cross_scenario_analytics.json"
TIMELINE_FILE = "multi_scenario_chain_timeline.md"
JSON_OUT = "chain_kpis.json"
MD_OUT = "chain_kpis.md"
RESPONSE_CSV_OUT = "chain_response_latency.csv"
CONTAINMENT_CSV_OUT = "chain_containment_latency.csv"

with open(ANALYTICS_FILE, "r", encoding="utf-8") as f:
    analytics = json.load(f)

scenario_count = len(analytics)
critical_count = 0
signal_total = 0
action_total = 0
max_signal = ("", 0)

for scenario, payload in analytics.items():
    signals = payload.get("signals", [])
    actions = payload.get("actions", [])
    risk_levels = payload.get("risk_levels", [])
    if "Critical" in risk_levels:
        critical_count += 1
    signal_total += len(signals)
    action_total += len(actions)
    if len(signals) > max_signal[1]:
        max_signal = (scenario, len(signals))

kpis = {
    "generated_on": datetime.now().strftime("%Y-%m-%d"),
    "scenario_count": scenario_count,
    "critical_scenarios": critical_count,
    "average_signals_per_scenario": round(signal_total / scenario_count, 2) if scenario_count else 0,
    "average_actions_per_scenario": round(action_total / scenario_count, 2) if scenario_count else 0,
    "highest_signal_density": {"scenario": max_signal[0], "signals": max_signal[1]},
}


def parse_time_to_minutes(value):
    hour, minute = value.split(":")
    return int(hour) * 60 + int(minute)


def canonical_scenario_key(scenario_num, analytics_payload):
    known = list(analytics_payload.keys())
    candidates = [
        key for key in known
        if key.startswith(f"SCENARIO_{scenario_num}_") or key.startswith(f"SCENARIO{scenario_num}_") or key == f"SCENARIO_{scenario_num}"
    ]
    return sorted(candidates)[0] if candidates else f"SCENARIO_{scenario_num}"


def estimate_timeline_metrics(path, analytics_payload):
    timeline_re = re.compile(r"^\|\s*(\d{2}:\d{2})\s*\|\s*(\d+)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|")
    buckets = {}

    def heuristic_response_minutes(response_text):
        text = response_text.lower()
        if any(term in text for term in ["alert triggered", "token blacklisted", "grant deleted"]):
            return 2
        if any(term in text for term in ["disabled", "account locked", "rollback initiated", "pipeline halted"]):
            return 5
        if any(term in text for term in ["node cordoned", "policy enforced", "secrets rotated", "step frozen"]):
            return 8
        return 3

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                match = timeline_re.match(line.strip())
                if not match:
                    continue
                time_text, scenario_num, _event, _identity, _detection, response = match.groups()
                scenario_key = canonical_scenario_key(scenario_num, analytics_payload)
                entry = buckets.setdefault(scenario_key, {"times": [], "response_latencies": []})
                entry["times"].append(parse_time_to_minutes(time_text))
                entry["response_latencies"].append(heuristic_response_minutes(response))
    except FileNotFoundError:
        return {}, {}, {}

    dwell_times = {}
    response_latencies = {}
    containment_latencies = {}
    for scenario_key, values in buckets.items():
        times = values["times"]
        dwell = max(times) - min(times) if times else 0
        response_latency = round(sum(values["response_latencies"]) / len(values["response_latencies"]), 2)
        dwell_times[scenario_key] = dwell
        response_latencies[scenario_key] = response_latency
        containment_latencies[scenario_key] = round(dwell + response_latency, 2)

    return dwell_times, response_latencies, containment_latencies


dwell_times, response_latencies, containment_latencies = estimate_timeline_metrics(TIMELINE_FILE, analytics)
if dwell_times:
    kpis["dwell_time_minutes"] = dwell_times
    kpis["average_dwell_time_minutes"] = round(sum(dwell_times.values()) / len(dwell_times), 2)
if response_latencies:
    kpis["estimated_response_latency_minutes"] = response_latencies
    kpis["average_estimated_response_latency_minutes"] = round(
        sum(response_latencies.values()) / len(response_latencies), 2
    )
if containment_latencies:
    kpis["estimated_containment_latency_minutes"] = containment_latencies
    kpis["average_estimated_containment_latency_minutes"] = round(
        sum(containment_latencies.values()) / len(containment_latencies), 2
    )

if response_latencies:
    with open(RESPONSE_CSV_OUT, "w", encoding="utf-8") as f:
        f.write("scenario,response_latency_minutes\n")
        for scenario_id in sorted(response_latencies.keys()):
            f.write(f"{scenario_id},{response_latencies[scenario_id]}\n")

if containment_latencies:
    with open(CONTAINMENT_CSV_OUT, "w", encoding="utf-8") as f:
        f.write("scenario,containment_latency_minutes\n")
        for scenario_id in sorted(containment_latencies.keys()):
            f.write(f"{scenario_id},{containment_latencies[scenario_id]}\n")

with open(JSON_OUT, "w", encoding="utf-8") as f:
    json.dump(kpis, f, indent=2)

lines = [f"# Chain KPI Report — {kpis['generated_on']}\n\n"]
lines.append(f"- Scenario coverage: {kpis['scenario_count']}\n")
lines.append(f"- Critical scenarios: {kpis['critical_scenarios']}\n")
lines.append(f"- Avg signals/scenario: {kpis['average_signals_per_scenario']}\n")
lines.append(f"- Avg actions/scenario: {kpis['average_actions_per_scenario']}\n")
lines.append(
    f"- Highest signal density: {kpis['highest_signal_density']['scenario']} ({kpis['highest_signal_density']['signals']} signals)\n"
)
if kpis.get("average_dwell_time_minutes") is not None:
    lines.append(f"- Avg dwell time (timeline-derived): {kpis['average_dwell_time_minutes']} minutes\n")
if kpis.get("average_estimated_response_latency_minutes") is not None:
    lines.append(f"- Avg estimated response latency: {kpis['average_estimated_response_latency_minutes']} minutes\n")
if kpis.get("average_estimated_containment_latency_minutes") is not None:
    lines.append(f"- Avg estimated containment latency: {kpis['average_estimated_containment_latency_minutes']} minutes\n")
if kpis.get("estimated_response_latency_minutes"):
    lines.append("\n## Estimated Response Latency by Scenario (Minutes)\n")
    for scenario_id in sorted(kpis["estimated_response_latency_minutes"].keys()):
        lines.append(f"- {scenario_id}: {kpis['estimated_response_latency_minutes'][scenario_id]}\n")
if kpis.get("dwell_time_minutes"):
    lines.append("\n## Dwell Time by Scenario (Minutes)\n")
    for scenario_id in sorted(kpis["dwell_time_minutes"].keys()):
        lines.append(f"- {scenario_id}: {kpis['dwell_time_minutes'][scenario_id]}\n")
if kpis.get("estimated_containment_latency_minutes"):
    lines.append("\n## Estimated Containment Latency by Scenario (Minutes)\n")
    for scenario_id in sorted(kpis["estimated_containment_latency_minutes"].keys()):
        lines.append(f"- {scenario_id}: {kpis['estimated_containment_latency_minutes'][scenario_id]}\n")

with open(MD_OUT, "w", encoding="utf-8") as f:
    f.writelines(lines)

print(f"Wrote {JSON_OUT}, {MD_OUT}, {RESPONSE_CSV_OUT}, and {CONTAINMENT_CSV_OUT}")
