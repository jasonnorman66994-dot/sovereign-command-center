from datetime import datetime
import json
import re

ANALYTICS_FILE = "cross_scenario_analytics.json"
GRAPH_FILE = "incident_attack_graph.json"
KPI_FILE = "chain_kpis.json"
OUT_JSON = "red_team_deliverable_package.json"
OUT_MD = "red_team_deliverable_package.md"


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def scenario_num(scenario_id):
    match = re.search(r"SCENARIO_?(\d+)", scenario_id or "")
    return int(match.group(1)) if match else None


def build_package():
    analytics = load_json(ANALYTICS_FILE)
    graph = load_json(GRAPH_FILE)
    kpis = load_json(KPI_FILE)

    available_ids = sorted(analytics.keys(), key=lambda name: (scenario_num(name) or 999, name))
    available_numbers = {scenario_num(sid) for sid in available_ids if scenario_num(sid) is not None}

    full_spectrum_sequence = []
    for number in range(1, 21):
        scenario_id = next((sid for sid in available_ids if scenario_num(sid) == number), f"SCENARIO_{number}_SYNTHETIC_PLACEHOLDER")
        full_spectrum_sequence.append({
            "order": number,
            "scenario_id": scenario_id,
            "status": "available" if number in available_numbers else "synthetic_placeholder",
            "safety_mode": "simulated_synthetic_safe",
        })

    package = {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "campaign_modes": {
            "single_scenario": {
                "description": "Run one scenario at a time for focused detection and response drills.",
                "mode": "one-scenario-at-a-time",
                "supported_scenarios": available_ids,
            },
            "multi_scenario_chains": {
                "description": "Run pre-defined chained campaigns for correlation and escalation analysis.",
                "example_chain": [
                    "SCENARIO_3_UNAUTHORIZED_ACCESS",
                    "SCENARIO_5_OAUTH_ABUSE",
                    "SCENARIO_9_LATERAL_MOVEMENT_OAUTH",
                    "SCENARIO_14_HYBRID_CLOUD_RANSOMWARE",
                ],
                "recommended_chains": [
                    [
                        "SCENARIO_3_UNAUTHORIZED_ACCESS",
                        "SCENARIO_5_OAUTH_ABUSE",
                        "SCENARIO_9_LATERAL_MOVEMENT_OAUTH",
                        "SCENARIO_14_HYBRID_CLOUD_RANSOMWARE",
                    ],
                    [
                        "SCENARIO_5_OAUTH_ABUSE",
                        "SCENARIO_10_SERVICE_PRINCIPAL_HIJACK",
                        "SCENARIO_12_SUPPLY_CHAIN_POISONING",
                        "SCENARIO_16_OIDC_SIGNING_KEY_THEFT",
                    ],
                    [
                        "SCENARIO_11_K8S_SIDECAR_BREAKOUT",
                        "SCENARIO_13_ZERO_DAY_EXPLOIT",
                        "SCENARIO_17_HARDWARE_ROOT_OF_TRUST_COMPROMISE",
                    ],
                ],
            },
            "full_spectrum_campaign": {
                "description": "Run Scenario 1 through Scenario 20 in sequence as a simulated, synthetic, safe campaign.",
                "sequence": full_spectrum_sequence,
                "safety_assertions": [
                    "No live malware deployment",
                    "No unauthorized external network targeting",
                    "No destructive commands against production systems",
                    "Synthetic payloads and controlled telemetry only",
                ],
            },
        },
        "red_team_deliverable_package": {
            "package_number": 8,
            "name": "Red Team Deliverable Package",
            "deliverables": [
                "Campaign scope and objectives",
                "Scenario inject matrix",
                "Unified incident attack graph",
                "Detection and response checkpoints",
                "Executive communication brief",
                "Blue-team scoring workbook",
                "After-action review template",
                "Safety, legal, and control constraints",
            ],
            "references": {
                "analytics_file": ANALYTICS_FILE,
                "kpi_file": KPI_FILE,
                "graph_file": GRAPH_FILE,
                "graph_summary": graph.get("summary", {}),
            },
        },
    }
    return package


def write_markdown(package):
    modes = package["campaign_modes"]
    lines = [
        f"# Red Team Deliverable Package — {datetime.now().strftime('%Y-%m-%d')}\n\n",
        "This package defines campaign operating modes and formal red-team deliverables for Mission Control exercises.\n\n",
        "## Campaign Modes\n\n",
        "### One Scenario at a Time\n\n",
        f"- Mode: `{modes['single_scenario']['mode']}`\n",
        f"- Description: {modes['single_scenario']['description']}\n",
        f"- Currently available scenarios: {len(modes['single_scenario']['supported_scenarios'])}\n\n",
        "### Multi-Scenario Chains\n\n",
        f"- Description: {modes['multi_scenario_chains']['description']}\n",
        "- Numeric shorthand example: 3 -> 5 -> 9 -> 14\n",
        "- Example chain: SCENARIO_3_UNAUTHORIZED_ACCESS -> SCENARIO_5_OAUTH_ABUSE -> SCENARIO_9_LATERAL_MOVEMENT_OAUTH -> SCENARIO_14_HYBRID_CLOUD_RANSOMWARE\n",
        "- Recommended chains:\n",
    ]

    for chain in modes["multi_scenario_chains"]["recommended_chains"]:
        lines.append(f"  - {' -> '.join(chain)}\n")

    lines.extend([
        "\n### Full-Spectrum Campaign\n\n",
        f"- Description: {modes['full_spectrum_campaign']['description']}\n",
        "- Numeric shorthand sequence: Scenario 1 -> 20 (simulated, synthetic, safe)\n",
        "- Sequence policy: Scenario 1 -> Scenario 20 (simulated, synthetic, safe)\n",
        "- Current sequence status:\n",
    ])

    for step in modes["full_spectrum_campaign"]["sequence"]:
        lines.append(
            f"  - {step['order']:02d}. {step['scenario_id']} [{step['status']}]\n"
        )

    lines.extend([
        "\n## 8) Red Team Deliverable Package\n\n",
        f"- Package name: {package['red_team_deliverable_package']['name']}\n",
        "- Deliverables:\n",
    ])

    for item in package["red_team_deliverable_package"]["deliverables"]:
        lines.append(f"  - {item}\n")

    lines.extend([
        "\n## Safety Controls\n\n",
    ])

    for assertion in modes["full_spectrum_campaign"]["safety_assertions"]:
        lines.append(f"- {assertion}\n")

    lines.append("\n")

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.writelines(lines)


def main():
    package = build_package()
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(package, f, indent=2)
    write_markdown(package)
    print(f"Wrote {OUT_JSON} and {OUT_MD}")


if __name__ == "__main__":
    main()