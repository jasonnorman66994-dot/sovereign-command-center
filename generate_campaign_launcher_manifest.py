from datetime import datetime
import json
import re

ANALYTICS_FILE = "cross_scenario_analytics.json"
PACKAGE_FILE = "red_team_deliverable_package.json"
OUT_JSON = "campaign_launcher_manifest.json"
OUT_MD = "campaign_launcher_manifest.md"


def load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def scenario_num(scenario_id):
    match = re.search(r"SCENARIO_?(\d+)", scenario_id or "")
    return int(match.group(1)) if match else None


def build_manifest():
    analytics = load_json(ANALYTICS_FILE)
    package = load_json(PACKAGE_FILE)

    scenario_ids = sorted(analytics.keys(), key=lambda name: (scenario_num(name) or 999, name))
    chain_block = package.get("campaign_modes", {}).get("multi_scenario_chains", {})
    full_block = package.get("campaign_modes", {}).get("full_spectrum_campaign", {})

    full_sequence = full_block.get("sequence", [])
    normalized_full = [entry.get("scenario_id") for entry in full_sequence if entry.get("scenario_id")]

    profiles = []

    for scenario_id in scenario_ids:
        profiles.append({
            "id": f"single-{scenario_id.lower()}",
            "mode": "single_scenario",
            "name": f"Single Scenario: {scenario_id}",
            "safe": True,
            "synthetic": True,
            "sequence": [scenario_id],
            "launch": {
                "runner": "python",
                "entrypoint": "shadow_toolkit.cli",
                "arguments": ["campaign", "--mode", "single", "--scenario", scenario_id],
            },
        })

    for index, chain in enumerate(chain_block.get("recommended_chains", []), start=1):
        profiles.append({
            "id": f"chain-{index:02d}",
            "mode": "multi_scenario_chain",
            "name": f"Chain Campaign {index:02d}",
            "safe": True,
            "synthetic": True,
            "sequence": chain,
            "launch": {
                "runner": "python",
                "entrypoint": "shadow_toolkit.cli",
                "arguments": ["campaign", "--mode", "chain", "--chain-id", f"chain-{index:02d}"],
            },
        })

    profiles.append({
        "id": "full-spectrum-01",
        "mode": "full_spectrum_campaign",
        "name": "Full Spectrum Campaign (Scenario 1 -> 20)",
        "safe": True,
        "synthetic": True,
        "sequence": normalized_full,
        "launch": {
            "runner": "python",
            "entrypoint": "shadow_toolkit.cli",
            "arguments": ["campaign", "--mode", "full-spectrum", "--start", "1", "--end", "20", "--safety", "simulated-synthetic-safe"],
        },
    })

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "schema_version": "1.0.0",
        "description": "Machine-runnable launcher manifest for single-scenario drills, chained campaigns, and full-spectrum synthetic exercises.",
        "global_constraints": {
            "safe_mode": True,
            "synthetic_only": True,
            "destructive_actions_forbidden": True,
            "authorized_scope_required": True,
        },
        "profiles": profiles,
    }


def write_markdown(manifest):
    lines = [
        f"# Campaign Launcher Manifest — {datetime.now().strftime('%Y-%m-%d')}\n\n",
        "Machine-runnable launcher profiles for Mission Control campaigns.\n\n",
        "## Constraints\n\n",
    ]

    for key, value in manifest.get("global_constraints", {}).items():
        lines.append(f"- {key}: {value}\n")

    lines.extend([
        "\n## Profiles\n\n",
        "| ID | Mode | Safe | Synthetic | Sequence Length |\n",
        "|---|---|---|---|---:|\n",
    ])

    for profile in manifest.get("profiles", []):
        lines.append(
            f"| {profile['id']} | {profile['mode']} | {profile['safe']} | {profile['synthetic']} | {len(profile.get('sequence', []))} |\n"
        )

    lines.extend([
        "\n## Example Launch Intents\n\n",
        "- Single scenario: `python -m shadow_toolkit.cli campaign --mode single --scenario SCENARIO_3_UNAUTHORIZED_ACCESS`\n",
        "- Chain campaign: `python -m shadow_toolkit.cli campaign --mode chain --chain-id chain-01`\n",
        "- Full spectrum: `python -m shadow_toolkit.cli campaign --mode full-spectrum --start 1 --end 20 --safety simulated-synthetic-safe`\n",
        "\n",
    ])

    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.writelines(lines)


def main():
    manifest = build_manifest()
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    write_markdown(manifest)
    print(f"Wrote {OUT_JSON} and {OUT_MD}")


if __name__ == "__main__":
    main()