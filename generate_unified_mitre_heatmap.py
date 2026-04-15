import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_entries(path: Path) -> list[dict]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise ValueError("Top-level JSON must be an array of heatmap entries.")
    return data


def classify_heat(count: int) -> tuple[str, str]:
    if count >= 5:
        return "High", "HIGH"
    if count >= 3:
        return "Medium", "MED"
    if count >= 1:
        return "Low", "LOW"
    return "None", "NONE"


def scenario_label(scenarios: list[int]) -> str:
    if not scenarios:
        return "Not observed"
    return ", ".join(f"Scenario {n}" for n in sorted(scenarios))


def build_rows(entries: list[dict]) -> list[dict]:
    rows = []
    for item in entries:
        scenarios = item.get("scenarios", [])
        count = len(set(scenarios))
        heat, icon = classify_heat(count)
        rows.append(
            {
                "tactic": item.get("tactic", "Unknown"),
                "technique": item.get("technique", "Unknown"),
                "technique_id": item.get("technique_id", "-"),
                "frequency": scenario_label(scenarios),
                "count": count,
                "heat": heat,
                "icon": icon,
            }
        )
    rows.sort(key=lambda r: (r["tactic"], -r["count"], r["technique_id"]))
    return rows


def build_summary(rows: list[dict]) -> dict:
    by_heat = defaultdict(list)
    for row in rows:
        by_heat[row["heat"]].append(row)

    # Most recurrent techniques are the maximum-frequency techniques,
    # regardless of whether they cross the 5+ "High" threshold.
    max_count = max((row["count"] for row in rows), default=0)
    most_recurrent = [
        row for row in rows if row["count"] == max_count and row["count"] > 0
    ]

    return {
        "high_count": len(by_heat["High"]),
        "medium_count": len(by_heat["Medium"]),
        "low_count": len(by_heat["Low"]),
        "none_count": len(by_heat["None"]),
        "most_recurrent": most_recurrent,
        "max_count": max_count,
    }


def render_markdown(rows: list[dict], summary: dict) -> str:
    lines = []
    lines.append("# Unified MITRE ATT&CK Heatmap (Across All Scenarios)")
    lines.append("")
    lines.append("## Legend")
    lines.append("")
    lines.append("- High ([HIGH]) - Appears in 5+ scenarios")
    lines.append("- Medium ([MED]) - Appears in 3-4 scenarios")
    lines.append("- Low ([LOW]) - Appears in 1-2 scenarios")
    lines.append("- None ([NONE]) - Not observed")
    lines.append("")
    lines.append("## ATT&CK Heatmap")
    lines.append("")
    lines.append("| MITRE Tactic | Technique | ID | Frequency | Heat |")
    lines.append("|---|---|---|---|---|")
    for row in rows:
        lines.append(
            f"| {row['tactic']} | {row['technique']} | {row['technique_id']} | "
            f"{row['frequency']} | [{row['icon']}] {row['heat']} |"
        )

    lines.append("")
    lines.append("## Heatmap Summary")
    lines.append("")
    lines.append(f"- High techniques: {summary['high_count']}")
    lines.append(f"- Medium techniques: {summary['medium_count']}")
    lines.append(f"- Low techniques: {summary['low_count']}")
    lines.append(f"- None techniques: {summary['none_count']}")

    lines.append("")
    lines.append("### Most Recurrent Behavior Cluster")
    lines.append("")
    if summary["most_recurrent"]:
        lines.append(
            f"Top recurrence in this dataset is {summary['max_count']} scenario(s) "
            "per technique (below the 5+ High threshold)."
        )
        lines.append("")
        for row in summary["most_recurrent"]:
            lines.append(
                f"- {row['technique']} ({row['technique_id']}) in {row['frequency']} "
                f"[[{row['icon']}] {row['heat']}]"
            )
    else:
        lines.append("No observed techniques in the current dataset.")

    lines.append("")
    lines.append("## Interpretation")
    lines.append("")
    lines.append("1. The recurring pattern centers on initial access, escalation, evasion, and exfiltration.")
    lines.append("2. Under-represented areas include cloud discovery, lateral movement depth, and broader impact patterns.")
    lines.append("3. Detection priorities should focus on privilege escalation, mailbox rule changes, exfiltration, and anti-evasion controls.")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate unified MITRE ATT&CK heatmap markdown from JSON input.")
    parser.add_argument(
        "--input",
        default="data/unified_mitre_heatmap.json",
        help="Path to heatmap JSON data file",
    )
    parser.add_argument(
        "--output",
        default="unified_mitre_attack_heatmap.md",
        help="Output markdown path",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    entries = load_entries(input_path)
    rows = build_rows(entries)
    summary = build_summary(rows)
    report = render_markdown(rows, summary)

    output_path.write_text(report + "\n", encoding="utf-8")
    print(f"Wrote unified heatmap report to {output_path}")


if __name__ == "__main__":
    main()
