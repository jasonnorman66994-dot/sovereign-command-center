import subprocess

COMMANDS = [
    ["python", "cross_scenario_analytics.py"],
    ["python", "executive_summary_generator.py"],
    ["python", "drilldown_report_generator.py"],
    ["python", "chain_metrics_report.py"],
    ["python", "generate_incident_attack_graph.py"],
    ["python", "generate_red_team_deliverable_package.py"],
    ["python", "generate_campaign_launcher_manifest.py"],
    ["python", "mission_control_report_generator.py"],
    ["python", "export_mission_report_html.py"],
    ["python", "mission_control_presentation_generator.py"],
    ["python", "export_presentation_html.py"],
]

for cmd in COMMANDS:
    print("Running:", " ".join(cmd))
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0:
        raise SystemExit(f"Command failed: {' '.join(cmd)}")

print("Reporting pipeline complete.")
