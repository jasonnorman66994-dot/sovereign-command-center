# Scenario Analysis & Reporting Tools Guide

Quick reference for cross-scenario attack pattern assessment, ATT&CK coverage analysis, and leadership reporting.

## Tools Overview

| Tool | Purpose | Input | Output | Usage |
|---|---|---|---|---|
| **Attack Chain Timeline** | Map events to ATT&CK phases | JSON event array | Markdown table or JSON | `attack_chain_timeline.py <events.json>` |
| **MITRE Heatmap Generator** | Compute technique frequency heatmap | Scenario-technique JSON | Markdown report | `generate_unified_mitre_heatmap.py` |
| **Leadership Report** | Executive summary with timeline | Manual compilation | Markdown artifact | Static file at `leadership_attack_coverage_timeline_report.md` |

---

## Quick Start

### 1. Generate Attack Chain Timeline

Create a scenario event file (`scenario_events.json`):

```json
[
  {
    "event": "email_spam_burst",
    "count": 150,
    "source": "attacker@example.com",
    "timestamp": "2026-04-15T12:01:00Z"
  },
  {
    "event": "privilege_escalation_attempt",
    "account": "shadow-admin",
    "timestamp": "2026-04-15T12:05:00Z"
  },
  {
    "event": "data_exfiltration",
    "destination_ip": "198.51.100.42",
    "bytes_transferred": 50331648,
    "timestamp": "2026-04-15T12:10:00Z"
  }
]
```

Run the timeline generator:

```bash
python attack_chain_timeline.py scenario_events.json
```

Output (table with ATT&CK phase classification):

```
| Timestamp | Phase | Event | Details |
|-----------|-------|-------|---------|
| 2026-04-15T12:01:00Z | Initial Access | email_spam_burst | {...} |
| 2026-04-15T12:05:00Z | Privilege Escalation | privilege_escalation_attempt | {...} |
| 2026-04-15T12:10:00Z | Exfiltration | data_exfiltration | {...} |
```

For JSON output:

```bash
python attack_chain_timeline.py scenario_events.json --format json
```

### 2. Generate Unified MITRE ATT&CK Heatmap

Update the scenario-technique mapping in `data/unified_mitre_heatmap.json`:

```json
[
  {
    "tactic": "Initial Access",
    "technique": "Phishing / Spam Burst",
    "technique_id": "T1566",
    "scenarios": [10, 11, 13]
  },
  {
    "tactic": "Exfiltration",
    "technique": "Exfiltration Over Web Services",
    "technique_id": "T1567",
    "scenarios": [10, 13, 15]
  }
]
```

Generate the heatmap report:

```bash
python generate_unified_mitre_heatmap.py
```

Output: `unified_mitre_attack_heatmap.md` with:
- Heat-level summary (High/Medium/Low/None)
- Technique frequency table
- Most recurrent behavior clusters
- Interpretation for detection priorities

Specify custom input/output:

```bash
python generate_unified_mitre_heatmap.py \
  --input data/unified_mitre_heatmap.json \
  --output my_heatmap_report.md
```

### 3. Review Leadership Report

Static consolidated report at [leadership_attack_coverage_timeline_report.md](../../leadership_attack_coverage_timeline_report.md):

- Scenario 10–16 timeline narrative
- ATT&CK coverage heatmap
- Detection engineering priorities
- Cross-scenario interpretation

---

## Supported Event Types

The attack chain timeline classifier recognizes these event types and maps them to ATT&CK phases:

| Event Type | Phase | Tactics |
|---|---|---|
| `email_spam_burst`, `exploit_payload_delivered`, `serialized_payload_delivered` | Initial Access | T1566, T1195, T1078 |
| `unexpected_process_spawn`, `command_injection`, `script_execution` | Execution | T1204, T1059 |
| `privilege_escalation_attempt`, `capability_abuse`, `container_capability_request` | Privilege Escalation | T1548, T1068 |
| `lateral_movement`, `ssh_attempt`, `internal_ssh_to_db` | Lateral Movement | T1021, T1134 |
| `data_exfiltration`, `large_outbound_transfer` | Exfiltration | T1567, T1537 |
| `cron_job_created`, `mailbox_rule_change`, `scheduled_task_created` | Persistence | T1114, T1098 |
| `log_cleared`, `signature_mismatch`, `obfuscated_payload` | Defense Evasion | T1070, T1027 |
| `ueba_anomaly_score`, `runtime_anomaly` | UEBA Correlation | Analytics |

See [attack_chain_timeline.py](../../attack_chain_timeline.py) for the full classification mapping.

---

## Workflow Integration

### Manual CI Trigger

GitHub Actions provides a manual workflow dispatch for the analysis tools:

1. Go to **Actions** → **Scenario Analysis & Reporting**
2. Click **Run workflow**
3. Select desired branch (default: `main`)
4. Wait for validation to complete
5. Download artifacts (heatmap, reports)

### Automatic Triggers

The analysis workflow runs automatically when:

- `data/unified_mitre_heatmap.json` is modified (dataset update)
- `generate_unified_mitre_heatmap.py` is modified (tool update)
- `attack_chain_timeline.py` is modified (tool update)
- Any `scenario*_events.json` file is modified (new test data)

---

## Output Formats

### Timeline: Table Format (default)

```
+-----------+-------------------+---------+------------------+
| Timestamp | Phase             | Event   | Details          |
+-----------+-------------------+---------+------------------+
| 20:12:01Z | Initial Access    | exploit | {...}            |
| 20:13:00Z | Privilege Esc.    | sudo    | {...}            |
+-----------+-------------------+---------+------------------+
```

With `--no-colour` for plaintext (CI-friendly):

```bash
python attack_chain_timeline.py events.json --no-colour
```

### Timeline: JSON Format

```bash
python attack_chain_timeline.py events.json --format json
```

Output:

```json
[
  {
    "timestamp": "2026-04-15T20:12:01Z",
    "phase": "Initial Access",
    "event": "exploit_payload_delivered",
    "details": { ... }
  }
]
```

### Heatmap: Markdown Report

Auto-generated table with heat levels:

```markdown
| MITRE Tactic | Technique | ID | Frequency | Heat |
|---|---|---|---|---|
| Initial Access | Phishing / Spam Burst | T1566 | Scenario 10, 11, 13 | [MED] Medium |
| Exfiltration | Exfiltration Over Web Services | T1567 | Scenario 10, 13, 15 | [MED] Medium |
```

Plus summary and interpretation sections.

---

## Contributing

### Adding a New Scenario Event File

1. Create `scenario{N}_events.json` with synthetic test events
2. Run the timeline generator to verify classification
3. Commit with message: `Add Scenario {N} events for timeline analysis`

### Updating the ATT&CK Heatmap

1. Edit `data/unified_mitre_heatmap.json` to add/modify scenario mappings
2. Run `python generate_unified_mitre_heatmap.py` to regenerate the report
3. Review `unified_mitre_attack_heatmap.md` for accuracy
4. Commit: `Update MITRE heatmap dataset for Scenario {N}`

### Updating the Leadership Report

1. Edit `leadership_attack_coverage_timeline_report.md` directly (manual artifact)
2. Include new scenario timelines, heat analysis, and interpretation sections
3. Run lint: `npx markdownlint-cli2 leadership_attack_coverage_timeline_report.md`
4. Commit: `Update leadership report with Scenario {N} coverage`

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for full workflow.

---

## Troubleshooting

**Q: Timeline shows "Unknown" phase for my event**

A: Add the event type to the `_PHASE_MAP` in `attack_chain_timeline.py`. Contribute the mapping upstream.

**Q: Heatmap has no Medium or High techniques**

A: Check the scenario count thresholds:
- High: 5+ scenarios
- Medium: 3–4 scenarios
- Low: 1–2 scenarios

Add more scenarios to the dataset or adjust technique-to-scenario mappings in `data/unified_mitre_heatmap.json`.

**Q: CI workflow fails but script runs locally**

A: Verify `requirements.txt` includes all dependencies. CI runs in a clean Ubuntu environment.

---

## Related Documentation

- [README: Scenario Analysis & Reporting Tools](../../README.md#-scenario-analysis--reporting-tools)
- [CONTRIBUTING: Scenario Analysis & Reporting](../../CONTRIBUTING.md#scenario-analysis--reporting)
- [Leadership Report](../../leadership_attack_coverage_timeline_report.md)
- [Unified MITRE Heatmap](../../unified_mitre_attack_heatmap.md)
