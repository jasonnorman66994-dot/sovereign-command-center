"""
attack_chain_timeline.py
Consume a synthetic event JSON file and render an attack-chain timeline
mapped to MITRE ATT&CK-style phases.

Usage:
    python attack_chain_timeline.py scenario13_events.json
    python attack_chain_timeline.py scenario13_events.json --format table
    python attack_chain_timeline.py scenario13_events.json --format json
"""

import argparse
import json
import sys


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------

_PHASE_MAP = {
    # Reconnaissance
    "port_scan": "Reconnaissance",
    "service_probe": "Reconnaissance",
    # Initial Access
    "email_spam_burst": "Initial Access",
    "exploit_payload_delivered": "Initial Access",
    "serialized_payload_delivered": "Initial Access",
    "phishing_link_clicked": "Initial Access",
    # Execution
    "unexpected_process_spawn": "Execution",
    "command_injection": "Execution",
    "script_execution": "Execution",
    # Persistence
    "mailbox_rule_change": "Persistence",
    "cron_job_created": "Persistence",
    "scheduled_task_created": "Persistence",
    "keepalive_script_created": "Persistence",
    # Privilege Escalation
    "privilege_escalation_attempt": "Privilege Escalation",
    "capability_abuse": "Privilege Escalation",
    "container_capability_request": "Privilege Escalation",
    # Defense Evasion
    "log_cleared": "Defense Evasion",
    "signature_mismatch": "Defense Evasion",
    "obfuscated_payload": "Defense Evasion",
    # Credential Access
    "credential_dump": "Credential Access",
    "secret_rotation_triggered": "Credential Access",
    # Lateral Movement
    "lateral_movement": "Lateral Movement",
    "ssh_attempt": "Lateral Movement",
    "internal_ssh_to_db": "Lateral Movement",
    # Collection
    "data_staged": "Collection",
    "file_access_anomaly": "Collection",
    # Exfiltration
    "data_exfiltration": "Exfiltration",
    "large_outbound_transfer": "Exfiltration",
    # Impact
    "service_disruption": "Impact",
    "ransomware_trigger": "Impact",
    # UEBA / Analytics
    "ueba_anomaly_score": "UEBA Correlation",
    "runtime_anomaly": "UEBA Correlation",
}


def classify_event(event: dict) -> str:
    """Return the ATT&CK-style phase for a single event dict."""
    key = event.get("event", "").lower()
    return _PHASE_MAP.get(key, "Unknown")


# ---------------------------------------------------------------------------
# Timeline builder
# ---------------------------------------------------------------------------

def build_attack_chain(events: list[dict]) -> list[dict]:
    """Return an ordered list of phase-annotated event rows."""
    rows = []
    for e in events:
        phase = classify_event(e)
        rows.append(
            {
                "timestamp": e.get("timestamp", "—"),
                "phase": phase,
                "event": e.get("event", "—"),
                "details": {k: v for k, v in e.items() if k not in {"event", "timestamp"}},
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_PHASE_COLORS = {
    "Reconnaissance":     "\033[36m",   # cyan
    "Initial Access":     "\033[91m",   # bright red
    "Execution":          "\033[31m",   # red
    "Persistence":        "\033[33m",   # yellow
    "Privilege Escalation": "\033[95m", # magenta
    "Defense Evasion":    "\033[90m",   # dark grey
    "Credential Access":  "\033[35m",   # magenta
    "Lateral Movement":   "\033[93m",   # bright yellow
    "Collection":         "\033[94m",   # blue
    "Exfiltration":       "\033[91m",   # bright red
    "Impact":             "\033[31m",   # red
    "UEBA Correlation":   "\033[96m",   # cyan
    "Unknown":            "\033[0m",    # reset
}
_RESET = "\033[0m"


def _colour(phase: str, text: str) -> str:
    return f"{_PHASE_COLORS.get(phase, '')}{text}{_RESET}"


def render_table(rows: list[dict], use_colour: bool = True) -> str:
    """Render the timeline as a fixed-width table."""
    if not rows:
        return "No events to display."

    ts_w  = max(len(r["timestamp"]) for r in rows)
    ph_w  = max(len(r["phase"])     for r in rows)
    ev_w  = max(len(r["event"])     for r in rows)

    ts_w  = max(ts_w, 24)
    ph_w  = max(ph_w, 22)
    ev_w  = max(ev_w, 30)

    sep = f"+{'-' * (ts_w + 2)}+{'-' * (ph_w + 2)}+{'-' * (ev_w + 2)}+{'-' * 40}+"
    header = (
        f"| {'Timestamp':<{ts_w}} "
        f"| {'Phase':<{ph_w}} "
        f"| {'Event':<{ev_w}} "
        f"| {'Details':<38} |"
    )

    lines = [sep, header, sep]
    for r in rows:
        detail_str = json.dumps(r["details"], separators=(",", ":"))
        if len(detail_str) > 37:
            detail_str = detail_str[:34] + "..."
        phase_text = _colour(r["phase"], f"{r['phase']:<{ph_w}}") if use_colour else f"{r['phase']:<{ph_w}}"
        lines.append(
            f"| {r['timestamp']:<{ts_w}} "
            f"| {phase_text} "
            f"| {r['event']:<{ev_w}} "
            f"| {detail_str:<38} |"
        )
    lines.append(sep)
    return "\n".join(lines)


def render_json(rows: list[dict]) -> str:
    return json.dumps(rows, indent=2)


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def load_events(path: str) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        print(f"[ERROR] File not found: {path}", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in {path}: {exc}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, list):
        print("[ERROR] Expected a JSON array at the top level.", file=sys.stderr)
        sys.exit(1)

    return data


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Attack chain timeline generator — maps synthetic events to ATT&CK phases."
    )
    parser.add_argument(
        "input_file",
        help="Path to synthetic event JSON (e.g. scenario13_events.json)",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format: table (default) or json",
    )
    parser.add_argument(
        "--no-colour",
        action="store_true",
        help="Disable ANSI colour in table output",
    )
    args = parser.parse_args()

    events   = load_events(args.input_file)
    timeline = build_attack_chain(events)

    if args.format == "json":
        print(render_json(timeline))
    else:
        print(render_table(timeline, use_colour=not args.no_colour))
        print(f"\n  {len(timeline)} event(s) classified across "
              f"{len({r['phase'] for r in timeline})} phase(s).")


if __name__ == "__main__":
    main()
