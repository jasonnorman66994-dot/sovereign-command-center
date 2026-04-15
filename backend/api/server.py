#!/usr/bin/env python3
"""
Sovereign Pulse — Telemetry API Server
=======================================
Flask REST API bridging health-check scripts, the Sentinel baseline
engine, and the threat-intel service.  Endpoints:

  POST /api/telemetry/heartbeat   — ingest health-check / heartbeat results
  GET  /api/sentinel/sparkline    — baseline-vs-actual sparkline data
  GET  /api/sentinel/status       — current baseline status
  GET  /api/threats/events        — recent threat events with badges
  GET  /api/health                — simple liveness probe
"""

import csv
import io
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from functools import wraps
from pathlib import Path

import psutil
import requests
from flask import Flask, request, jsonify, abort, make_response, send_from_directory
from flask_socketio import SocketIO

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path so local imports resolve
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Auth key for /trigger-pulse  — override via env var in production
SECRET_PULSE_KEY = os.environ.get("PULSE_AUTH_KEY", "9ce627a5453249379b10dedbfb53785203226cfa3aee25dfee32026033a575db")

from shadow_toolkit.sentinel_baseline import (
    BehavioralEngine,
    get_sparkline_data,
    is_cache_fresh,
    load_anomalies,
    METRICS,
)
from backend.services.threat_intel import (
    get_recent_events as get_threat_events,
    evaluate_with_zscore,
    lookup as threat_lookup,
)
from sovereign_db import (
    get_targets_with_pulses,
    add_target as db_add_target,
    remove_target as db_remove_target,
    purge_targets as db_purge_targets,
)
from engine_control import halt_pulse_engine, is_pulse_active, resume_pulse_engine

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Path to the frontend directory
FRONTEND_DIR = PROJECT_ROOT / "frontend"

TELEMETRY_LOG = Path(os.environ.get(
    "TELEMETRY_LOG_DIR", os.path.join("C:\\Logs", "sentinel")
)) / "telemetry_heartbeats.json"

PIPELINE_LOG = Path(os.environ.get(
    "TELEMETRY_LOG_DIR", os.path.join("C:\\Logs", "sentinel")
)) / "pipeline_log.json"

# Track scheduler state (updated by sovereign_pulse_scheduler.py)
PIPELINE_STATE = Path(os.environ.get(
    "TELEMETRY_LOG_DIR", os.path.join("C:\\Logs", "sentinel")
)) / "pipeline_state.json"

engine = BehavioralEngine()
cpu_critical_start_time = None
memory_history: list[float] = []
event_logs: list[dict[str, object]] = []
uptime_stats = {
    "start_time": time.time(),
    "total_downtime": 0.0,
    "last_halt_timestamp": None,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _load_heartbeats() -> list:
    if not TELEMETRY_LOG.exists():
        return []
    with open(TELEMETRY_LOG, "r") as f:
        return json.load(f)


def _save_heartbeats(entries: list):
    TELEMETRY_LOG.parent.mkdir(parents=True, exist_ok=True)
    entries = entries[-2000:]  # keep last 2000
    with open(TELEMETRY_LOG, "w") as f:
        json.dump(entries, f, indent=2)


def log_event(event_type: str, data: dict | None = None):
    payload = data or {}
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "type": event_type,
        "cpu": payload.get("cpu", 0),
        "latency": payload.get("latency", 0),
        "uptime": payload.get("uptime", 100.0),
        "status": payload.get("error", payload.get("state", payload.get("status", "NOMINAL"))),
    }
    event_logs.append(entry)
    if len(event_logs) > 1000:
        event_logs.pop(0)


def calculate_uptime_percentage() -> float:
    total_elapsed = time.time() - uptime_stats["start_time"]
    if total_elapsed == 0:
        return 100.0

    current_downtime = float(uptime_stats["total_downtime"])
    if not is_pulse_active() and uptime_stats["last_halt_timestamp"]:
        current_downtime += time.time() - float(uptime_stats["last_halt_timestamp"])

    uptime_ratio = (total_elapsed - current_downtime) / total_elapsed
    return round(max(0.0, uptime_ratio * 100), 2)


def require_auth(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        auth_key = request.headers.get("X-Pulse-Auth")
        if auth_key != SECRET_PULSE_KEY:
            return jsonify({"status": "error", "message": "Forbidden"}), 403
        return func(*args, **kwargs)

    return wrapper


def check_service_health():
    """Probe external/internal gateway health and emit a real-time service status event."""
    service_name = os.environ.get("SERVICE_HEALTH_NAME", "External_Gateway")
    service_url = os.environ.get("SERVICE_HEALTH_URL", "https://api.github.com")
    try:
        response = requests.get(service_url, timeout=5)
        status = "UP" if response.status_code == 200 else "DEGRADED"
    except Exception:
        status = "DOWN"

    payload = {
        "name": service_name,
        "status": status,
        "url": service_url,
        "timestamp": datetime.utcnow().isoformat(),
    }
    socketio.emit("service_status", payload)
    log_event("service_status", payload)


def service_health_worker():
    """Continuously run service probes and stream status via Socket.IO."""
    interval = max(int(os.environ.get("SERVICE_HEALTH_INTERVAL", "10")), 2)
    while True:
        check_service_health()
        time.sleep(interval)


def get_network_latency(host: str = "8.8.8.8") -> int:
    """Return ICMP latency in ms, or 999 on timeout/error."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", host]
    try:
        start = time.time()
        subprocess.check_call(command, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
        return int((time.time() - start) * 1000)
    except Exception:
        return 999


def detect_leak(current_mem: float) -> bool:
    memory_history.append(current_mem)
    if len(memory_history) > 150:
        memory_history.pop(0)
        if current_mem > memory_history[0] + 15:
            return True
    return False


def monitor_vitals():
    """Emit telemetry and sustained-threshold alerts for CPU, memory, network latency, and uptime."""
    global cpu_critical_start_time
    latency_host = os.environ.get("LATENCY_TARGET_HOST", "8.8.8.8")

    while True:
        cpu = float(psutil.cpu_percent())
        latency = get_network_latency(latency_host)
        memory = float(psutil.virtual_memory().percent)

        # CPU Threshold Logic (1 minute sustained)
        if cpu > 90:
            if cpu_critical_start_time is None:
                cpu_critical_start_time = time.time()
            elif time.time() - cpu_critical_start_time > 60:
                if is_pulse_active():
                    halt_pulse_engine()
                    halt_payload = {
                        "state": "HALTED",
                        "error": "EMERGENCY_STOP_CPU_LIMIT",
                        "cpu": cpu,
                        "latency": latency,
                    }
                    socketio.emit("system_status", halt_payload)
                    log_event("system_status", halt_payload)
        else:
            cpu_critical_start_time = None
            if is_pulse_active():
                nominal_payload = {"state": "NOMINAL", "cpu": cpu, "latency": latency}
                socketio.emit("system_status", nominal_payload)
                log_event("system_status", nominal_payload)

        if not is_pulse_active() and uptime_stats["last_halt_timestamp"] is None:
            uptime_stats["last_halt_timestamp"] = time.time()
        elif is_pulse_active() and uptime_stats["last_halt_timestamp"] is not None:
            uptime_stats["total_downtime"] += time.time() - float(uptime_stats["last_halt_timestamp"])
            uptime_stats["last_halt_timestamp"] = None

        uptime_pct = calculate_uptime_percentage()
        telemetry_payload = {
            "cpu": cpu,
            "latency": latency,
            "memory": memory,
            "uptime": uptime_pct,
            "state": "NOMINAL" if is_pulse_active() else "HALTED",
            "engine_active": is_pulse_active(),
        }
        socketio.emit("telemetry_update", telemetry_payload)
        log_event("telemetry_update", telemetry_payload)

        if detect_leak(memory):
            alert_payload = {"type": "MEM_LEAK", "severity": "LOW", "cpu": cpu, "latency": latency, "uptime": uptime_pct, "status": "WARNING"}
            socketio.emit("telemetry_alert", alert_payload)
            log_event("telemetry_alert", alert_payload)

        time.sleep(2)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def index():
    """Serve the live dashboard."""
    return send_from_directory(str(FRONTEND_DIR), "system_health.html")


@app.route("/styles.css", methods=["GET"])
def serve_css():
    """Serve the dashboard stylesheet."""
    return send_from_directory(str(FRONTEND_DIR), "styles.css")


@app.route("/api/health", methods=["GET"])
def health():
    """Liveness / readiness probe."""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.utcnow().isoformat(),
        "cache_fresh": is_cache_fresh(),
    })


@app.route("/api/telemetry/heartbeat", methods=["POST"])
def telemetry_heartbeat():
    """
    Ingest a heartbeat or health-check result from scripts.

    Expected JSON body:
      {
        "source": "healthcheck" | "heartbeat" | "dashboard",
        "host": "<hostname>",
        "pass_count": <int>,
        "warn_count": <int>,
        "fail_count": <int>,
        "details": "<optional text>",
        "checks": [ {"name": "...", "status": "PASS|FAIL|WARN"} ]
      }
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "JSON body required"}), 400

    allowed_sources = {"healthcheck", "heartbeat", "dashboard", "sentinel"}
    source = data.get("source", "unknown")
    if source not in allowed_sources:
        source = "unknown"

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": source,
        "host": data.get("host", "unknown"),
        "pass_count": int(data.get("pass_count", 0)),
        "warn_count": int(data.get("warn_count", 0)),
        "fail_count": int(data.get("fail_count", 0)),
        "details": str(data.get("details", ""))[:500],
        "checks": data.get("checks", []),
    }

    entries = _load_heartbeats()
    entries.append(entry)
    _save_heartbeats(entries)

    return jsonify({"status": "accepted", "entry": entry}), 201


@app.route("/api/sentinel/sparkline", methods=["GET"])
def sentinel_sparkline():
    """Return sparkline data for one or all metrics."""
    metric = request.args.get("metric", "")
    points = min(int(request.args.get("points", 24)), 168)  # cap at 7 days hourly

    if metric and metric in METRICS:
        return jsonify(engine.get_sparkline_data(metric, points))
    else:
        return jsonify(engine.get_all_sparklines(points))


@app.route("/api/sentinel/status", methods=["GET"])
def sentinel_status():
    """Return current baseline status."""
    return jsonify(engine.get_baseline_status())


@app.route("/api/sentinel/collect", methods=["POST"])
def sentinel_collect():
    """Trigger a telemetry collection and return the evaluation."""
    result = engine.collect_and_evaluate()
    return jsonify(result), 201


@app.route("/api/threats/events", methods=["GET"])
def threat_events():
    """Return recent threat events with badges."""
    days = min(int(request.args.get("days", 7)), 90)
    events = get_threat_events(days)
    anomalies = load_anomalies(days)

    combined = []
    for a in anomalies:
        combined.append({
            "timestamp": a.get("timestamp", ""),
            "badge": "ANOMALY",
            "type": "behavioral",
            "detail": f"{a.get('metric', '')}: z={a.get('zscore', 0):+.1f}",
            "severity": a.get("severity", "INFO"),
        })
    for t in events:
        combined.append({
            "timestamp": t.get("timestamp", ""),
            "badge": t.get("badge", "Threat Match"),
            "type": "threat-intel",
            "detail": f"{t.get('indicator', '')} ({t.get('category', '')})",
            "severity": "HIGH" if t.get("confidence", 0) >= 70 else "MEDIUM",
        })

    combined.sort(key=lambda e: e["timestamp"], reverse=True)
    return jsonify(combined[:100])


@app.route("/api/threats/lookup", methods=["POST"])
def threat_lookup_endpoint():
    """Lookup a single indicator."""
    data = request.get_json(silent=True)
    if not data or "indicator" not in data:
        return jsonify({"error": "JSON body with 'indicator' required"}), 400

    indicator = str(data["indicator"]).strip()
    match = threat_lookup(indicator)
    if match:
        from dataclasses import asdict
        return jsonify({"match": True, **asdict(match)})
    return jsonify({"match": False, "indicator": indicator})


@app.route("/api/telemetry/history", methods=["GET"])
def telemetry_history():
    """Return recent heartbeat history entries."""
    limit = min(int(request.args.get("limit", 50)), 200)
    entries = _load_heartbeats()
    return jsonify(entries[-limit:])


# ---------------------------------------------------------------------------
# Pipeline Log – feeds the Live Output panel
# ---------------------------------------------------------------------------
def _load_pipeline_log() -> list:
    if not PIPELINE_LOG.exists():
        return []
    with open(PIPELINE_LOG, "r") as f:
        return json.load(f)


def _load_pipeline_state() -> dict:
    if not PIPELINE_STATE.exists():
        return {}
    with open(PIPELINE_STATE, "r") as f:
        return json.load(f)


@app.route("/api/pipeline/log", methods=["GET"])
def pipeline_log():
    """
    Return pipeline log entries newer than ``after`` timestamp,
    plus current pipeline status.

    Query params:
      after  – ISO timestamp; only entries after this are returned
    """
    after = request.args.get("after", "")
    entries = _load_pipeline_log()
    if after:
        entries = [e for e in entries if e.get("timestamp", "") > after]
    # Cap at 100 entries per poll to avoid huge payloads
    entries = entries[-100:]
    state = _load_pipeline_state()
    return jsonify({"entries": entries, "status": state})


@app.route("/api/pipeline/log", methods=["POST"])
def pipeline_log_append():
    """
    Append a log entry.  Used by sovereign_pulse_scheduler.py and scripts.

    JSON body: { "message": "...", "level": "info|warn|error" }
    """
    data = request.get_json(silent=True)
    if not data or "message" not in data:
        return jsonify({"error": "JSON body with 'message' required"}), 400

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "message": str(data["message"])[:500],
        "level": str(data.get("level", "info")).lower(),
    }
    log = _load_pipeline_log()
    log.append(entry)
    # Keep last 1000 entries
    log = log[-1000:]
    PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(PIPELINE_LOG, "w") as f:
        json.dump(log, f, indent=2)
    return jsonify({"status": "appended", "entry": entry}), 201


@app.route("/api/pipeline/trigger", methods=["POST"])
def pipeline_trigger():
    """
    Trigger a full pipeline run (collect + dashboard + email) in a
    background thread.  Returns immediately with 202 Accepted.
    """
    import threading

    state = _load_pipeline_state()
    if state.get("state") == "Running":
        return jsonify({"error": "Pipeline already running"}), 409

    def _run_pipeline():
        try:
            from sovereign_pulse_scheduler import automated_pipeline_task
            automated_pipeline_task()
        except Exception as exc:
            # Log the error into the pipeline log file
            err_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "message": f"Manual trigger error: {exc}",
                "level": "error",
            }
            log = _load_pipeline_log()
            log.append(err_entry)
            PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
            with open(PIPELINE_LOG, "w") as f:
                json.dump(log[-1000:], f, indent=2)

    # Append a log entry for the manual trigger
    trigger_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "message": "Manual override: FORCE RUN triggered from dashboard",
        "level": "warn",
    }
    log = _load_pipeline_log()
    log.append(trigger_entry)
    PIPELINE_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(PIPELINE_LOG, "w") as f:
        json.dump(log[-1000:], f, indent=2)

    t = threading.Thread(target=_run_pipeline, daemon=True)
    t.start()
    return jsonify({"status": "triggered", "entry": trigger_entry}), 202


@app.route("/api/pipeline/status", methods=["GET"])
def pipeline_status_detail():
    """
    Return detailed pipeline connectivity status:
    SMTP reachability, signature cert, and mail queue depth.
    """
    import socket as _socket

    # SMTP check — just test TCP connectivity to smtp.gmail.com:465
    smtp_ok = False
    try:
        s = _socket.create_connection(("smtp.gmail.com", 465), timeout=5)
        s.close()
        smtp_ok = True
    except Exception:
        pass

    # Signature cert check
    cert_path = os.environ.get("CERT_PATH", "")
    sig_status = "VERIFIED" if cert_path and os.path.isfile(cert_path) else "NO CERT"

    # Queue = pipeline log entries with level "warn" that mention "Pending"
    state = _load_pipeline_state()
    queue = state.get("mail_queue", "Idle")
    pending = 1 if queue == "Pending" else 0

    return jsonify({
        "smtp": "CONNECTED" if smtp_ok else "UNREACHABLE",
        "signature": sig_status,
        "queue_pending": pending,
        "state": state.get("state", "Unknown"),
    })


@app.route("/trigger-pulse", methods=["POST"])
def trigger_pulse():
    """Convenience alias — triggers the full pipeline asynchronously."""
    auth_key = request.headers.get("X-Pulse-Auth")
    if auth_key != SECRET_PULSE_KEY:
        abort(403)
    try:
        from sovereign_pulse_scheduler import dispatch_pulse_async
        dispatch_pulse_async()
        return jsonify({"status": "success", "message": "Pulse dispatched (async)."}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/get-targets', methods=['GET'])
def get_targets():
    targets = get_targets_with_pulses()
    return jsonify(targets)


@app.route('/add-target', methods=['POST'])
def add_target():
    data = request.get_json(silent=True) or {}
    new_email = str(data.get('email', '')).strip()
    if not new_email or "@" not in new_email:
        return jsonify({"status": "error", "message": "Invalid Email"}), 400

    created = db_add_target(new_email)
    if not created:
        return jsonify({"status": "error", "message": "User already exists"}), 400
    socketio.emit("targets_updated", {"action": "add", "email": new_email})
    return jsonify({"status": "success"}), 200


@app.route('/remove-target', methods=['POST'])
def remove_target():
    data = request.get_json(silent=True) or {}
    email = str(data.get('email', '')).strip()
    if not email or "@" not in email:
        return jsonify({"status": "error", "message": "Invalid Email"}), 400

    deleted = db_remove_target(email)
    if not deleted:
        return jsonify({"status": "error", "message": "User not found"}), 404
    socketio.emit("targets_updated", {"action": "remove", "email": email})
    return jsonify({"status": "success"}), 200


@app.route('/purge-targets', methods=['POST'])
@require_auth
def purge_targets():
    try:
        db_purge_targets()
        socketio.emit("targets_updated", {"action": "purge"})
        return jsonify({"status": "success", "message": "Database Purged"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/resume-engine', methods=['POST'])
@require_auth
def resume_engine():
    resume_pulse_engine()
    payload = {"state": "NOMINAL", "message": "ENGINE_RESUMED"}
    socketio.emit("system_status", payload)
    log_event("system_status", payload)
    return jsonify({"status": "success", "message": "Engine resumed"}), 200


@app.route('/debug/simulate-halt', methods=['POST'])
@require_auth
def simulate_halt():
    if os.environ.get('PULSE_ENV') == 'testing':
        halt_pulse_engine()
        payload = {
            'state': 'HALTED',
            'error': 'SIMULATED_CRITICAL_EVENT'
        }
        socketio.emit('system_status', payload)
        log_event('system_status', payload)
        return jsonify({"status": "success", "message": "Kill-switch triggered"}), 200
    return jsonify({"status": "forbidden"}), 403


@app.route('/export-logs', methods=['GET'])
@require_auth
def export_logs():
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=["timestamp", "type", "cpu", "latency", "uptime", "status"])
    writer.writeheader()
    writer.writerows(event_logs)

    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=pulse_audit_log.csv"
    output.headers["Content-type"] = "text/csv"
    return output


@app.route('/clear-logs', methods=['POST'])
@require_auth
def clear_logs():
    event_logs.clear()
    return jsonify({"status": "success", "message": "Audit buffer cleared"}), 200


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("SOVEREIGN_PORT", 5050))

    # Auto-start the APScheduler if available
    try:
        from sovereign_pulse_scheduler import build_scheduler
        scheduler = build_scheduler(interval_hours=6)
        scheduler.start()
        print(f"[Sovereign Pulse API] Scheduler started (6h interval)")
    except Exception as exc:
        print(f"[Sovereign Pulse API] Scheduler not started: {exc}")

    # Start service heartbeat monitor for real-time dashboard alerting.
    socketio.start_background_task(service_health_worker)
    socketio.start_background_task(monitor_vitals)

    print(f"[Sovereign Pulse API] Dashboard: http://127.0.0.1:{port}")
    print(f"[Sovereign Pulse API] API:       http://127.0.0.1:{port}/api/health")
    socketio.run(app, host="127.0.0.1", port=port, debug=False)
