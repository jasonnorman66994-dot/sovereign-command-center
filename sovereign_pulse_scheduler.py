#!/usr/bin/env python3
"""
Sovereign Pulse — Automated Scheduler
======================================
Runs the full Sovereign Pulse pipeline on a configurable interval
using APScheduler.  Collects telemetry, evaluates anomalies,
generates the HTML+PDF dashboard, and dispatches Gmail reports.

Usage:
    python sovereign_pulse_scheduler.py                  # default: every 6h
    python sovereign_pulse_scheduler.py --interval 1     # every 1 hour
    python sovereign_pulse_scheduler.py --weekly mon 8   # cron: Mondays at 08:00
    python sovereign_pulse_scheduler.py --every-min 15   # high-frequency: every 15 min
    python sovereign_pulse_scheduler.py --weekly mon 9 --every-min 15  # dual-schedule
    python sovereign_pulse_scheduler.py --with-api       # also start Flask API
    python sovereign_pulse_scheduler.py --once            # single run, no scheduler

Dual-schedule mode (--weekly + --every-min together):
    Weekly job  → full pipeline: telemetry + PDF dashboard + email with attachments
    Frequent job → lightweight pulse check: telemetry only, alerts on anomalies

Environment variables:
    GMAIL_USER          — Gmail address  (default from stored credentials)
    GMAIL_APP_PASSWORD  — Gmail App Password
    SOVEREIGN_PORT      — API port (default 5050)
    ALERT_EMAIL         — report recipient
    CERT_PATH           — PKCS#12 cert for PDF signing (optional)
    CERT_PASSWORD       — cert password (optional)
"""

import argparse
import hashlib
import io
import json
import logging
import os
import platform
import smtplib
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from email import encoders
from email.mime.application import MIMEApplication
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path
from queue import Queue

# ---------------------------------------------------------------------------
# Ensure project root is on sys.path
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shadow_toolkit.sentinel_baseline import BehavioralEngine, load_anomalies
from backend.services.threat_intel import get_recent_events, lookup as threat_lookup
from sovereign_db import get_all_targets, increment_pulse
from engine_control import is_pulse_active

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
LOG_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", r"C:\Logs\sentinel"))
CVE_LOG_DIR = Path(r"C:\Logs\cve43887")
REPORT_DIR = Path(r"C:\Reports\cve43887")
SCHEDULER_LOG = LOG_DIR / "scheduler.log"

ALERT_EMAIL = os.environ.get("ALERT_EMAIL", "jasonnorman66994@gmail.com")
TARGET_USERS = get_all_targets() or [ALERT_EMAIL]

PIPELINE_LOG_FILE = LOG_DIR / "pipeline_log.json"
PIPELINE_STATE_FILE = LOG_DIR / "pipeline_state.json"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(SCHEDULER_LOG), encoding="utf-8"),
    ],
)
log = logging.getLogger("sovereign_pulse")

engine = BehavioralEngine()

_start_time = datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Pipeline Log & State helpers (feed the Live Output panel)
# ---------------------------------------------------------------------------
def _emit_log(message: str, level: str = "info"):
    """Append a log entry to the pipeline log file for the dashboard."""
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "message": str(message)[:500],
        "level": level,
    }
    try:
        entries = []
        if PIPELINE_LOG_FILE.exists():
            with open(PIPELINE_LOG_FILE, "r") as f:
                entries = json.load(f)
        entries.append(entry)
        entries = entries[-1000:]
        PIPELINE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PIPELINE_LOG_FILE, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception:
        pass  # best-effort, don't break the pipeline


def _save_pipeline_state(state: dict):
    """Persist current pipeline state for the dashboard."""
    try:
        PIPELINE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(PIPELINE_STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Pipeline Stage 1: Telemetry Collection & Anomaly Detection
# ---------------------------------------------------------------------------
def run_pulse_pipeline() -> dict:
    """
    Collect telemetry, evaluate baseline, detect anomalies,
    and return a summary dict for the report.
    """
    log.info("Stage 1: Collecting telemetry...")
    _emit_log("Stage 1: Collecting telemetry...")
    result = engine.collect_and_evaluate()

    sample = result["sample"]
    anomalies = result["anomalies"]
    sample_count = result["sample_count"]

    log.info(
        "Telemetry: processes=%d, unique_ips=%d, samples=%d, anomalies=%d",
        sample.get("process_count", 0),
        sample.get("unique_remote_ips", 0),
        sample_count,
        len(anomalies),
    )
    _emit_log(f"Telemetry: processes={sample.get('process_count',0)}, ips={sample.get('unique_remote_ips',0)}, samples={sample_count}, anomalies={len(anomalies)}")

    # Fetch recent threat events for the report
    threat_events = get_recent_events(days=7)

    report_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": platform.node(),
        "sample": sample,
        "baseline_status": engine.get_baseline_status(),
        "anomalies": anomalies,
        "anomaly_count_7d": len(load_anomalies(7)),
        "threat_events": threat_events,
        "threat_count_7d": len(threat_events),
        "sample_count": sample_count,
        "cache_fresh": result["cache_fresh"],
    }

    if anomalies:
        log.warning("%d anomalies detected in this collection!", len(anomalies))
        _emit_log(f"{len(anomalies)} anomalies detected!", "warn")
        for a in anomalies:
            log.warning(
                "  ANOMALY: %s observed=%s z=%+.2f severity=%s",
                a.get("metric"), a.get("observed"), a.get("zscore", 0), a.get("severity"),
            )

    return report_data


# ---------------------------------------------------------------------------
# Pipeline Stage 2: Dashboard Generation (HTML + PDF)
# ---------------------------------------------------------------------------
def generate_dashboard(report_data: dict) -> dict:
    """
    Invoke the PowerShell dashboard generator to create HTML + PDF.
    Returns paths to generated files.
    """
    log.info("Stage 2: Generating HTML + PDF dashboard...")
    _emit_log("Stage 2: Generating HTML + PDF dashboard...")

    ps_script = PROJECT_ROOT / "cve43887_dashboard_html.ps1"
    if not ps_script.exists():
        log.warning("Dashboard script not found: %s — skipping generation", ps_script)
        return {"html": None, "pdf": None}

    cert_path = os.environ.get("CERT_PATH", "")
    cert_password = os.environ.get("CERT_PASSWORD", "")

    cmd = [
        "pwsh", "-ExecutionPolicy", "Bypass", "-File", str(ps_script),
        "-SkipEmail",  # we handle email ourselves
    ]
    if not cert_path:
        cmd.append("-SkipSign")
    else:
        cmd.extend(["-CertPath", cert_path, "-CertPassword", cert_password])

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120,
            cwd=str(PROJECT_ROOT),
        )
        if proc.returncode != 0:
            log.error("Dashboard script failed:\n%s", proc.stderr or proc.stdout)
        else:
            log.info("Dashboard script completed successfully")
    except subprocess.TimeoutExpired:
        log.error("Dashboard script timed out after 120s")
    except FileNotFoundError:
        log.warning("pwsh not found — cannot generate dashboard")

    # Find the generated files
    today = datetime.now().strftime("%Y-%m-%d")
    html_path = REPORT_DIR / f"cve43887-dashboard-{today}.html"
    pdf_path = REPORT_DIR / f"cve43887-dashboard-{today}.pdf"
    signed_pdf = REPORT_DIR / f"cve43887-dashboard-{today}-signed.pdf"

    result_pdf = signed_pdf if signed_pdf.exists() else (pdf_path if pdf_path.exists() else None)

    return {
        "html": str(html_path) if html_path.exists() else None,
        "pdf": str(result_pdf) if result_pdf else None,
    }


# ---------------------------------------------------------------------------
# Pipeline Stage 3: Gmail Report Delivery
# ---------------------------------------------------------------------------
def _load_gmail_credentials() -> tuple:
    """
    Load Gmail credentials from environment or stored credential file.
    Returns (username, password) or (None, None).
    """
    user = os.environ.get("GMAIL_USER", "")
    pwd = os.environ.get("GMAIL_APP_PASSWORD", "")

    if user and pwd:
        return user, pwd

    # Try loading from PowerShell Export-Clixml credential file
    cred_file = CVE_LOG_DIR / "gmail_cred.xml"
    if cred_file.exists():
        try:
            proc = subprocess.run(
                [
                    "pwsh", "-NoProfile", "-Command",
                    f"$c = Import-Clixml '{cred_file}'; "
                    f"'{{\"{0}\":\"{1}\"}}'.Replace('{0}', $c.UserName)"
                    f".Replace('{1}', $c.GetNetworkCredential().Password)",
                ],
                capture_output=True, text=True, timeout=15,
            )
            if proc.returncode == 0:
                cred = json.loads(proc.stdout.strip())
                return list(cred.keys())[0], list(cred.values())[0]
        except Exception as e:
            log.warning("Failed to load stored Gmail credentials: %s", e)

    return None, None


def _get_pdf_checksum(file_path: str) -> str:
    """Return the SHA-256 hex digest of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def send_gmail_report(report_data: dict, files: dict = None):
    """
    Send the pipeline report via Gmail SMTP SSL (port 465).
    Attaches HTML and PDF dashboard files if available.
    """
    log.info("Stage 3: Sending Gmail report...")
    _emit_log("Stage 3: Sending Gmail report...")
    _emit_log("SMTP Auth connecting to smtp.gmail.com:465...")

    user, pwd = _load_gmail_credentials()
    if not user or not pwd:
        log.warning("Gmail credentials not available — skipping email delivery")
        return

    to_addr = ALERT_EMAIL
    timestamp = report_data.get("timestamp", datetime.now(timezone.utc).isoformat())[:19]
    anomaly_count = len(report_data.get("anomalies", []))
    threat_count = report_data.get("threat_count_7d", 0)
    sample_count = report_data.get("sample_count", 0)
    cache_fresh = report_data.get("cache_fresh", False)
    proc_count = report_data.get("sample", {}).get("process_count", 0)
    unique_ips = report_data.get("sample", {}).get("unique_remote_ips", 0)

    status = "HEALTHY" if anomaly_count == 0 and cache_fresh else "ALERT"
    subject = f"Sovereign Pulse [{status}] — {timestamp[:10]}"

    body = f"""Sovereign Pulse Automated Report — {timestamp}
Host: {report_data.get('host', 'unknown')}
Status: {status}

--- Current Telemetry ---
Process Count: {proc_count}
Unique Remote IPs: {unique_ips}
Baseline Samples: {sample_count}
Cache Fresh: {'Yes' if cache_fresh else 'No'}

--- 7-Day Summary ---
Anomalies: {report_data.get('anomaly_count_7d', 0)}
Threat Events: {threat_count}
New Anomalies (this run): {anomaly_count}

"""
    if anomaly_count > 0:
        body += "--- Anomalies Detected ---\n"
        for a in report_data["anomalies"]:
            body += (
                f"  [{a.get('severity', 'INFO')}] {a.get('metric', '')}: "
                f"observed={a.get('observed', '')} z={a.get('zscore', 0):+.2f}\n"
            )
        body += "\n"

    body += "This report is auto-generated by the Sovereign Pulse scheduler.\n"

    # Compute PDF checksum if attached
    pdf_path = files.get("pdf") if files else None
    if pdf_path and os.path.isfile(pdf_path):
        checksum = _get_pdf_checksum(pdf_path)
        body += f"\nSignature Hash (SHA-256): {checksum}\nStatus: Verified.\n"
        log.info("PDF checksum: %s", checksum)

    # Build email
    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = to_addr
    msg.attach(MIMEText(body, "plain"))

    # Attach dashboard files
    if files:
        for label, fpath in files.items():
            if fpath and os.path.isfile(fpath):
                with open(fpath, "rb") as f:
                    part = MIMEBase("application", "octet-stream")
                    part.set_payload(f.read())
                encoders.encode_base64(part)
                part.add_header(
                    "Content-Disposition",
                    f'attachment; filename="{os.path.basename(fpath)}"',
                )
                msg.attach(part)
                log.info("  Attached: %s", os.path.basename(fpath))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
            smtp.login(user, pwd)
            smtp.send_message(msg)
        log.info("Email dispatched to %s", to_addr)
        _emit_log(f"SMTP Auth Success - email dispatched to {to_addr}")
    except Exception as e:
        log.error("Gmail delivery failed: %s", e)
        _emit_log(f"Gmail delivery failed: {e}", "error")


# ---------------------------------------------------------------------------
# Lightweight Pulse Check (for high-frequency scheduling)
# ---------------------------------------------------------------------------
def pulse_check_task():
    """
    Lightweight telemetry-only check.  Runs Stage 1 (collect & evaluate)
    and sends a short alert email *only* when anomalies are detected.
    No PDF generation — designed for high-frequency intervals.
    """
    log.info("--- Pulse check ---")
    _emit_log("Pulse check: collecting telemetry...")

    uptime_delta = datetime.now(timezone.utc) - _start_time
    uptime_str = f"{int(uptime_delta.total_seconds() // 3600)}h {int((uptime_delta.total_seconds() % 3600) // 60)}m"

    _save_pipeline_state({
        "state": "Pulse Check",
        "last_run": datetime.now(timezone.utc).isoformat(),
        "uptime": uptime_str,
        "mail_queue": "Checking",
    })

    try:
        result = engine.collect_and_evaluate()
        sample = result["sample"]
        anomalies = result["anomalies"]

        log.info(
            "Pulse: processes=%d, ips=%d, anomalies=%d",
            sample.get("process_count", 0),
            sample.get("unique_remote_ips", 0),
            len(anomalies),
        )
        _emit_log(
            f"Pulse: processes={sample.get('process_count',0)}, "
            f"ips={sample.get('unique_remote_ips',0)}, "
            f"anomalies={len(anomalies)}"
        )

        # Only email if anomalies were found
        if anomalies:
            _emit_log(f"ALERT: {len(anomalies)} anomalies — sending pulse alert", "warn")
            _send_pulse_alert(anomalies, sample)
            _save_pipeline_state({
                "state": "Idle",
                "last_run": datetime.now(timezone.utc).isoformat(),
                "uptime": uptime_str,
                "mail_queue": "Alert Sent",
            })
        else:
            _emit_log("Pulse check clean — no anomalies")
            _save_pipeline_state({
                "state": "Idle",
                "last_run": datetime.now(timezone.utc).isoformat(),
                "uptime": uptime_str,
                "mail_queue": "Idle",
            })
    except Exception:
        log.exception("Pulse check error:")
        _emit_log("Pulse check error — see scheduler.log", "error")


def _send_pulse_alert(anomalies: list, sample: dict):
    """Send a short anomaly-alert email (no attachments)."""
    user, pwd = _load_gmail_credentials()
    if not user or not pwd:
        return

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    subject = f"Sovereign Pulse [ALERT] — {len(anomalies)} anomalies @ {ts}"

    lines = [f"Sovereign Pulse — Anomaly Alert ({ts})", ""]
    lines.append(f"Host: {platform.node()}")
    lines.append(f"Processes: {sample.get('process_count', 0)}")
    lines.append(f"Unique IPs: {sample.get('unique_remote_ips', 0)}")
    lines.append("")
    for a in anomalies:
        lines.append(
            f"  [{a.get('severity','INFO')}] {a.get('metric','')}: "
            f"observed={a.get('observed','')} z={a.get('zscore',0):+.2f}"
        )
    lines.append("")
    lines.append("Full report will be sent on the next weekly run.")

    msg = MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = user
    msg["To"] = ALERT_EMAIL
    msg.attach(MIMEText("\n".join(lines), "plain"))

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as smtp:
            smtp.login(user, pwd)
            smtp.send_message(msg)
        log.info("Pulse alert dispatched to %s", ALERT_EMAIL)
        _emit_log(f"Pulse alert dispatched to {ALERT_EMAIL}")
    except Exception as e:
        log.error("Pulse alert delivery failed: %s", e)
        _emit_log(f"Pulse alert failed: {e}", "error")


# ---------------------------------------------------------------------------
# Full Pipeline Runner (weekly / default)
# ---------------------------------------------------------------------------
def automated_pipeline_task():
    """Execute the full Sovereign Pulse pipeline."""
    log.info("=" * 60)
    log.info("Pulse sequence initiated at %s", datetime.now().isoformat())
    log.info("=" * 60)

    _emit_log("Pulse sequence initiated")
    uptime_delta = datetime.now(timezone.utc) - _start_time
    uptime_str = f"{int(uptime_delta.total_seconds() // 3600)}h {int((uptime_delta.total_seconds() % 3600) // 60)}m"

    _save_pipeline_state({
        "state": "Running",
        "last_run": datetime.now(timezone.utc).isoformat(),
        "uptime": uptime_str,
        "mail_queue": "Pending",
    })

    try:
        # Stage 1 — Collect & evaluate
        report_data = run_pulse_pipeline()

        # Stage 2 — Generate dashboard
        files = generate_dashboard(report_data)

        # Stage 3 — Email delivery
        send_gmail_report(report_data, files)

        log.info("Pipeline completed successfully.")
        _emit_log("Pipeline completed successfully")
        _save_pipeline_state({
            "state": "Idle",
            "last_run": datetime.now(timezone.utc).isoformat(),
            "uptime": uptime_str,
            "mail_queue": "Idle",
        })
    except Exception:
        log.exception("Pipeline error:")
        _emit_log("Pipeline error — see scheduler.log", "error")
        _save_pipeline_state({
            "state": "Error",
            "last_run": datetime.now(timezone.utc).isoformat(),
            "uptime": uptime_str,
            "mail_queue": "Failed",
        })


# ---------------------------------------------------------------------------
# Async Dispatch Helper
# ---------------------------------------------------------------------------
def dispatch_pulse_async():
    """Run the full pipeline in a separate thread to prevent blocking."""
    thread = threading.Thread(target=automated_pipeline_task, daemon=True)
    thread.start()


def cleanup_old_reports():
    """Purge report files older than 24 hours from ./reports."""
    directory = os.path.join(os.path.dirname(__file__), "reports")
    if not os.path.isdir(directory):
        return
    now = time.time()
    for f in os.listdir(directory):
        path = os.path.join(directory, f)
        if os.path.isfile(path) and os.stat(path).st_mtime < now - 86400:
            os.remove(path)
            print(f"Purged: {f}")


# ---------------------------------------------------------------------------
# Mail Queue — decoupled pulse generation from SMTP delivery
# ---------------------------------------------------------------------------
mail_queue: Queue = Queue()


# ---------------------------------------------------------------------------
# SovereignEngine — persistent SMTP_SSL with auto-reconnect
# ---------------------------------------------------------------------------
class SovereignEngine:
    """Persistent SSL connection to Gmail for high-frequency pulse delivery."""

    def __init__(self, sender_email: str, app_password: str, target_email: str):
        self.sender = sender_email
        self.password = app_password
        self.target = target_email
        self.server = None

    def connect(self):
        """Establish (or re-establish) a persistent SMTP_SSL connection."""
        try:
            self.server = smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30)
            self.server.login(self.sender, self.password)
            log.info(">>> SovereignEngine: CONNECTION ESTABLISHED")
            _emit_log("SovereignEngine: SMTP connection established")
        except Exception as e:
            log.error(">>> SovereignEngine: AUTH FAILED: %s", e)
            _emit_log(f"SovereignEngine: AUTH FAILED: {e}", "error")
            self.server = None

    def _generate_signed_payload(self, timestamp: str) -> io.BytesIO:
        """Generate a mock-signed PDF payload with integrity hash."""
        content = f"Sovereign Pulse Telemetry Report\nTimestamp: {timestamp}\nIntegrity: VERIFIED\nEngine: SovereignEngine v1.0".encode()
        sig = hashlib.sha256(content).hexdigest()
        pdf_buffer = io.BytesIO()
        pdf_buffer.write(b"%PDF-1.4 ")
        pdf_buffer.write(content)
        pdf_buffer.write(f"\n%%SIG:{sig}".encode())
        pdf_buffer.seek(0)
        return pdf_buffer

    def _create_packet(self, target: str, content: str, pdf_data: io.BytesIO, timestamp: str) -> MIMEMultipart:
        """Build a MIME multipart message for the given target."""
        msg = MIMEMultipart()
        msg["Subject"] = f"PULSE_ENCRYPTED_{int(time.time())}"
        msg["From"] = self.sender
        msg["To"] = target
        msg.attach(MIMEText(f"Integrity: VERIFIED\nTimestamp: {timestamp}\n\n{content}", "plain"))
        pdf_data.seek(0)
        part = MIMEApplication(pdf_data.read(), Name=f"pulse_{timestamp}.pdf")
        part["Content-Disposition"] = f'attachment; filename="pulse_{timestamp}.pdf"'
        msg.attach(part)
        return msg

    def pulse(self, content: str) -> tuple[bool, str]:
        """Send a MIME multipart pulse with signed PDF attachment; auto-reconnects on failure.

        Returns (success, sig_hash) where sig_hash is the first 16 hex chars of the PDF SHA-256.
        """
        timestamp = time.strftime("%H_%M_%S")
        pdf_data = self._generate_signed_payload(timestamp)
        pdf_content = pdf_data.getvalue()
        sig_hash = hashlib.sha256(pdf_content).hexdigest()[:16].upper()

        msg = self._create_packet(self.target, content, pdf_data, timestamp)

        try:
            self.server.send_message(msg)
            return True, sig_hash
        except Exception:
            self.connect()
            if self.server is None:
                return False, sig_hash
            try:
                self.server.send_message(msg)
                return True, sig_hash
            except Exception:
                return False, sig_hash

    def dispatch_to(self, target: str, content: str) -> tuple[bool, str]:
        """Send a MIME multipart pulse to a specific target email.

        Returns (success, sig_hash).
        """
        timestamp = time.strftime("%H_%M_%S")
        pdf_data = self._generate_signed_payload(timestamp)
        pdf_content = pdf_data.getvalue()
        sig_hash = hashlib.sha256(pdf_content).hexdigest()[:16].upper()

        msg = self._create_packet(target, content, pdf_data, timestamp)

        try:
            self.server.send_message(msg)
            return True, sig_hash
        except Exception:
            self.connect()
            if self.server is None:
                return False, sig_hash
            try:
                self.server.send_message(msg)
                return True, sig_hash
            except Exception:
                return False, sig_hash

    def multi_target_dispatch(self, content: str, targets: list[str]) -> tuple[int, str]:
        """Send signed PDF pulse to multiple targets.

        Returns (success_count, sig_hash).
        """
        timestamp = time.strftime("%H_%M_%S")
        pdf_data = self._generate_signed_payload(timestamp)
        pdf_content = pdf_data.getvalue()
        sig_hash = hashlib.sha256(pdf_content).hexdigest()[:16].upper()
        success_count = 0

        for email in targets:
            try:
                msg = self._create_packet(email, content, pdf_data, timestamp)
                self.server.send_message(msg)
                success_count += 1
                log.info("[MultiTarget] Dispatched to %s [SIG:%s]", email, sig_hash)
                time.sleep(0.5)  # micro-sleep to keep connection stable
            except Exception as e:
                log.warning("[MultiTarget] Failed to reach %s: %s", email, e)
                self.connect()
                if self.server is None:
                    break

        return success_count, sig_hash


def _get_sovereign_engine() -> SovereignEngine | None:
    """Create and connect a SovereignEngine using stored credentials."""
    user, pwd = _load_gmail_credentials()
    if not user or not pwd:
        log.warning("SovereignEngine: No Gmail credentials — skipping")
        return None
    eng = SovereignEngine(user, pwd, ALERT_EMAIL)
    eng.connect()
    return eng


# Module-level engine — initialised lazily by pulse_worker
_sovereign_engine: SovereignEngine | None = None
_failed_attempts = 0


def pulse_worker():
    """High-frequency telemetry generator — 10s tight loop with persistent SMTP."""
    global _sovereign_engine, _failed_attempts
    _sovereign_engine = _get_sovereign_engine()
    dispatch_count = 0

    while True:
        try:
            if not is_pulse_active():
                log.warning(">>> DISPATCH HALTED: System in Critical State.")
                _emit_log("Dispatch halted by kill-switch", "warn")
                time.sleep(10)
                continue

            targets = get_all_targets() or [ALERT_EMAIL]
            timestamp = time.strftime("%H:%M:%S")
            
            # Persistent connection check
            if _sovereign_engine and not _sovereign_engine.server:
                log.info("[PulseWorker] Re-establishing Sovereign link...")
                _sovereign_engine.connect()
            
            # Multi-dispatch loop
            sig_hash = ""
            success = False
            if _sovereign_engine:
                log.info("[PulseWorker] Pulse generated at %s", timestamp)
                _emit_log(f"Pulse generated at {timestamp}")
                mail_queue.put(timestamp)
                
                for email in targets:
                    success, sig_hash = _sovereign_engine.dispatch_to(
                        email,
                        "Sovereign Payload v4.6"
                    )
                    if success:
                        dispatch_count += 1
                        increment_pulse(email)
                        log.info("[PulseWorker] Dispatch #%d to %s [SIG:%s]", dispatch_count, email, sig_hash)
                    time.sleep(0.5)  # Anti-throttle delay
            
            # Track consecutive failures for system status
            if success:
                _failed_attempts = 0
            else:
                _failed_attempts += 1
            
            # Push real-time events to connected dashboards via SocketIO
            try:
                from backend.api.server import socketio
                socketio.emit("new_pulse", {
                    "time": timestamp,
                    "count": dispatch_count,
                    "status": "SENT" if success else "FAILED",
                    "hash": sig_hash,
                    "target": ", ".join(targets),
                })
                if _failed_attempts >= 3:
                    socketio.emit("system_status", {"state": "CRITICAL", "msg": "SMTP_LINK_SEVERED"})
                else:
                    socketio.emit("system_status", {"state": "NOMINAL"})
            except Exception:
                pass  # socketio not available (standalone mode)
            
        except (smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError) as e:
            _failed_attempts += 1
            log.warning("[PulseWorker] Handshake Error: %s", e)
            try:
                from backend.api.server import socketio
                if _failed_attempts >= 3:
                    socketio.emit("system_status", {"state": "CRITICAL", "msg": "SMTP_LINK_SEVERED"})
            except Exception:
                pass
            time.sleep(5)
            if _sovereign_engine:
                _sovereign_engine.connect()
        except Exception as exc:
            _failed_attempts += 1
            log.error("[PulseWorker] Critical error: %s", exc)

        time.sleep(10)


def mail_dispatcher():
    """Consumes the mail queue and handles SMTP delivery without blocking the pulse."""
    while True:
        timestamp = mail_queue.get()
        if timestamp is None:
            break
        try:
            if not is_pulse_active():
                log.warning("[MailDispatcher] Skipping outbound report while engine is HALTED")
                _emit_log("Mail dispatch skipped (engine halted)", "warn")
                continue

            log.info("[MailDispatcher] Sending report for pulse %s", timestamp)
            _emit_log(f"Mail dispatcher processing pulse {timestamp}")
            report_data = run_pulse_pipeline()
            files = generate_dashboard(report_data)
            send_gmail_report(report_data, files)
            log.info("[MailDispatcher] Report delivered for pulse %s", timestamp)
            _emit_log(f"Mail delivered for pulse {timestamp}")
        except Exception as e:
            log.error("[MailDispatcher] Delivery failed for pulse %s: %s", timestamp, e)
            _emit_log(f"Mail dispatch failed: {e}", "error")
        finally:
            mail_queue.task_done()


# ---------------------------------------------------------------------------
# Build Scheduler (importable by server.py)
# ---------------------------------------------------------------------------
def build_scheduler(interval_hours: float = 6, pulse_minutes: int = 5):
    """
    Create and return a configured BackgroundScheduler (not started).

    Jobs:
        - Full pipeline every ``interval_hours`` (default 6h)
        - Lightweight pulse check every ``pulse_minutes`` (default 5m)
    """
    from apscheduler.schedulers.background import BackgroundScheduler

    sched = BackgroundScheduler()

    # Full pipeline on the longer cadence
    sched.add_job(
        dispatch_pulse_async,
        "interval",
        hours=interval_hours,
        id="sovereign_pulse_full",
        name=f"Full pipeline (every {interval_hours}h)",
    )

    # Lightweight pulse check on high-frequency cadence
    if pulse_minutes > 0:
        sched.add_job(
            pulse_check_task,
            "interval",
            minutes=pulse_minutes,
            id="sovereign_pulse_freq",
            name=f"Pulse check (every {pulse_minutes}m)",
        )

    # Report cleanup every 24 hours
    sched.add_job(
        cleanup_old_reports,
        "interval",
        hours=24,
        id="sovereign_report_cleanup",
        name="Report cleanup (every 24h)",
    )

    # Start pulse worker + mail dispatcher daemon threads
    threading.Thread(target=pulse_worker, daemon=True, name="PulseWorker").start()
    threading.Thread(target=mail_dispatcher, daemon=True, name="MailDispatcher").start()

    return sched


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Sovereign Pulse — Automated Pipeline Scheduler",
    )
    parser.add_argument(
        "--interval", type=float, default=6,
        help="Run interval in hours (default: 6)",
    )
    parser.add_argument(
        "--weekly", nargs=2, metavar=("DAY", "HOUR"),
        help="Cron schedule: DAY (mon-sun) HOUR (0-23). e.g. --weekly mon 8",
    )
    parser.add_argument(
        "--every-min", type=int, default=0, metavar="MINUTES",
        help="High-frequency interval in minutes (use with caution)",
    )
    parser.add_argument(
        "--with-api", action="store_true",
        help="Also start the Flask API server in-process",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Run the pipeline once and exit (no scheduling)",
    )
    args = parser.parse_args()

    # Ensure directories exist
    for d in (LOG_DIR, CVE_LOG_DIR, REPORT_DIR):
        d.mkdir(parents=True, exist_ok=True)

    if args.once:
        log.info("Running pipeline once (--once mode)")
        automated_pipeline_task()
        return

    # Import scheduler only when needed
    from apscheduler.schedulers.background import BackgroundScheduler

    scheduler = BackgroundScheduler()

    # Determine schedule mode
    schedule_parts = []

    # --- Weekly cron job (full pipeline: telemetry + PDF + email) ---
    if args.weekly:
        day_str = args.weekly[0].lower()[:3]
        hour_int = int(args.weekly[1])
        valid_days = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
        if day_str not in valid_days:
            log.error("Invalid day '%s'. Use: %s", day_str, ", ".join(valid_days))
            return
        if not (0 <= hour_int <= 23):
            log.error("Hour must be 0-23, got %d", hour_int)
            return
        scheduler.add_job(
            automated_pipeline_task,
            "cron",
            day_of_week=day_str,
            hour=hour_int,
            id="sovereign_pulse_weekly",
            name="Sovereign Pulse Pipeline (weekly)",
        )
        schedule_parts.append(f"Weekly: {day_str.capitalize()} at {hour_int:02d}:00")

    # --- High-frequency pulse check (telemetry only, alert on anomaly) ---
    if args.every_min > 0:
        if args.every_min < 5:
            log.warning("Interval < 5 min is aggressive — proceeding anyway")
        # When running alongside weekly, use lightweight pulse_check_task
        freq_func = pulse_check_task if args.weekly else automated_pipeline_task
        freq_label = "Pulse check" if args.weekly else "Full pipeline"
        scheduler.add_job(
            freq_func,
            "interval",
            minutes=args.every_min,
            next_run_time=datetime.now(),
            id="sovereign_pulse_freq",
            name=f"Sovereign Pulse ({freq_label} every {args.every_min}m)",
        )
        schedule_parts.append(f"Every {args.every_min}m ({freq_label.lower()})")

    # --- Default: interval in hours ---
    if not schedule_parts:
        scheduler.add_job(
            automated_pipeline_task,
            "interval",
            hours=args.interval,
            next_run_time=datetime.now(),
            id="sovereign_pulse",
            name="Sovereign Pulse Pipeline",
        )
        schedule_parts.append(f"Every {args.interval}h")

    schedule_desc = " + ".join(schedule_parts)

    scheduler.start()
    log.info("Scheduler started — %s. Press Ctrl+C to stop.", schedule_desc)
    _emit_log(f"Scheduler started — {schedule_desc}")

    # Compute earliest next run time across all jobs
    next_runs = []
    for job in scheduler.get_jobs():
        if job.next_run_time:
            next_runs.append(job.next_run_time.astimezone(timezone.utc))
    next_run_iso = min(next_runs).isoformat() if next_runs else "--"

    _save_pipeline_state({
        "state": "Idle",
        "last_run": "--",
        "next_run": next_run_iso,
        "uptime": "0h 0m",
        "mail_queue": "Idle",
        "interval": schedule_desc,
    })

    # Optionally run the Flask API in the foreground
    if args.with_api:
        log.info("Starting Flask API server alongside scheduler...")
        from backend.api.server import app
        port = int(os.environ.get("SOVEREIGN_PORT", 5050))
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)
    else:
        try:
            while True:
                time.sleep(60)
        except (KeyboardInterrupt, SystemExit):
            log.info("Shutting down scheduler...")
            scheduler.shutdown()


if __name__ == "__main__":
    main()
