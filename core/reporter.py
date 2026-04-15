from __future__ import annotations

import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from core.notifications import BusinessNotificationHub
from modules.port_scanner.main import scan_business_assets

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    HAS_REPORTLAB = True
except Exception:
    HAS_REPORTLAB = False


DB_PATH = Path("data/telemetry.db")


def _load_notification_config() -> dict[str, Any]:
    load_dotenv()
    return {
        "slack_webhook": os.getenv("SHADOW_SLACK_WEBHOOK", ""),
        "email_user": os.getenv("SHADOW_EMAIL_USER", ""),
        "email_pass": os.getenv("SHADOW_EMAIL_PASS", ""),
        "admin_email": os.getenv("SHADOW_ADMIN_EMAIL", ""),
        "telegram_bot_token": os.getenv("SHADOW_TELEGRAM_BOT_TOKEN", ""),
        "telegram_chat_id": os.getenv("SHADOW_TELEGRAM_CHAT_ID", ""),
        "smtp_host": os.getenv("SHADOW_SMTP_HOST", "smtp.gmail.com"),
        "smtp_port": int(os.getenv("SHADOW_SMTP_PORT", "465")),
        "smtp_timeout": int(os.getenv("SHADOW_SMTP_TIMEOUT", "10")),
        "cooldown_seconds": int(os.getenv("SHADOW_NOTIFY_COOLDOWN_SECONDS", "300")),
    }


class DailyReporter:
    """Generate and dispatch daily business summaries from telemetry."""

    def __init__(self, db_path: str = str(DB_PATH), targets_file: str = "data/targets.json") -> None:
        self.db_path = db_path
        self.hub = BusinessNotificationHub(
            targets_file=targets_file,
            fallback_config=_load_notification_config(),
        )
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        db_file = Path(self.db_path)
        if not db_file.exists():
            return

        conn = sqlite3.connect(self.db_path)
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            table_exists = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
            ).fetchone()
            if not table_exists:
                return

            columns = {row[1] for row in conn.execute("PRAGMA table_info(events)").fetchall()}
            if "business" not in columns:
                conn.execute("ALTER TABLE events ADD COLUMN business TEXT DEFAULT 'global'")
                conn.commit()
        finally:
            conn.close()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def generate_daily_summary(self, company_name: str) -> list[dict[str, Any]]:
        """Return last 24h events for a specific business."""
        since = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
        conn = self._connect()
        try:
            rows = conn.execute(
                """
                SELECT timestamp, module, event, severity, business, data_json
                FROM events
                WHERE business = ? AND timestamp > ?
                ORDER BY timestamp ASC
                """,
                (company_name, since),
            ).fetchall()
        finally:
            conn.close()

        summary_rows: list[dict[str, Any]] = []
        for row in rows:
            try:
                payload = json.loads(row[5] or "{}")
            except Exception:
                payload = {}
            summary_rows.append(
                {
                    "timestamp": row[0],
                    "module": row[1],
                    "event": row[2],
                    "severity": str(row[3]).lower(),
                    "business": row[4],
                    "payload": payload,
                }
            )
        return summary_rows

    def _store_compliance_violations(
        self,
        company_name: str,
        violations: dict[str, list[int]],
        allowed_ports: list[int],
    ) -> None:
        if not violations:
            return

        conn = self._connect()
        try:
            for ip, ports in violations.items():
                payload = {
                    "business": company_name,
                    "ip": ip,
                    "open_unauthorized_ports": ports,
                    "allowed_ports": allowed_ports,
                }
                conn.execute(
                    "INSERT INTO events (module, event, severity, business, data_json) VALUES (?, ?, ?, ?, ?)",
                    (
                        "port_scanner",
                        "compliance_violation",
                        "warning",
                        company_name,
                        json.dumps(payload, separators=(",", ":")),
                    ),
                )
            conn.commit()
        finally:
            conn.close()

    def _run_compliance_scan(self, company_name: str, config: dict[str, Any]) -> dict[str, Any]:
        assets = [str(ip) for ip in config.get("assets", [])]
        allowed_ports = [int(p) for p in config.get("allowed_ports", [22, 80, 443])]
        scan_ports = [int(p) for p in config.get("scan_ports", [21, 22, 23, 80, 443, 3389])]
        timeout = float(os.getenv("SHADOW_PORT_SCAN_TIMEOUT", "0.35"))
        workers = int(os.getenv("SHADOW_PORT_SCAN_WORKERS", "64"))

        if not assets:
            return {
                "assets_scanned": 0,
                "violations": {},
                "violation_count": 0,
                "compliance_score": 100,
                "allowed_ports": allowed_ports,
            }

        violations = scan_business_assets(
            assets=assets,
            safe_ports=allowed_ports,
            scan_ports=scan_ports,
            timeout=timeout,
            workers=workers,
        )
        violation_count = sum(len(ports) for ports in violations.values())
        score = max(0, 100 - (violation_count * 5))

        self._store_compliance_violations(company_name, violations, allowed_ports)

        return {
            "assets_scanned": len(assets),
            "violations": violations,
            "violation_count": violation_count,
            "compliance_score": score,
            "allowed_ports": allowed_ports,
        }

    def _estimate_uptime_percent(self, logs: list[dict[str, Any]]) -> float:
        if not logs:
            return 100.0
        penalties = 0
        for item in logs:
            sev = item.get("severity", "info")
            if sev == "critical":
                penalties += 20
            elif sev == "warning":
                penalties += 5
        estimated = max(90.0, 100.0 - (penalties / max(1, len(logs))))
        return round(estimated, 2)

    def _format_summary(self, company_name: str, logs: list[dict[str, Any]], compliance: dict[str, Any]) -> str:
        sev_counts = Counter(item.get("severity", "info").upper() for item in logs)
        uptime = self._estimate_uptime_percent(logs)
        now = datetime.now().strftime("%Y-%m-%d")

        headline = [
            "SHADOW-TOOLZ EXECUTIVE SUMMARY",
            f"Target: {company_name} | Date: {now}",
            f"Operational Status: {'NOMINAL' if sev_counts.get('CRITICAL', 0) == 0 else 'ATTENTION REQUIRED'} ({uptime:.2f}% Uptime)",
            f"COMPLIANCE SCORE: {compliance.get('compliance_score', 100)}%",
            f"Compliance Violations: {compliance.get('violation_count', 0)}",
            f"Total Events Tracked: {len(logs)}",
            f"Critical Alerts: {sev_counts.get('CRITICAL', 0)}",
            f"Warning Alerts: {sev_counts.get('WARNING', 0)}",
            "",
            "Compliance Findings:",
        ]

        violation_lines: list[str] = []
        violations = compliance.get("violations", {})
        if violations:
            for ip, ports in violations.items():
                joined = ", ".join(str(p) for p in ports)
                violation_lines.append(f" - {ip}: unauthorized open ports [{joined}]")
        else:
            violation_lines.append(" - No unauthorized open ports detected.")

        headline.extend(violation_lines)
        headline.extend([
            "",
            "Incident Log (Last 24 Hours):",
        ])

        incident_lines: list[str] = []
        for item in logs[-10:]:
            ts = item.get("timestamp", "")
            sev = str(item.get("severity", "info")).upper()
            event = item.get("event", "unknown")
            module = item.get("module", "unknown")
            incident_lines.append(f" - [{ts}] {sev}: {module}.{event}")

        if not incident_lines:
            incident_lines.append(" - No notable incidents in the last 24 hours.")

        return "\n".join(headline + incident_lines)

    def _write_csv(self, company_name: str, logs: list[dict[str, Any]]) -> Path:
        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        csv_path = reports_dir / f"{company_name}_{datetime.now().strftime('%Y%m%d')}.csv"
        with csv_path.open("w", encoding="utf-8") as handle:
            handle.write("timestamp,module,event,severity,business,payload\n")
            for item in logs:
                payload = json.dumps(item.get("payload", {}), separators=(",", ":")).replace('"', '""')
                handle.write(
                    f"{item.get('timestamp','')},{item.get('module','')},{item.get('event','')},{item.get('severity','')},{item.get('business','')},\"{payload}\"\n"
                )
        return csv_path

    def _write_pdf(self, company_name: str, summary_text: str) -> Path | None:
        if not HAS_REPORTLAB:
            return None
        reports_dir = Path("data/reports")
        reports_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = reports_dir / f"{company_name}_{datetime.now().strftime('%Y%m%d')}.pdf"

        pdf = canvas.Canvas(str(pdf_path), pagesize=letter)
        width, height = letter
        y = height - 40
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(40, y, "SHADOW-TOOLZ Daily Business Audit")
        y -= 24
        pdf.setFont("Helvetica", 10)

        for line in summary_text.splitlines():
            if y < 40:
                pdf.showPage()
                pdf.setFont("Helvetica", 10)
                y = height - 40
            pdf.drawString(40, y, line[:140])
            y -= 14

        pdf.save()
        return pdf_path

    def dispatch_reports(self) -> dict[str, int]:
        """Dispatch daily reports to each configured business and return sent counts."""
        sent_business = 0
        sent_emails = 0
        csv_written = 0
        pdf_written = 0

        for company_name, config in self.hub.targets.items():
            if not config.get("enabled", True):
                continue

            compliance = self._run_compliance_scan(company_name, config)

            logs = self.generate_daily_summary(company_name)
            if not logs:
                continue

            summary_text = self._format_summary(company_name, logs, compliance)
            subject = f"Daily Security Audit: {company_name}"
            dedupe_key = f"daily-report:{company_name}:{datetime.now().strftime('%Y-%m-%d')}"

            # Export daily CSV per business for compliance and forensics records.
            csv_path = self._write_csv(company_name, logs)
            csv_written += 1
            pdf_path = self._write_pdf(company_name, summary_text)
            if pdf_path is not None:
                pdf_written += 1

            for recipient in config.get("contacts", []):
                if self.hub._send_email_to(recipient, subject, summary_text, dedupe_key=dedupe_key):
                    sent_emails += 1

            # Optional daily digest mirror to Slack and Telegram.
            self.hub.send_business_alert(
                company_name,
                config,
                subject=subject,
                message=f"{summary_text}\n\nCSV Report: {csv_path}\nPDF Report: {pdf_path if pdf_path else 'disabled (reportlab not installed)'}",
                event_data={"kind": "daily_report", "count": len(logs), "compliance": compliance},
                dedupe_key=dedupe_key,
                send_slack=True,
                send_email=False,
                send_telegram=True,
            )
            sent_business += 1

        return {
            "businesses_reported": sent_business,
            "emails_sent": sent_emails,
            "csv_written": csv_written,
            "pdf_written": pdf_written,
        }