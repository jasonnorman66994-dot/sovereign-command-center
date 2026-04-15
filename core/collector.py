import json
import os
import signal
import sqlite3
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from core.bus import create_subscriber
from core.notifications import NotificationHub, BusinessNotificationHub
from core.schema import TelemetryPacket


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


def _handle_notifications(
    hub: NotificationHub, 
    packet: TelemetryPacket,
    business_hub: BusinessNotificationHub = None
) -> None:
    """
    Route notifications based on packet content.
    
    If business_hub is provided and an IP can be extracted from the packet,
    route to business-specific contacts. Otherwise, use fallback global hub.
    """
    module_name = packet.module.lower()
    event_name = packet.event.lower()
    severity = packet.severity.lower()
    
    payload = packet.payload if isinstance(packet.payload, dict) else {}

    # Business-aware routing for critical alerts
    if severity == "critical" and module_name in {"arp_detector", "sentinel", "sentinel_01"}:
        alert_text = f"Module: {packet.module} | Event: {packet.event}"
        dedupe_key = f"{module_name}:{event_name}:critical"
        
        # Try business routing first (IP match, then module mapping)
        if business_hub:
            business_name, business_config = business_hub.get_business_for_packet(packet.module, payload)
            if business_name and business_config:
                print(f"[collector] routing critical alert to business: {business_name}")
                business_hub.send_business_alert(
                    business_name,
                    business_config,
                    "CRITICAL NETWORK ALERT",
                    alert_text,
                    packet.model_dump(),
                    dedupe_key=dedupe_key,
                    send_slack=True,
                    send_email=True,
                    send_telegram=False,
                )
                return
        
        # Fallback to global hub
        hub.send_slack(alert_text, dedupe_key=dedupe_key)
        hub.send_email("CRITICAL NETWORK ALERT", alert_text, dedupe_key=dedupe_key)
        hub.send_telegram(alert_text, dedupe_key=dedupe_key)
        return

    if severity == "warning" and module_name == "orchestrator" and event_name == "module_crash":
        alert_text = f"Module: {packet.module} | Event: {packet.event}"
        dedupe_key = f"{module_name}:{event_name}:warning"
        hub.send_slack(alert_text, dedupe_key=dedupe_key)
        hub.send_telegram(alert_text, dedupe_key=dedupe_key)
        return

    if severity == "warning" and module_name == "port_scanner" and event_name == "compliance_violation":
        dedupe_key = f"{module_name}:{event_name}:warning"
        ip = payload.get("ip", "unknown")
        ports = payload.get("open_unauthorized_ports", [])
        alert_text = f"Compliance violation on {ip}; unauthorized ports={ports}"

        if business_hub:
            business_name, business_config = business_hub.get_business_for_packet(packet.module, payload)
            if business_name and business_config:
                business_hub.send_business_alert(
                    business_name,
                    business_config,
                    "COMPLIANCE VIOLATION",
                    alert_text,
                    packet.model_dump(),
                    dedupe_key=dedupe_key,
                    send_slack=True,
                    send_email=False,
                    send_telegram=True,
                )
                return

        hub.send_slack(alert_text, dedupe_key=dedupe_key)
        hub.send_telegram(alert_text, dedupe_key=dedupe_key)


def init_db(db_path: Path = DB_PATH) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            module TEXT,
            event TEXT,
            severity TEXT,
            business TEXT,
            data_json TEXT
        )
        """
    )
    columns = {
        row[1]
        for row in conn.execute("PRAGMA table_info(events)").fetchall()
    }
    if "business" not in columns:
        conn.execute("ALTER TABLE events ADD COLUMN business TEXT DEFAULT 'global'")
    conn.commit()
    conn.close()


def persist_event(payload: dict[str, Any], db_path: Path = DB_PATH, business: str = None) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute(
        "INSERT INTO events (module, event, severity, business, data_json) VALUES (?, ?, ?, ?, ?)",
        (
            payload.get("module", "unknown"),
            payload.get("event", "unknown"),
            payload.get("severity", "info"),
            business or "global",
            json.dumps(payload.get("payload", {}), separators=(",", ":")),
        ),
    )
    conn.commit()
    conn.close()


def run_collector(port: int = 5555) -> None:
    init_db()
    _, socket = create_subscriber(port=port, bind=True)
    hub = NotificationHub(_load_notification_config())
    
    # Initialize multi-tenant business hub
    business_hub = None
    try:
        business_hub = BusinessNotificationHub(
            targets_file="data/targets.json",
            fallback_config=_load_notification_config()
        )
    except Exception as exc:
        print(f"[collector] Warning: Could not initialize BusinessNotificationHub: {exc}")
    
    running = True

    def stop_handler(_sig: int, _frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    print(f"[*] Collector listening on telemetry bus tcp://127.0.0.1:{port}")
    while running:
        try:
            topic, payload_bytes = socket.recv_multipart(flags=0)
            if topic.decode("utf-8") != "telemetry":
                continue
            payload_json = payload_bytes.decode("utf-8")
            payload = json.loads(payload_json)
            packet = TelemetryPacket.model_validate(payload)
            
            # Determine business for this event (IP first, then module mapping)
            business_name = "global"
            if business_hub:
                matched_business, _ = business_hub.get_business_for_packet(
                    packet.module,
                    packet.payload if isinstance(packet.payload, dict) else {},
                )
                if matched_business:
                    business_name = matched_business
            
            persist_event(packet.model_dump(mode="json"), business=business_name)
            _handle_notifications(hub, packet, business_hub=business_hub)
        except ValueError:
            continue
        except Exception as exc:
            print(f"[collector] warning: {exc}")

    socket.close(linger=0)


if __name__ == "__main__":
    run_collector()
