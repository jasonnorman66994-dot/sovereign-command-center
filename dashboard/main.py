import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse
from starlette.websockets import WebSocketDisconnect

from core.auth_verify import auth_config, require_clearance, verify_token, verify_websocket_token
from core.reporter import DailyReporter


if sys.platform.startswith("win"):
    # pyzmq asyncio sockets require selector-style loop APIs on Windows.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

load_dotenv()


DB_PATH = Path("data/telemetry.db")
AUDIT_LOG_PATH = Path("data/master_audit.log")
INDEX_PATH = Path(__file__).with_name("index.html")
PROJECT_ROOT = INDEX_PATH.parent.parent
ARTIFACT_FILES = {
    "chain_containment_latency.csv",
    "chain_kpis.json",
    "chain_response_latency.csv",
    "cross_scenario_analytics.json",
    "executive_summary.md",
    "mission_control_presentation.html",
    "mission_control_presentation.md",
    "mission_control_report.html",
    "mission_control_report.md",
    "multi_scenario_chain_timeline.md",
}
app = FastAPI(title="Shadow Toolz Telemetry Dashboard")
TELEMETRY_PORT = int(os.getenv("TELEMETRY_PORT", "5555"))
PIPELINE_DIAG: dict[str, Any] = {
    "ws_telemetry_connections": 0,
    "ws_telemetry_disconnects": 0,
    "ws_telemetry_frames_sent": 0,
    "ws_telemetry_errors": 0,
    "ws_telemetry_last_event_id": None,
}


def run_dashboard_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the FastAPI dashboard server in a dedicated process."""
    try:
        import uvicorn
    except Exception as exc:
        raise RuntimeError("uvicorn is required to run the dashboard server") from exc

    uvicorn.run(app, host=host, port=port, log_level="info")


def latest_events(limit: int = 25, business_filter: str = None) -> list[dict]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    
    if business_filter and business_filter != "all":
        rows = conn.execute(
            "SELECT timestamp, module, event, severity, business, data_json FROM events WHERE business = ? ORDER BY id DESC LIMIT ?",
            (business_filter, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT timestamp, module, event, severity, business, data_json FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    conn.close()

    return [
        {
            "timestamp": row[0],
            "module": row[1],
            "event": row[2],
            "severity": row[3],
            "business": row[4],
            "payload": json.loads(row[5] or "{}"),
        }
        for row in reversed(rows)
    ]


def latest_event_row() -> dict[str, Any] | None:
    if not DB_PATH.exists():
        return None

    conn = sqlite3.connect(DB_PATH)
    row = conn.execute(
        "SELECT id, timestamp, module, event, severity, business, data_json FROM events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "timestamp": row[1],
        "module": row[2],
        "event": row[3],
        "severity": row[4],
        "business": row[5],
        "payload": json.loads(row[6] or "{}"),
    }


@app.get("/")
def dashboard_index() -> FileResponse:
    return FileResponse(INDEX_PATH)


@app.get("/artifacts/{artifact_name}")
def dashboard_artifact(artifact_name: str) -> FileResponse:
    if artifact_name not in ARTIFACT_FILES:
        raise HTTPException(status_code=404, detail="Artifact not found")

    artifact_path = PROJECT_ROOT / artifact_name
    if not artifact_path.exists() or not artifact_path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")

    return FileResponse(artifact_path)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "telemetry_port": str(TELEMETRY_PORT)}


@app.get("/health/telemetry-pipeline")
def telemetry_pipeline_health(_claims: dict[str, Any] = Depends(verify_token)) -> dict[str, Any]:
    latest = latest_event_row()
    event_count = 0
    if DB_PATH.exists():
        conn = sqlite3.connect(DB_PATH)
        event_count = int(conn.execute("SELECT COUNT(1) FROM events").fetchone()[0])
        conn.close()

    return {
        "status": "ok",
        "telemetry_port": str(TELEMETRY_PORT),
        "db_path": str(DB_PATH),
        "db_events_total": event_count,
        "db_latest": latest,
        "ws_telemetry": PIPELINE_DIAG,
    }


@app.get("/auth/config")
def get_auth_config() -> dict[str, Any]:
    return auth_config()


@app.get("/health/notifications")
def notification_health(_claims: dict[str, Any] = Depends(verify_token)) -> dict[str, object]:
    """Expose channel readiness for notification integrations."""
    email_ready = all(
        [
            os.getenv("SHADOW_EMAIL_USER"),
            os.getenv("SHADOW_EMAIL_PASS"),
            os.getenv("SHADOW_ADMIN_EMAIL"),
        ]
    )
    telegram_ready = all(
        [
            os.getenv("SHADOW_TELEGRAM_BOT_TOKEN"),
            os.getenv("SHADOW_TELEGRAM_CHAT_ID"),
        ]
    )

    return {
        "status": "ok",
        "channels": {
            "slack": bool(os.getenv("SHADOW_SLACK_WEBHOOK")),
            "email": bool(email_ready),
            "telegram": bool(telegram_ready),
        },
        "cooldown_seconds": int(os.getenv("SHADOW_NOTIFY_COOLDOWN_SECONDS", "300")),
    }


@app.get("/targets")
def list_targets(_claims: dict[str, Any] = Depends(verify_token)) -> dict[str, object]:
    """List all configured business targets for MSSP operations."""
    targets_file = Path("data/targets.json")
    if not targets_file.exists():
        return {"targets": {}}
    
    try:
        with open(targets_file, 'r') as f:
            targets = json.load(f)
        return {"targets": targets}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load targets: {exc}")


@app.get("/logs/audit")
def get_audit_logs(limit: int = 50, _claims: dict[str, Any] = Depends(verify_token)) -> dict[str, list[str]]:
    """Retrieve audit logs with Bearer token authentication."""
    if not AUDIT_LOG_PATH.exists():
        return {"logs": []}
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    capped = max(1, min(limit, 500))
    return {"logs": lines[-capped:]}


@app.post("/maintenance/daily-report")
def run_daily_report_now(_claims: dict[str, Any] = Depends(require_clearance(2))) -> dict[str, object]:
    """Run daily report cycle immediately (authenticated)."""
    stats = DailyReporter().dispatch_reports()
    return {"status": "ok", "stats": stats}


@app.get("/forensics/pcaps")
def get_forensics_pcaps(_claims: dict[str, Any] = Depends(require_clearance(3))) -> dict[str, object]:
    """ABAC-protected sample endpoint for sensitive forensic data."""
    return {
        "status": "ok",
        "data": "Sensitive forensic data access granted",
        "artifact_path": "data/reports",
    }


@app.websocket("/ws")
async def ws_telemetry(websocket: WebSocket, access_token: str | None = None) -> None:
    try:
        verify_websocket_token(access_token)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    last_payload = ""
    try:
        while True:
            events = latest_events(limit=1)
            payload = json.dumps(events[0]) if events else "{}"
            if payload != last_payload:
                await websocket.send_text(payload)
                last_payload = payload
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close()


@app.websocket("/ws/telemetry")
async def ws_telemetry_bridge(websocket: WebSocket, access_token: str | None = None) -> None:
    try:
        verify_websocket_token(access_token)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    PIPELINE_DIAG["ws_telemetry_connections"] += 1
    last_event_id = 0

    try:
        # Emit the latest persisted event immediately so clients can validate stream health.
        initial = latest_event_row()
        if initial:
            await websocket.send_json({k: v for k, v in initial.items() if k != "id"})
            last_event_id = int(initial["id"])
            PIPELINE_DIAG["ws_telemetry_frames_sent"] += 1
            PIPELINE_DIAG["ws_telemetry_last_event_id"] = last_event_id

        while True:
            event = latest_event_row()
            if event and int(event["id"]) > last_event_id:
                await websocket.send_json({k: v for k, v in event.items() if k != "id"})
                last_event_id = int(event["id"])
                PIPELINE_DIAG["ws_telemetry_frames_sent"] += 1
                PIPELINE_DIAG["ws_telemetry_last_event_id"] = last_event_id
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        PIPELINE_DIAG["ws_telemetry_errors"] += 1
        await websocket.close()
    finally:
        PIPELINE_DIAG["ws_telemetry_disconnects"] += 1


if __name__ == "__main__":
    run_dashboard_server()
