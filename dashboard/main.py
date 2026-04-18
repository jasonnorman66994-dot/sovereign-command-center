import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, HTTPException, WebSocket
from fastapi.responses import FileResponse
from fastapi.responses import PlainTextResponse
from starlette.websockets import WebSocketDisconnect

from core.auth_verify import (
    auth_config,
    enforce_abac,
    get_abac_metrics,
    reset_abac_metrics,
    require_clearance,
    verify_token,
    verify_websocket_token,
)
from core.reporter import DailyReporter
from core.storage import build_storage, track_usage
from core.tasks import (
    celery_app,
    daily_report_task,
    refresh_audit_task,
    smoke_test_task,
)


if sys.platform.startswith("win"):
    # pyzmq asyncio sockets require selector-style loop APIs on Windows.
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

load_dotenv()


DB_PATH = Path("data/telemetry.db")
EVENT_STORAGE = build_storage()
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
    rows = EVENT_STORAGE.latest_events(limit=limit, business_filter=business_filter)
    return [
        {
            "timestamp": row.get("timestamp"),
            "module": row.get("module"),
            "event": row.get("event"),
            "severity": row.get("severity"),
            "business": row.get("business"),
            "payload": row.get("payload", {}),
        }
        for row in rows
    ]


def latest_event_row() -> dict[str, Any] | None:
    return EVENT_STORAGE.latest_event_row()


def latest_ids_events(
    limit: int = 50, severity: str | None = None
) -> list[dict[str, Any]]:
    return EVENT_STORAGE.latest_events(
        limit=limit,
        module_name="intrusion_detector",
        severity=severity,
    )


def latest_module_events(
    module_name: str, limit: int = 50, severity: str | None = None
) -> list[dict[str, Any]]:
    return EVENT_STORAGE.latest_events(
        limit=limit,
        module_name=module_name,
        severity=severity,
    )


def _tenant_from_claims(claims: dict[str, Any]) -> str:
    tenant = (
        claims.get("tenant")
        or claims.get("tenant_id")
        or claims.get("business")
        or claims.get("org")
        or "global"
    )
    return str(tenant).strip() or "global"


def _tenant_allowed(claims: dict[str, Any], requested_tenant: str) -> bool:
    clearance_raw = claims.get("security_clearance", claims.get("clearance", 0))
    try:
        clearance = int(clearance_raw)
    except Exception:
        clearance = 0

    if clearance >= 5:
        return True

    return _tenant_from_claims(claims).lower() == requested_tenant.lower()


def _prometheus_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


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


@app.get("/ready")
def ready() -> dict[str, Any]:
    latest = latest_event_row()
    return {
        "status": "ready",
        "storage_events": EVENT_STORAGE.count_events(),
        "latest_event": latest,
    }


@app.get("/metrics")
def metrics() -> dict[str, Any]:
    total = EVENT_STORAGE.count_events()
    return {
        "events_total": total,
        "ws_connections": PIPELINE_DIAG.get("ws_telemetry_connections", 0),
        "ws_frames_sent": PIPELINE_DIAG.get("ws_telemetry_frames_sent", 0),
        "ws_errors": PIPELINE_DIAG.get("ws_telemetry_errors", 0),
    }


@app.get("/metrics/prometheus", response_class=PlainTextResponse)
def metrics_prometheus() -> str:
    events_total = EVENT_STORAGE.count_events()
    ws_connections = int(PIPELINE_DIAG.get("ws_telemetry_connections", 0) or 0)
    ws_frames_sent = int(PIPELINE_DIAG.get("ws_telemetry_frames_sent", 0) or 0)
    ws_errors = int(PIPELINE_DIAG.get("ws_telemetry_errors", 0) or 0)
    ws_disconnects = int(PIPELINE_DIAG.get("ws_telemetry_disconnects", 0) or 0)
    abac_memory = get_abac_metrics()
    abac_persisted = EVENT_STORAGE.abac_deny_summary(None)

    combined_abac_total = int(abac_memory.get("deny_total", 0) or 0) + int(
        abac_persisted.get("deny_total", 0) or 0
    )
    combined_abac_by_action: dict[str, int] = {}
    for source in (
        abac_memory.get("deny_by_action", {}),
        abac_persisted.get("deny_by_action", {}),
    ):
        for action, count in source.items():
            key = str(action or "unknown")
            combined_abac_by_action[key] = combined_abac_by_action.get(key, 0) + int(
                count or 0
            )

    lines = [
        "# HELP shadow_events_total Total number of persisted telemetry events",
        "# TYPE shadow_events_total counter",
        f"shadow_events_total {events_total}",
        "# HELP shadow_ws_telemetry_connections_total Total websocket telemetry connections",
        "# TYPE shadow_ws_telemetry_connections_total counter",
        f"shadow_ws_telemetry_connections_total {ws_connections}",
        "# HELP shadow_ws_telemetry_frames_sent_total Total telemetry frames sent over websocket",
        "# TYPE shadow_ws_telemetry_frames_sent_total counter",
        f"shadow_ws_telemetry_frames_sent_total {ws_frames_sent}",
        "# HELP shadow_ws_telemetry_disconnects_total Total websocket telemetry disconnects",
        "# TYPE shadow_ws_telemetry_disconnects_total counter",
        f"shadow_ws_telemetry_disconnects_total {ws_disconnects}",
        "# HELP shadow_ws_telemetry_errors_total Total websocket telemetry errors",
        "# TYPE shadow_ws_telemetry_errors_total counter",
        f"shadow_ws_telemetry_errors_total {ws_errors}",
        "# HELP shadow_usage_metric_total Accumulated tenant usage value by metric",
        "# TYPE shadow_usage_metric_total gauge",
        "# HELP shadow_abac_denies_total Total ABAC deny decisions (memory + persisted)",
        "# TYPE shadow_abac_denies_total counter",
        f"shadow_abac_denies_total {combined_abac_total}",
        "# HELP shadow_abac_denies_by_action_total Total ABAC deny decisions by action (memory + persisted)",
        "# TYPE shadow_abac_denies_by_action_total counter",
    ]

    for row in EVENT_STORAGE.usage_summary(None):
        tenant = _prometheus_escape(str(row.get("tenant_id", "global")))
        metric = _prometheus_escape(str(row.get("metric", "unknown")))
        value = float(row.get("value", 0) or 0)
        lines.append(
            f'shadow_usage_metric_total{{tenant="{tenant}",metric="{metric}"}} {value}'
        )

    for action, count in sorted(combined_abac_by_action.items()):
        action_label = _prometheus_escape(action)
        lines.append(
            f'shadow_abac_denies_by_action_total{{action="{action_label}"}} {int(count)}'
        )

    return "\n".join(lines) + "\n"


@app.get("/health/telemetry-pipeline")
def telemetry_pipeline_health(
    _claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    latest = latest_event_row()
    event_count = EVENT_STORAGE.count_events()

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
def notification_health(
    _claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, object]:
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
        with open(targets_file, "r") as f:
            targets = json.load(f)
        return {"targets": targets}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to load targets: {exc}")


@app.get("/logs/audit")
def get_audit_logs(
    limit: int = 50, _claims: dict[str, Any] = Depends(verify_token)
) -> dict[str, list[str]]:
    """Retrieve audit logs with Bearer token authentication."""
    if not AUDIT_LOG_PATH.exists():
        return {"logs": []}
    lines = AUDIT_LOG_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()
    capped = max(1, min(limit, 500))
    return {"logs": lines[-capped:]}


@app.get("/ids/status")
def ids_status(_claims: dict[str, Any] = Depends(verify_token)) -> dict[str, Any]:
    rows = latest_ids_events(limit=200)
    snapshots = [row for row in rows if row.get("event") == "ids_snapshot"]
    alerts = [row for row in rows if row.get("severity") in {"warning", "critical"}]
    last_snapshot = snapshots[-1] if snapshots else None
    last_alert = alerts[-1] if alerts else None

    critical_count = sum(1 for row in rows if row.get("severity") == "critical")
    warning_count = sum(1 for row in rows if row.get("severity") == "warning")

    return {
        "status": "ok",
        "module": "intrusion_detector",
        "last_snapshot": last_snapshot,
        "last_alert": last_alert,
        "recent_warning_count": warning_count,
        "recent_critical_count": critical_count,
    }


@app.get("/ids/alerts")
def ids_alerts(
    limit: int = 50,
    severity: str | None = None,
    _claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    capped = max(1, min(limit, 500))
    requested_severity = severity.lower() if severity else None
    allowed = {None, "info", "warning", "critical"}
    if requested_severity not in allowed:
        raise HTTPException(status_code=400, detail="Invalid severity filter")

    events = latest_ids_events(limit=capped, severity=requested_severity)
    return {
        "status": "ok",
        "count": len(events),
        "events": events,
    }


@app.get("/monitoring/status")
def monitoring_status(
    _claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    rows = latest_module_events(module_name="monitoring_agent", limit=200)
    snapshots = [row for row in rows if row.get("event") == "host_snapshot"]
    alerts = [row for row in rows if row.get("severity") in {"warning", "critical"}]

    return {
        "status": "ok",
        "module": "monitoring_agent",
        "last_snapshot": snapshots[-1] if snapshots else None,
        "last_alert": alerts[-1] if alerts else None,
        "recent_warning_count": sum(
            1 for row in rows if row.get("severity") == "warning"
        ),
        "recent_critical_count": sum(
            1 for row in rows if row.get("severity") == "critical"
        ),
    }


@app.get("/monitoring/events")
def monitoring_events(
    limit: int = 50,
    severity: str | None = None,
    _claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    capped = max(1, min(limit, 500))
    requested_severity = severity.lower() if severity else None
    allowed = {None, "info", "warning", "critical"}
    if requested_severity not in allowed:
        raise HTTPException(status_code=400, detail="Invalid severity filter")

    events = latest_module_events(
        module_name="monitoring_agent",
        limit=capped,
        severity=requested_severity,
    )
    return {
        "status": "ok",
        "count": len(events),
        "events": events,
    }


@app.get("/cpanel/status")
def cpanel_status(
    tenant: str | None = None,
    claims: dict[str, Any] = Depends(verify_token),
) -> dict[str, Any]:
    requested_tenant = (tenant or _tenant_from_claims(claims)).strip() or "global"
    enforce_abac(action="cpanel.status.read", claims=claims, tenant=requested_tenant)
    if not _tenant_allowed(claims, requested_tenant):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    modules = [
        "sentinel_01",
        "arp_detector",
        "wifi_analyzer",
        "intrusion_detector",
        "monitoring_agent",
        "stream_processor",
    ]
    module_summary: dict[str, Any] = {}

    for module_name in modules:
        rows = EVENT_STORAGE.latest_events(
            limit=50,
            module_name=module_name,
            business_filter=requested_tenant,
        )
        module_summary[module_name] = {
            "event_count": len(rows),
            "last_event": rows[-1] if rows else None,
            "warning_count": sum(1 for row in rows if row.get("severity") == "warning"),
            "critical_count": sum(
                1 for row in rows if row.get("severity") == "critical"
            ),
        }

    total_events = EVENT_STORAGE.count_events(business=requested_tenant)

    return {
        "status": "ok",
        "tenant": requested_tenant,
        "telemetry_port": TELEMETRY_PORT,
        "db_path": str(DB_PATH),
        "db_events_total": total_events,
        "modules": module_summary,
    }


@app.post("/cpanel/action")
def cpanel_action(
    action: str,
    tenant: str | None = None,
    claims: dict[str, Any] = Depends(require_clearance(2)),
) -> dict[str, Any]:
    requested_tenant = (tenant or _tenant_from_claims(claims)).strip() or "global"
    enforce_abac(action="cpanel.action", claims=claims, tenant=requested_tenant)
    if not _tenant_allowed(claims, requested_tenant):
        raise HTTPException(status_code=403, detail="Tenant action denied")

    normalized = action.strip().lower()
    allowed = {
        "smoke_test",
        "refresh_audit",
        "daily_report",
    }
    if normalized not in allowed:
        raise HTTPException(status_code=400, detail="Unsupported cpanel action")

    EVENT_STORAGE.persist_event(
        {
            "module": "cpanel",
            "event": "action_dispatched",
            "severity": "info",
            "tenant_id": requested_tenant,
            "payload": {"action": normalized, "tenant": requested_tenant},
        },
        business=requested_tenant,
    )
    track_usage(
        tenant_id=requested_tenant,
        metric="cpanel.action",
        value=1.0,
        meta={"action": normalized},
        storage=EVENT_STORAGE,
    )

    celery_enabled = (
        os.getenv("SHADOW_CELERY_ENABLED", "false").strip().lower() == "true"
        and celery_app is not None
    )

    if celery_enabled:
        if normalized == "daily_report":
            task = daily_report_task.delay()
        elif normalized == "refresh_audit":
            task = refresh_audit_task.delay()
        else:
            task = smoke_test_task.delay()

        EVENT_STORAGE.persist_event(
            {
                "module": "cpanel",
                "event": "action_queued",
                "severity": "info",
                "tenant_id": requested_tenant,
                "payload": {
                    "action": normalized,
                    "tenant": requested_tenant,
                    "task_id": task.id,
                },
            },
            business=requested_tenant,
        )

        return {
            "status": "ok",
            "tenant": requested_tenant,
            "action": normalized,
            "queued": True,
            "task_id": task.id,
        }

    if normalized == "daily_report":
        stats = DailyReporter().dispatch_reports()
        return {
            "status": "ok",
            "tenant": requested_tenant,
            "action": normalized,
            "result": stats,
        }

    return {
        "status": "ok",
        "tenant": requested_tenant,
        "action": normalized,
        "result": "accepted",
    }


@app.get("/cpanel/task/{task_id}")
def cpanel_task_status(
    task_id: str,
    tenant: str | None = None,
    claims: dict[str, Any] = Depends(require_clearance(2)),
) -> dict[str, Any]:
    requested_tenant = (tenant or _tenant_from_claims(claims)).strip() or "global"
    enforce_abac(action="cpanel.task.read", claims=claims, tenant=requested_tenant)
    if not _tenant_allowed(claims, requested_tenant):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    if celery_app is None:
        raise HTTPException(status_code=503, detail="Celery is unavailable")

    task = celery_app.AsyncResult(task_id)

    payload: dict[str, Any] = {
        "status": "ok",
        "tenant": requested_tenant,
        "task_id": task_id,
        "state": task.state,
        "ready": bool(task.ready()),
        "successful": bool(task.successful()) if task.ready() else False,
    }

    if task.ready():
        if task.successful():
            payload["result"] = task.result
        else:
            payload["error"] = str(task.result)

    return payload


@app.get("/cpanel/tasks")
def cpanel_recent_tasks(
    limit: int = 10,
    tenant: str | None = None,
    include_live_state: bool = True,
    claims: dict[str, Any] = Depends(require_clearance(2)),
) -> dict[str, Any]:
    requested_tenant = (tenant or _tenant_from_claims(claims)).strip() or "global"
    enforce_abac(action="cpanel.task.read", claims=claims, tenant=requested_tenant)
    if not _tenant_allowed(claims, requested_tenant):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    capped = max(1, min(limit, 100))
    rows = EVENT_STORAGE.latest_events(
        limit=500,
        module_name="cpanel",
        business_filter=requested_tenant,
    )
    queued = [row for row in rows if row.get("event") == "action_queued"]
    queued = queued[-capped:]

    tasks: list[dict[str, Any]] = []
    for row in queued:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        item: dict[str, Any] = {
            "timestamp": row.get("timestamp"),
            "tenant": row.get("business") or requested_tenant,
            "action": payload.get("action", "unknown"),
            "task_id": payload.get("task_id", ""),
        }

        task_id = str(item["task_id"] or "").strip()
        if include_live_state and task_id and celery_app is not None:
            task = celery_app.AsyncResult(task_id)
            item["state"] = task.state
            item["ready"] = bool(task.ready())
            item["successful"] = bool(task.successful()) if task.ready() else False
        tasks.append(item)

    return {
        "status": "ok",
        "tenant": requested_tenant,
        "count": len(tasks),
        "tasks": tasks,
    }


@app.get("/billing/usage")
def billing_usage_summary(
    tenant: str | None = None,
    claims: dict[str, Any] = Depends(require_clearance(4)),
) -> dict[str, Any]:
    requested_tenant = (tenant or _tenant_from_claims(claims)).strip() or "global"
    enforce_abac(action="billing.usage.read", claims=claims, tenant=requested_tenant)
    is_global_scope = requested_tenant.lower() in {"all", "*"}

    if not is_global_scope and not _tenant_allowed(claims, requested_tenant):
        raise HTTPException(status_code=403, detail="Tenant access denied")

    summary = EVENT_STORAGE.usage_summary(
        None if is_global_scope else requested_tenant,
    )
    return {
        "status": "ok",
        "tenant": "all" if is_global_scope else requested_tenant,
        "entries": summary,
    }


@app.get("/audit/verify")
def verify_immutable_audit_log(
    tenant: str | None = None,
    claims: dict[str, Any] = Depends(require_clearance(4)),
) -> dict[str, Any]:
    requested_tenant = (tenant or _tenant_from_claims(claims)).strip() or "global"
    is_global_scope = requested_tenant.lower() in {"all", "*"}
    effective_tenant = None if is_global_scope else requested_tenant

    enforce_abac(
        action="audit.verify",
        claims=claims,
        tenant=requested_tenant,
    )
    result = EVENT_STORAGE.verify_audit_chain(effective_tenant)
    return {
        "status": "ok" if result.get("ok") else "tamper-detected",
        "tenant": "all" if is_global_scope else requested_tenant,
        "result": result,
    }


@app.get("/audit/chain-tips")
def audit_chain_tips(
    claims: dict[str, Any] = Depends(require_clearance(4)),
) -> dict[str, Any]:
    enforce_abac(action="audit.verify", claims=claims, tenant="all")
    verification = EVENT_STORAGE.verify_audit_chain(None)
    details = verification.get("details", []) if isinstance(verification, dict) else []
    tips = [
        {
            "tenant": item.get("tenant", "global"),
            "ok": bool(item.get("ok", False)),
            "chain_tip": item.get("chain_tip", ""),
            "records": int(item.get("records", 0) or 0),
        }
        for item in details
        if isinstance(item, dict)
    ]
    return {
        "status": "ok",
        "count": len(tips),
        "tips": tips,
    }


@app.get("/abac/metrics")
def abac_metrics(
    claims: dict[str, Any] = Depends(require_clearance(4)),
) -> dict[str, Any]:
    enforce_abac(action="audit.verify", claims=claims, tenant="all")
    in_memory = get_abac_metrics()
    persisted = EVENT_STORAGE.abac_deny_summary(None)

    combined_total = int(in_memory.get("deny_total", 0) or 0) + int(
        persisted.get("deny_total", 0) or 0
    )
    combined_by_action: dict[str, int] = {}
    for source in (
        in_memory.get("deny_by_action", {}),
        persisted.get("deny_by_action", {}),
    ):
        for action, count in source.items():
            key = str(action or "unknown")
            combined_by_action[key] = combined_by_action.get(key, 0) + int(count or 0)

    return {
        "status": "ok",
        "metrics": {
            "deny_total": combined_total,
            "deny_by_action": combined_by_action,
            "memory": in_memory,
            "persisted": persisted,
        },
    }


@app.post("/abac/metrics/reset")
def reset_abac_metrics_in_memory(
    claims: dict[str, Any] = Depends(require_clearance(5)),
) -> dict[str, Any]:
    enforce_abac(action="audit.verify", claims=claims, tenant="all")
    EVENT_STORAGE.persist_event(
        {
            "module": "governance",
            "event": "abac_memory_reset",
            "severity": "info",
            "tenant_id": "global",
            "payload": {
                "actor": str(
                    claims.get("preferred_username") or claims.get("sub") or "unknown"
                ),
                "auth_mode": str(claims.get("auth_mode") or "unknown"),
            },
        },
        business="global",
    )
    actor = str(claims.get("preferred_username") or claims.get("sub") or "unknown")
    memory_after_reset = reset_abac_metrics(actor=actor)
    persisted = EVENT_STORAGE.abac_deny_summary(None)
    combined_total = int(memory_after_reset.get("deny_total", 0) or 0) + int(
        persisted.get("deny_total", 0) or 0
    )
    combined_by_action: dict[str, int] = {}
    for source in (
        memory_after_reset.get("deny_by_action", {}),
        persisted.get("deny_by_action", {}),
    ):
        for action, count in source.items():
            key = str(action or "unknown")
            combined_by_action[key] = combined_by_action.get(key, 0) + int(count or 0)

    return {
        "status": "ok",
        "message": "In-memory ABAC deny counters reset. Persisted history preserved.",
        "last_reset_by": memory_after_reset.get("last_reset_by", ""),
        "last_reset_at": memory_after_reset.get("last_reset_at", ""),
        "metrics": {
            "deny_total": combined_total,
            "deny_by_action": combined_by_action,
            "memory": memory_after_reset,
            "persisted": persisted,
        },
    }


@app.post("/maintenance/daily-report")
def run_daily_report_now(
    _claims: dict[str, Any] = Depends(require_clearance(2)),
) -> dict[str, object]:
    """Run daily report cycle immediately (authenticated)."""
    stats = DailyReporter().dispatch_reports()
    return {"status": "ok", "stats": stats}


@app.get("/forensics/pcaps")
def get_forensics_pcaps(
    _claims: dict[str, Any] = Depends(require_clearance(3)),
) -> dict[str, object]:
    """ABAC-protected sample endpoint for sensitive forensic data."""
    enforce_abac(
        action="forensics.pcaps.read",
        claims=_claims,
        tenant=_tenant_from_claims(_claims),
    )
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
async def ws_telemetry_bridge(
    websocket: WebSocket, access_token: str | None = None
) -> None:
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


@app.websocket("/ws/ids")
async def ws_ids(websocket: WebSocket, access_token: str | None = None) -> None:
    try:
        verify_websocket_token(access_token)
    except HTTPException:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    last_event_id = 0

    try:
        initial = latest_ids_events(limit=1)
        if initial:
            latest = initial[-1]
            await websocket.send_json({k: v for k, v in latest.items() if k != "id"})
            last_event_id = int(latest["id"])

        while True:
            latest_batch = latest_ids_events(limit=1)
            if latest_batch:
                candidate = latest_batch[-1]
                if int(candidate["id"]) > last_event_id:
                    await websocket.send_json(
                        {k: v for k, v in candidate.items() if k != "id"}
                    )
                    last_event_id = int(candidate["id"])
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception:
        await websocket.close()


if __name__ == "__main__":
    run_dashboard_server()
