import time
from datetime import datetime
from pathlib import Path

from core.bus import TelemetryBus


def run() -> None:
    bus = TelemetryBus()
    module_id = "sentinel_01"
    local_log = Path("modules/sentinel/sentinel_local.log")
    local_log.parent.mkdir(parents=True, exist_ok=True)

    with local_log.open("a", encoding="utf-8") as handle:
        handle.write(f"[{datetime.now().isoformat()}] Sentinel initializing\n")
        handle.flush()

        while True:
            status_data = {
                "uptime": 100.0,
                "gateway_status": "active",
                "active_nodes": 4,
            }
            bus.publish(
                module_name=module_id,
                event_type="heartbeat",
                data=status_data,
                severity="info",
            )
            handle.write(f"[{datetime.now().isoformat()}] Heartbeat dispatched\n")
            handle.flush()
            time.sleep(10)
