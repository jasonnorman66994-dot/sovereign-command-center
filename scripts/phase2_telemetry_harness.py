#!/usr/bin/env python3
"""
Phase 2 telemetry harness

Publishes synthetic API/Kubernetes findings, persists them into data/telemetry.db,
and validates collector routing behavior for warning/critical severities.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import time
from pathlib import Path

import zmq

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.bus import TelemetryBus, create_subscriber
from core.collector import DB_PATH, _handle_notifications, init_db, persist_event
from core.schema import TelemetryPacket


class HarnessNotificationHub:
    """In-memory channel recorder for routing assertions."""

    def __init__(self) -> None:
        self.calls: dict[str, list[tuple[str, str]]] = {
            "slack": [],
            "email": [],
            "telegram": [],
        }

    def send_slack(self, message: str, dedupe_key: str = "global") -> bool:
        self.calls["slack"].append((message, dedupe_key))
        return True

    def send_email(self, subject: str, body: str, dedupe_key: str = "global") -> bool:
        self.calls["email"].append((subject, dedupe_key))
        return True

    def send_telegram(self, message: str, dedupe_key: str = "global") -> bool:
        self.calls["telegram"].append((message, dedupe_key))
        return True


def _count_phase2_rows(db_path: Path) -> int:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.execute(
            """
            SELECT COUNT(*)
            FROM events
            WHERE module IN ('api_security_tester', 'kubernetes_pod_analyzer')
            """
        )
        row = cur.fetchone()
        return int(row[0]) if row else 0
    finally:
        conn.close()


def _consume_and_route(
    socket: zmq.Socket,
    expected_events: int,
    hub: HarnessNotificationHub,
    timeout_seconds: float = 5.0,
) -> int:
    """Consume telemetry packets and run the same persistence + routing path as collector."""
    received = 0
    end_time = time.time() + timeout_seconds

    while received < expected_events and time.time() < end_time:
        if socket.poll(timeout=250, flags=zmq.POLLIN) == 0:
            continue

        topic, payload_bytes = socket.recv_multipart(flags=0)
        if topic.decode("utf-8") != "telemetry":
            continue

        payload = json.loads(payload_bytes.decode("utf-8"))
        packet = TelemetryPacket.model_validate(payload)
        persist_event(packet.model_dump(mode="json"), business="global")
        _handle_notifications(hub, packet, business_hub=None)
        received += 1

    return received


def _publish_synthetic_events(bus: TelemetryBus) -> None:
    """Publish one warning and one critical synthetic event."""
    bus.publish(
        module_name="api_security_tester",
        event_type="unauthenticated_operation",
        severity="warning",
        data={
            "target": "POST /v1/profile/update",
            "finding_type": "unauthenticated_operation",
            "evidence": "Operation has no security requirements",
        },
    )

    bus.publish(
        module_name="kubernetes_pod_analyzer",
        event_type="privileged_container",
        severity="critical",
        data={
            "namespace": "prod",
            "pod": "profile-api-7d4b5",
            "finding_type": "privileged_container",
            "evidence": "securityContext.privileged=true",
        },
    )


def main() -> int:
    init_db(DB_PATH)
    before_count = _count_phase2_rows(DB_PATH)

    port = 5567
    hub = HarnessNotificationHub()

    _, socket = create_subscriber(port=port, bind=True)
    socket.setsockopt(zmq.RCVTIMEO, 3000)

    bus = TelemetryBus(port=port)
    try:
        # Ensure subscriber handshake is established before first publish.
        time.sleep(0.5)

        received = 0
        deadline = time.time() + 6.0
        while received < 2 and time.time() < deadline:
            _publish_synthetic_events(bus)
            time.sleep(0.1)
            received += _consume_and_route(
                socket=socket,
                expected_events=(2 - received),
                hub=hub,
                timeout_seconds=0.8,
            )

    finally:
        bus.close()

    socket.close(linger=0)
    after_count = _count_phase2_rows(DB_PATH)

    db_delta_ok = (after_count - before_count) >= 2
    received_ok = received >= 2

    slack_calls = len(hub.calls["slack"])
    email_calls = len(hub.calls["email"])
    telegram_calls = len(hub.calls["telegram"])

    routing_ok = (
        slack_calls >= 2 and email_calls >= 1 and telegram_calls >= 1
    )

    print("Phase 2 Telemetry Harness")
    print("-------------------------")
    print(f"Events consumed: {received}")
    print(f"DB rows delta (phase2 modules): {after_count - before_count}")
    print(
        "Notification calls: "
        f"slack={slack_calls}, email={email_calls}, telegram={telegram_calls}"
    )

    if received_ok and db_delta_ok and routing_ok:
        print("RESULT: PASS")
        return 0

    print("RESULT: FAIL")
    print(
        "Checks -> "
        f"received_ok={received_ok}, db_delta_ok={db_delta_ok}, routing_ok={routing_ok}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
