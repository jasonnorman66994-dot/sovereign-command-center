"""
Smoke Test Module - Live Telemetry Verification

This module generates high-frequency test packets to verify the ZeroMQ-to-WebSocket
pipeline and test log rotation under load. Use for system validation before deployment.

Usage:
    shadow > start smoke_test
    # Watch the dashboard for a spike in packet rate
    # Logs should rotate once master_audit.log exceeds 5MB
"""

import time
from core.bus import TelemetryBus


def run() -> None:
    """Generate test telemetry packets at 100ms intervals."""
    bus = TelemetryBus()
    packet_count = 0

    try:
        while True:
            packet_count += 1
            bus.publish(
                module_name="SMOKE_TEST",
                event_type="pipeline_verify",
                data={"packet_id": packet_count, "load_test": True},
                severity="info",
            )
            time.sleep(0.1)  # 100ms interval = 10 packets/sec
    except KeyboardInterrupt:
        pass
    finally:
        pass


if __name__ == "__main__":
    run()
