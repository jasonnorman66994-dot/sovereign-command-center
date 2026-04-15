import json
from typing import Any

import zmq

from core.schema import TelemetryPacket


class TelemetryBus:
    """ZeroMQ PUB/SUB wrapper for local high-throughput telemetry."""

    def __init__(self, port: int = 5555, host: str = "127.0.0.1") -> None:
        self.context = zmq.Context.instance()
        self.socket = self.context.socket(zmq.PUB)
        self.socket.connect(f"tcp://{host}:{port}")

    def publish(
        self,
        module_name: str,
        event_type: str,
        data: dict[str, Any],
        severity: str = "info",
    ) -> None:
        packet = TelemetryPacket(
            module=module_name,
            event=event_type,
            severity=severity,
            payload=data,
        )
        payload = packet.model_dump(mode="json")
        self.socket.send_multipart([
            b"telemetry",
            json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        ])

    def close(self) -> None:
        self.socket.close(linger=0)


def create_subscriber(port: int = 5555, topic: str = "telemetry", bind: bool = False) -> tuple[zmq.Context, zmq.Socket]:
    """Create and connect/bind a SUB socket to the local telemetry stream."""
    context = zmq.Context.instance()
    socket = context.socket(zmq.SUB)
    endpoint = f"tcp://127.0.0.1:{port}"
    if bind:
        socket.bind(f"tcp://*:{port}")
    else:
        socket.connect(endpoint)
    socket.setsockopt_string(zmq.SUBSCRIBE, topic)
    return context, socket
