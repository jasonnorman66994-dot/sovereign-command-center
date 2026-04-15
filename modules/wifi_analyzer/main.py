import platform
import time

from core.bus import TelemetryBus
from shadow_toolkit.wifi_analyzer import (
    analyze_channels,
    detect_rogue_aps,
    scan_networks_linux,
    scan_networks_windows,
)


def _scan_networks() -> list[dict]:
    if platform.system() == "Windows":
        return scan_networks_windows()
    return scan_networks_linux()


def run() -> None:
    bus = TelemetryBus()
    bus.publish("wifi_analyzer", "startup", {"platform": platform.system()}, severity="info")

    while True:
        networks = _scan_networks()
        channels = analyze_channels(networks)
        rogues = detect_rogue_aps(networks)
        payload = {
            "network_count": len(networks),
            "channel_count": len(channels),
            "rogue_count": len(rogues),
        }
        severity = "warning" if rogues else "info"
        bus.publish("wifi_analyzer", "scan_result", payload, severity=severity)
        time.sleep(10.0)
