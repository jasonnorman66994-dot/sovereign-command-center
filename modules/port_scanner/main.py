"""
Unauthorized Port Scanner - Daily Compliance Module

Scans business assets and flags open ports not in the approved safe list.
Runs in module mode (periodic) and can be reused by DailyReporter for on-demand audits.
"""

from __future__ import annotations

import json
import os
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from core.bus import TelemetryBus


def _load_targets(path: str = "data/targets.json") -> dict[str, Any]:
    target_path = Path(path)
    if not target_path.exists():
        return {}
    try:
        return json.loads(target_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"[port_scanner] Failed to parse targets file: {exc}")
        return {}


def _is_open(ip: str, port: int, timeout: float) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((ip, port)) == 0


def scan_host(ip: str, ports: list[int], timeout: float = 0.35, workers: int = 64) -> list[int]:
    """Return unauthorized open ports for one host (caller applies safe list)."""
    open_ports: list[int] = []
    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = {executor.submit(_is_open, ip, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue
    return sorted(open_ports)


def scan_business_assets(
    assets: list[str],
    safe_ports: list[int],
    scan_ports: list[int],
    timeout: float = 0.35,
    workers: int = 64,
) -> dict[str, list[int]]:
    """Scan all assets and return ip -> unauthorized open ports mapping."""
    unauthorized_by_host: dict[str, list[int]] = {}
    safe = set(safe_ports)
    ports = [p for p in scan_ports if 1 <= int(p) <= 65535]

    for ip in assets:
        open_ports = scan_host(ip, ports, timeout=timeout, workers=workers)
        unauthorized = [p for p in open_ports if p not in safe]
        if unauthorized:
            unauthorized_by_host[ip] = unauthorized

    return unauthorized_by_host


def run() -> None:
    """Periodic compliance scanner for unauthorized ports."""
    interval_seconds = int(os.getenv("SHADOW_PORT_SCAN_INTERVAL_SECONDS", "86400"))
    timeout = float(os.getenv("SHADOW_PORT_SCAN_TIMEOUT", "0.35"))
    workers = int(os.getenv("SHADOW_PORT_SCAN_WORKERS", "64"))
    bus = TelemetryBus()

    print("[port_scanner] Unauthorized port compliance scanner online")

    try:
        while True:
            targets = _load_targets()
            for business_name, config in targets.items():
                if not config.get("enabled", True):
                    continue

                assets = [str(ip) for ip in config.get("assets", [])]
                if not assets:
                    continue

                safe_ports = [int(p) for p in config.get("allowed_ports", [80, 443, 22])]
                scan_ports = [int(p) for p in config.get("scan_ports", list(range(1, 1025)))]
                violations = scan_business_assets(
                    assets=assets,
                    safe_ports=safe_ports,
                    scan_ports=scan_ports,
                    timeout=timeout,
                    workers=workers,
                )

                for ip, ports in violations.items():
                    bus.publish(
                        module_name="port_scanner",
                        event_type="compliance_violation",
                        severity="warning",
                        data={
                            "business": business_name,
                            "ip": ip,
                            "open_unauthorized_ports": ports,
                            "allowed_ports": safe_ports,
                        },
                    )

                bus.publish(
                    module_name="port_scanner",
                    event_type="compliance_scan_complete",
                    severity="info",
                    data={
                        "business": business_name,
                        "assets_scanned": len(assets),
                        "violating_assets": len(violations),
                    },
                )

            time.sleep(max(60, interval_seconds))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    run()
