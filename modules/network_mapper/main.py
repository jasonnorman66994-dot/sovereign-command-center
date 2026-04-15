"""
Active Network Mapper - Asset Discovery & Shadow IT Detection

Performs periodic ARP scanning on the subnet to build a device inventory.
Useful for discovering unauthorized hardware ("shadow IT") and maintaining
an asset baseline for NOC operations.

Configuration: Update target_network in config.yaml under network_mapper section
"""

import time
from collections import defaultdict
from pathlib import Path

import yaml

try:
    import scapy.all as scapy
except ImportError:
    raise RuntimeError("scapy is required. Install via: pip install scapy")

from core.bus import TelemetryBus


def _load_config() -> dict:
    """Load config.yaml if present, otherwise return empty config."""
    config_path = Path("config.yaml")
    if not config_path.exists():
        return {}
    try:
        return yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:
        print(f"[network_mapper] Failed to load config.yaml: {exc}")
        return {}


def get_devices(network_range: str) -> list[dict[str, str]]:
    """
    Scan a network range and return active devices with IP and MAC.
    
    Args:
        network_range: CIDR notation (e.g., "192.168.1.0/24")
    
    Returns:
        List of dicts with "ip" and "mac" keys
    """
    devices = []
    try:
        arp_request = scapy.ARP(pdst=network_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        for sent, received in answered_list:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc,
            })
    except Exception as exc:
        print(f"[network_mapper] Scan failed for {network_range}: {exc}")
    
    return devices


def run() -> None:
    """Continuously scan network for active devices and publish discovery events."""
    bus = TelemetryBus()
    config = _load_config()
    module_cfg = config.get("network_mapper", {}) if isinstance(config, dict) else {}

    target_network = module_cfg.get("target_network", "192.168.1.0/24")
    scan_interval = int(module_cfg.get("scan_interval", 60))
    
    print(f"[network_mapper] Initializing with target network {target_network}")
    
    last_device_count = 0
    device_history = defaultdict(list)
    
    try:
        while True:
            devices = get_devices(target_network)
            device_count = len(devices)
            
            # Track device MACs over time (detect movement/addition)
            for device in devices:
                device_history[device["ip"]].append(device["mac"])
                # Keep only last 3 observations
                if len(device_history[device["ip"]]) > 3:
                    device_history[device["ip"]].pop(0)
            
            # Publish discovery event
            severity = "info"
            
            # Alert if new devices appear (potential shadow IT)
            if device_count > last_device_count:
                severity = "warning"
                print(f"[network_mapper] New device detected! Count: {last_device_count} → {device_count}")
            elif device_count < last_device_count:
                severity = "info"
                print(f"[network_mapper] Device offline. Count: {last_device_count} → {device_count}")
            
            bus.publish(
                module_name="network_mapper",
                event_type="discovery_update",
                severity=severity,
                data={
                    "target_network": target_network,
                    "device_count": device_count,
                    "hosts": devices,
                },
            )
            
            last_device_count = device_count
            time.sleep(scan_interval)
    except KeyboardInterrupt:
        pass
    finally:
        pass


if __name__ == "__main__":
    run()
