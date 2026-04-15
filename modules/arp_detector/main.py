"""
ARP Spoof Detector - Network Integrity Monitor

Detects MAC address changes (flip-flopping) on the gateway, indicating potential
Man-in-the-Middle (MitM) attacks or ARP spoofing attempts.

Configuration: Update gateway_ip in config.yaml under arp_detector section
"""

import time
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
        print(f"[arp_detector] Failed to load config.yaml: {exc}")
        return {}


def get_mac(ip: str) -> str | None:
    """Resolve IP address to MAC address via ARP request."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc if answered_list else None
    except Exception as exc:
        print(f"[arp_detector] ARP resolution failed for {ip}: {exc}")
        return None


def run() -> None:
    """Monitor gateway MAC address for spoofing attempts."""
    bus = TelemetryBus()
    config = _load_config()
    module_cfg = config.get("arp_detector", {}) if isinstance(config, dict) else {}

    gateway_ip = module_cfg.get("gateway_ip", "192.168.1.1")
    scan_interval = int(module_cfg.get("scan_interval", 5))
    max_consecutive = int(module_cfg.get("alert_threshold", 3))
    
    print(f"[arp_detector] Initializing with gateway {gateway_ip}")
    
    # Establish baseline
    expected_mac = get_mac(gateway_ip)
    if not expected_mac:
        print(f"[arp_detector] Warning: Could not resolve gateway {gateway_ip}")
        expected_mac = None
    
    print(f"[arp_detector] Baseline MAC: {expected_mac}")
    
    consecutive_alerts = 0
    
    try:
        while True:
            current_mac = get_mac(gateway_ip)
            
            if current_mac is None:
                # Timeout or error - skip this iteration
                time.sleep(scan_interval)
                continue
            
            # Check for MAC address change (spoof indicator)
            if expected_mac and current_mac != expected_mac:
                consecutive_alerts += 1
                
                if consecutive_alerts >= max_consecutive:
                    # Publish critical alert after debounce
                    bus.publish(
                        module_name="arp_detector",
                        event_type="spoof_alert",
                        severity="critical",
                        data={
                            "gateway_ip": gateway_ip,
                            "expected_mac": expected_mac,
                            "detected_mac": current_mac,
                            "consecutive_detections": consecutive_alerts,
                        },
                    )
                    print(f"[arp_detector] ALERT: MAC flip-flop detected! Expected {expected_mac}, got {current_mac}")
                    consecutive_alerts = 0  # Reset after alert
            else:
                # MAC is stable - reset consecutive counter
                if consecutive_alerts > 0:
                    print(f"[arp_detector] Stability restored (was {consecutive_alerts} detections)")
                consecutive_alerts = 0
            
            time.sleep(scan_interval)
    except KeyboardInterrupt:
        pass
    finally:
        pass


if __name__ == "__main__":
    run()
