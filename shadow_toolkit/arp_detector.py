#!/usr/bin/env python3
"""
ARP Spoof Detector
==================
Monitors ARP traffic to detect poisoning/MITM attacks.
Tracks MAC-IP bindings and alerts on suspicious changes.
Works on Windows (using arp -a) and Linux (raw sockets or arp).
"""

import subprocess
import platform
import re
import time
import sys
import threading
from datetime import datetime
from collections import defaultdict


class ARPMonitor:
    """Monitors ARP table for signs of spoofing."""

    def __init__(self):
        self.arp_table = {}          # ip -> {"mac": str, "first_seen": datetime, "last_seen": datetime}
        self.mac_to_ips = defaultdict(set)  # mac -> set of IPs  (one MAC = many IPs is suspicious)
        self.alerts = []
        self.history = []            # all state changes
        self.running = False
        self.gateway_ip = None
        self.gateway_mac = None

    def get_gateway(self):
        """Detect default gateway IP."""
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["ipconfig"], capture_output=True, text=True, timeout=15
                )
                for line in result.stdout.splitlines():
                    if "Default Gateway" in line:
                        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if match:
                            self.gateway_ip = match.group(1)
                            return self.gateway_ip
            else:
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=15
                )
                match = re.search(r"via\s+(\d+\.\d+\.\d+\.\d+)", result.stdout)
                if match:
                    self.gateway_ip = match.group(1)
                    return self.gateway_ip
        except Exception as e:
            print(f"  [!] Could not detect gateway: {e}")
        return None

    def get_arp_table(self) -> list:
        """Read current ARP table from OS."""
        entries = []
        try:
            if platform.system() == "Windows":
                result = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=15
                )
                for line in result.stdout.splitlines():
                    match = re.match(
                        r"\s*(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2}[:-]"
                        r"[\da-fA-F]{2}[:-][\da-fA-F]{2}[:-][\da-fA-F]{2})\s+(\w+)",
                        line
                    )
                    if match:
                        entries.append({
                            "ip": match.group(1),
                            "mac": match.group(2).lower().replace("-", ":"),
                            "type": match.group(3),
                        })
            else:
                result = subprocess.run(
                    ["arp", "-n"], capture_output=True, text=True, timeout=15
                )
                for line in result.stdout.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[2].lower() if parts[1] == "ether" else parts[1].lower()
                        if re.match(r"[\da-f]{2}:", mac):
                            entries.append({"ip": ip, "mac": mac, "type": "dynamic"})
        except Exception as e:
            print(f"  [!] ARP table read error: {e}")
        return entries

    def check_entry(self, entry: dict):
        """Check a single ARP entry for anomalies."""
        ip = entry["ip"]
        mac = entry["mac"]
        now = datetime.now()

        # Skip broadcast / incomplete
        if mac in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return

        if ip in self.arp_table:
            old_mac = self.arp_table[ip]["mac"]
            if old_mac != mac:
                # MAC changed for this IP — possible ARP spoofing
                alert = {
                    "time": now.strftime("%H:%M:%S"),
                    "type": "MAC_CHANGE",
                    "severity": "HIGH" if ip == self.gateway_ip else "MEDIUM",
                    "ip": ip,
                    "old_mac": old_mac,
                    "new_mac": mac,
                    "msg": f"IP {ip} changed MAC: {old_mac} → {mac}",
                }
                if ip == self.gateway_ip:
                    alert["msg"] += " [GATEWAY — Possible MITM!]"
                    alert["severity"] = "CRITICAL"
                self.alerts.append(alert)
                self.history.append(alert)
                self._print_alert(alert)

                self.arp_table[ip]["mac"] = mac
                self.arp_table[ip]["last_seen"] = now
            else:
                self.arp_table[ip]["last_seen"] = now
        else:
            self.arp_table[ip] = {"mac": mac, "first_seen": now, "last_seen": now}

        # Track MAC -> IPs mapping
        self.mac_to_ips[mac].add(ip)
        if len(self.mac_to_ips[mac]) > 3:
            # One MAC claiming lots of IPs — likely ARP spoofing
            ips_list = ", ".join(sorted(self.mac_to_ips[mac]))
            alert = {
                "time": now.strftime("%H:%M:%S"),
                "type": "MAC_FLOOD",
                "severity": "HIGH",
                "ip": ip,
                "old_mac": mac,
                "new_mac": mac,
                "msg": f"MAC {mac} claims {len(self.mac_to_ips[mac])} IPs: {ips_list}",
            }
            # Deduplicate: only alert if count crossed threshold just now or every 5 new IPs
            count = len(self.mac_to_ips[mac])
            if count == 4 or count % 5 == 0:
                self.alerts.append(alert)
                self.history.append(alert)
                self._print_alert(alert)

    def _print_alert(self, alert: dict):
        """Print an alert to console."""
        sev = alert["severity"]
        prefix = {
            "CRITICAL": "  [!!!]",
            "HIGH": "  [!!]",
            "MEDIUM": "  [!]",
            "LOW": "  [*]",
        }.get(sev, "  [?]")
        print(f"{prefix} [{alert['time']}] {sev}: {alert['msg']}")

    def check_duplicate_gateways(self, entries: list):
        """Check if multiple MACs claim to be the gateway."""
        if not self.gateway_ip:
            return
        gw_macs = set()
        for e in entries:
            if e["ip"] == self.gateway_ip:
                gw_macs.add(e["mac"])
        if len(gw_macs) > 1:
            alert = {
                "time": datetime.now().strftime("%H:%M:%S"),
                "type": "DUPLICATE_GATEWAY",
                "severity": "CRITICAL",
                "ip": self.gateway_ip,
                "old_mac": ", ".join(gw_macs),
                "new_mac": "",
                "msg": f"MULTIPLE MACs for gateway {self.gateway_ip}: {', '.join(gw_macs)}",
            }
            self.alerts.append(alert)
            self._print_alert(alert)

    def scan_once(self):
        """Perform a single ARP table scan."""
        entries = self.get_arp_table()
        for entry in entries:
            self.check_entry(entry)
        self.check_duplicate_gateways(entries)
        return entries

    def monitor(self, duration: int = 60, interval: float = 2.0):
        """Continuously monitor ARP table for the given duration (seconds)."""
        self.running = True
        end_time = time.time() + duration

        # Initial scan to populate baseline
        print(f"  [*] Building ARP baseline...")
        entries = self.scan_once()
        print(f"  [*] Baseline: {len(entries)} entries, Gateway: {self.gateway_ip or 'unknown'}")
        if self.gateway_ip and self.gateway_ip in self.arp_table:
            self.gateway_mac = self.arp_table[self.gateway_ip]["mac"]
            print(f"  [*] Gateway MAC: {self.gateway_mac}")
        print(f"  [*] Monitoring for {duration}s (interval: {interval}s)...")
        print(f"  [*] Press Ctrl+C to stop\n")

        scan_count = 0
        try:
            while self.running and time.time() < end_time:
                time.sleep(interval)
                self.scan_once()
                scan_count += 1
                remaining = int(end_time - time.time())
                if scan_count % 5 == 0:
                    print(f"  [·] {remaining}s remaining | {len(self.arp_table)} hosts | {len(self.alerts)} alerts")
        except KeyboardInterrupt:
            print("\n  [*] Stopped by user")
        finally:
            self.running = False

    def get_summary(self) -> dict:
        """Get monitoring summary."""
        return {
            "total_hosts": len(self.arp_table),
            "total_alerts": len(self.alerts),
            "critical": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
            "high": sum(1 for a in self.alerts if a["severity"] == "HIGH"),
            "medium": sum(1 for a in self.alerts if a["severity"] == "MEDIUM"),
            "gateway_ip": self.gateway_ip,
            "gateway_mac": self.gateway_mac,
            "arp_table": dict(self.arp_table),
            "alerts": list(self.alerts),
        }


def display_summary(monitor: ARPMonitor):
    """Display final monitoring summary."""
    summary = monitor.get_summary()
    print(f"\n  {'='*55}")
    print(f"  ARP Monitor Summary")
    print(f"  {'='*55}")
    print(f"    Hosts tracked:    {summary['total_hosts']}")
    print(f"    Gateway:          {summary['gateway_ip']} ({summary['gateway_mac'] or '?'})")
    print(f"    Total alerts:     {summary['total_alerts']}")
    print(f"      Critical:       {summary['critical']}")
    print(f"      High:           {summary['high']}")
    print(f"      Medium:         {summary['medium']}")

    if summary['alerts']:
        print(f"\n  [Alert Log]")
        print(f"  {'─'*55}")
        for a in summary['alerts']:
            print(f"    [{a['time']}] {a['severity']}: {a['msg']}")
    else:
        print(f"\n  [✓] No spoofing detected during monitoring period")

    print(f"\n  [ARP Table Snapshot]")
    print(f"  {'─'*55}")
    print(f"  {'IP':<18} {'MAC':<20} {'First Seen':<12} {'Last Seen':<12}")
    print(f"  {'─'*55}")
    for ip, info in sorted(monitor.arp_table.items()):
        first = info["first_seen"].strftime("%H:%M:%S")
        last = info["last_seen"].strftime("%H:%M:%S")
        marker = " ← GW" if ip == monitor.gateway_ip else ""
        print(f"  {ip:<18} {info['mac']:<20} {first:<12} {last:<12}{marker}")


def run_arp_detector(args=None):
    """Entry point for ARP spoof detection."""
    print("\n  [*] Shadow Toolkit — ARP Spoof Detector")
    print("  [*] Initializing ARP monitoring...\n")

    duration = 60
    interval = 2.0
    if args:
        duration = getattr(args, "duration", 60)
        interval = getattr(args, "interval", 2.0)

    monitor = ARPMonitor()
    monitor.get_gateway()
    monitor.monitor(duration=duration, interval=interval)
    display_summary(monitor)

    return monitor.get_summary()


if __name__ == "__main__":
    run_arp_detector()
