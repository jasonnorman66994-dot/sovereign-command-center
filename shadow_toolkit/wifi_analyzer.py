#!/usr/bin/env python3
"""
WiFi Network Analyzer
=====================
Scan nearby WiFi networks, detect channel congestion,
identify rogue APs, and assess encryption strength.
Uses Windows 'netsh wlan' commands under the hood.
"""

import subprocess
import re
import sys
import platform
from datetime import datetime
from collections import defaultdict


def scan_networks_windows():
    """Scan WiFi networks using netsh (Windows)."""
    networks = []
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=Bssid"],
            capture_output=True, text=True, timeout=30, encoding="utf-8", errors="replace"
        )
        if result.returncode != 0:
            print(f"  [!] netsh error: {result.stderr.strip()}")
            return networks

        if not result.stdout:
            print("  [!] No output from netsh")
            return networks

        current = {}
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("SSID") and "BSSID" not in line:
                if current:
                    networks.append(current)
                match = re.match(r"SSID\s+\d+\s*:\s*(.*)", line)
                current = {"ssid": match.group(1).strip() if match else "Hidden"}
            elif line.startswith("Network type"):
                current["type"] = line.split(":")[1].strip()
            elif line.startswith("Authentication"):
                current["auth"] = line.split(":")[1].strip()
            elif line.startswith("Encryption"):
                current["encryption"] = line.split(":")[1].strip()
            elif line.startswith("BSSID"):
                match = re.match(r"BSSID\s+\d+\s*:\s*(.*)", line)
                current["bssid"] = match.group(1).strip() if match else "Unknown"
            elif line.startswith("Signal"):
                match = re.search(r"(\d+)%", line)
                current["signal"] = int(match.group(1)) if match else 0
            elif line.startswith("Channel"):
                match = re.search(r"(\d+)", line.split(":")[1])
                current["channel"] = int(match.group(1)) if match else 0

        if current:
            networks.append(current)

    except FileNotFoundError:
        print("  [!] netsh not found. Windows only.")
    except subprocess.TimeoutExpired:
        print("  [!] WiFi scan timed out")
    return networks


def scan_networks_linux():
    """Scan WiFi networks using iwlist/nmcli (Linux)."""
    networks = []
    try:
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,CHAN,SECURITY", "dev", "wifi", "list", "--rescan", "yes"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"  [!] nmcli error: {result.stderr.strip()}")
            return networks

        for line in result.stdout.strip().splitlines():
            parts = line.split(":")
            if len(parts) >= 5:
                networks.append({
                    "ssid": parts[0] or "Hidden",
                    "bssid": ":".join(parts[1:7]) if len(parts) > 6 else parts[1],
                    "signal": int(parts[-3]) if parts[-3].isdigit() else 0,
                    "channel": int(parts[-2]) if parts[-2].isdigit() else 0,
                    "auth": parts[-1],
                    "encryption": parts[-1],
                })
    except FileNotFoundError:
        print("  [!] nmcli not found. Install NetworkManager.")
    except subprocess.TimeoutExpired:
        print("  [!] WiFi scan timed out")
    return networks


def get_current_connection():
    """Get current WiFi connection details."""
    if platform.system() == "Windows":
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=15, encoding="utf-8", errors="replace"
            )
            info = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if "SSID" in line and "BSSID" not in line:
                    info["ssid"] = line.split(":")[1].strip() if ":" in line else ""
                elif "BSSID" in line:
                    info["bssid"] = line.split(":", 1)[1].strip() if ":" in line else ""
                elif "Signal" in line:
                    m = re.search(r"(\d+)%", line)
                    info["signal"] = int(m.group(1)) if m else 0
                elif "Channel" in line:
                    m = re.search(r"(\d+)", line.split(":")[1])
                    info["channel"] = int(m.group(1)) if m else 0
                elif "Authentication" in line:
                    info["auth"] = line.split(":")[1].strip() if ":" in line else ""
                elif "Receive rate" in line:
                    info["rx_rate"] = line.split(":")[1].strip() if ":" in line else ""
                elif "Transmit rate" in line:
                    info["tx_rate"] = line.split(":")[1].strip() if ":" in line else ""
            return info
        except Exception:
            return None
    return None


def assess_security(network: dict) -> tuple:
    """Assess security strength of a network. Returns (rating, color, notes)."""
    auth = network.get("auth", "").lower()
    enc = network.get("encryption", "").lower()

    if "wpa3" in auth:
        return "STRONG", "green", "WPA3 - Excellent"
    elif "wpa2" in auth and ("aes" in enc or "ccmp" in enc):
        return "GOOD", "green", "WPA2-AES"
    elif "wpa2" in auth:
        return "FAIR", "yellow", "WPA2 (check cipher)"
    elif "wpa" in auth:
        return "WEAK", "red", "WPA1 - Deprecated"
    elif "wep" in auth:
        return "CRITICAL", "red", "WEP - Trivially crackable"
    elif "open" in auth or not auth:
        return "NONE", "red", "OPEN - No encryption"
    else:
        return "UNKNOWN", "yellow", f"Auth: {auth}"


def analyze_channels(networks: list) -> dict:
    """Analyze channel congestion."""
    channel_map = defaultdict(list)
    for net in networks:
        ch = net.get("channel", 0)
        if ch > 0:
            channel_map[ch].append(net.get("ssid", "Hidden"))

    analysis = {}
    for ch, ssids in sorted(channel_map.items()):
        congestion = "Low" if len(ssids) <= 2 else ("Medium" if len(ssids) <= 5 else "High")
        analysis[ch] = {"count": len(ssids), "congestion": congestion, "networks": ssids}
    return analysis


def detect_rogue_aps(networks: list) -> list:
    """Detect potential rogue APs (duplicate SSIDs with different BSSIDs/encryption)."""
    ssid_groups = defaultdict(list)
    for net in networks:
        ssid = net.get("ssid", "")
        if ssid and ssid != "Hidden":
            ssid_groups[ssid].append(net)

    rogues = []
    for ssid, nets in ssid_groups.items():
        if len(nets) > 1:
            encryptions = set(n.get("encryption", "") for n in nets)
            if len(encryptions) > 1:
                rogues.append({
                    "ssid": ssid,
                    "count": len(nets),
                    "reason": f"Multiple encryption types: {', '.join(encryptions)}",
                    "networks": nets,
                })
    return rogues


def display_results(networks, channels, rogues, conn_info):
    """Display scan results."""
    print(f"\n  {'='*60}")
    print(f"  WiFi Analysis Report — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {'='*60}")

    # Current connection
    if conn_info:
        print(f"\n  [Connected Network]")
        print(f"    SSID:    {conn_info.get('ssid', 'N/A')}")
        print(f"    BSSID:   {conn_info.get('bssid', 'N/A')}")
        print(f"    Signal:  {conn_info.get('signal', 'N/A')}%")
        print(f"    Channel: {conn_info.get('channel', 'N/A')}")
        print(f"    Auth:    {conn_info.get('auth', 'N/A')}")
        if conn_info.get("rx_rate"):
            print(f"    RX Rate: {conn_info['rx_rate']}")
        if conn_info.get("tx_rate"):
            print(f"    TX Rate: {conn_info['tx_rate']}")

    # All networks
    print(f"\n  [Discovered Networks: {len(networks)}]")
    print(f"  {'─'*75}")
    print(f"  {'SSID':<25} {'BSSID':<20} {'Ch':>3} {'Signal':>7} {'Security':<15} {'Rating'}")
    print(f"  {'─'*75}")

    for net in sorted(networks, key=lambda x: x.get("signal", 0), reverse=True):
        rating, _, note = assess_security(net)
        signal = f"{net.get('signal', 0)}%"
        ssid = net.get("ssid", "Hidden")[:24]
        bssid = net.get("bssid", "??:??:??")
        ch = net.get("channel", "?")
        enc = net.get("encryption", "?")[:14]
        print(f"  {ssid:<25} {bssid:<20} {ch:>3} {signal:>7} {enc:<15} [{rating}]")

    # Channel analysis
    print(f"\n  [Channel Congestion]")
    print(f"  {'─'*50}")
    for ch, info in sorted(channels.items()):
        bar = "█" * info["count"] + "░" * (10 - min(info["count"], 10))
        print(f"    Ch {ch:>3}: [{bar}] {info['count']:>2} networks ({info['congestion']})")

    # Rogue AP detection
    if rogues:
        print(f"\n  [⚠ Potential Rogue APs Detected: {len(rogues)}]")
        print(f"  {'─'*50}")
        for rogue in rogues:
            print(f"    SSID: {rogue['ssid']}")
            print(f"    Instances: {rogue['count']}")
            print(f"    Reason: {rogue['reason']}")
            for n in rogue["networks"]:
                print(f"      - BSSID: {n.get('bssid', '?')} | Enc: {n.get('encryption', '?')} | Signal: {n.get('signal', '?')}%")
            print()
    else:
        print(f"\n  [✓] No rogue APs detected")

    # Security summary
    ratings = defaultdict(int)
    for net in networks:
        r, _, _ = assess_security(net)
        ratings[r] += 1

    print(f"\n  [Security Summary]")
    print(f"  {'─'*30}")
    for rating in ["STRONG", "GOOD", "FAIR", "WEAK", "CRITICAL", "NONE", "UNKNOWN"]:
        if ratings[rating] > 0:
            print(f"    {rating:<12}: {ratings[rating]}")


def run_wifi_analyzer(args=None):
    """Entry point for WiFi analyzer."""
    print("\n  [*] Shadow Toolkit — WiFi Network Analyzer")
    print("  [*] Scanning nearby networks...\n")

    if platform.system() == "Windows":
        networks = scan_networks_windows()
    else:
        networks = scan_networks_linux()

    if not networks:
        print("  [!] No networks found. Check WiFi adapter is enabled.")
        return {"networks": [], "channels": {}, "rogues": []}

    conn_info = get_current_connection()
    channels = analyze_channels(networks)
    rogues = detect_rogue_aps(networks)

    display_results(networks, channels, rogues, conn_info)

    print(f"\n  [*] Scan complete — {len(networks)} networks analyzed")

    return {"networks": networks, "channels": channels, "rogues": rogues}


if __name__ == "__main__":
    run_wifi_analyzer()
