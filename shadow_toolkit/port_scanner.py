#!/usr/bin/env python3
"""
Network Port Scanner
====================
Multi-threaded TCP/UDP port scanner with service detection and banner grabbing.
For authorized use only.
"""

import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

# Common service banners / port mappings
COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "WebSocket", 27017: "MongoDB",
}

SERVICE_PROBES = {
    "HTTP": b"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n",
    "SSH": b"",  # SSH servers send banner immediately
    "FTP": b"",  # FTP servers send banner immediately
    "SMTP": b"EHLO shadow\r\n",
    "POP3": b"",
    "IMAP": b"",
}


@dataclass
class ScanResult:
    port: int
    state: str  # "open", "closed", "filtered"
    protocol: str = "tcp"
    service: str = ""
    banner: str = ""
    version: str = ""


@dataclass
class ScanReport:
    target: str
    ip: str
    start_time: float = 0.0
    end_time: float = 0.0
    results: list = field(default_factory=list)

    @property
    def open_ports(self):
        return [r for r in self.results if r.state == "open"]

    @property
    def duration(self):
        return self.end_time - self.start_time


def parse_ports(port_str: str) -> list[int]:
    """Parse port specification like '80,443,8080' or '1-1024' or '80,443,1000-2000'."""
    ports = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.extend(range(start, min(end + 1, 65536)))
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.append(p)
    return sorted(set(ports))


def tcp_scan_port(target: str, port: int, timeout: float) -> ScanResult:
    """Scan a single TCP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result_code = sock.connect_ex((target, port))
        if result_code == 0:
            service = COMMON_SERVICES.get(port, "unknown")
            result = ScanResult(port=port, state="open", protocol="tcp", service=service)
            sock.close()
            return result
        sock.close()
        return ScanResult(port=port, state="closed", protocol="tcp")
    except socket.timeout:
        return ScanResult(port=port, state="filtered", protocol="tcp")
    except OSError:
        return ScanResult(port=port, state="filtered", protocol="tcp")


def udp_scan_port(target: str, port: int, timeout: float) -> ScanResult:
    """Scan a single UDP port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        # Send an empty UDP datagram
        sock.sendto(b"\x00", (target, port))
        try:
            data, _ = sock.recvfrom(1024)
            service = COMMON_SERVICES.get(port, "unknown")
            return ScanResult(port=port, state="open", protocol="udp", service=service, banner=data.decode(errors="replace")[:100])
        except socket.timeout:
            return ScanResult(port=port, state="open|filtered", protocol="udp", service=COMMON_SERVICES.get(port, "unknown"))
    except OSError:
        return ScanResult(port=port, state="closed", protocol="udp")
    finally:
        sock.close()


def grab_banner(target: str, port: int, service: str, timeout: float) -> tuple[str, str]:
    """Attempt to grab a service banner for version detection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout + 1)
        sock.connect((target, port))

        # Send probe if we have one, otherwise wait for banner
        probe = SERVICE_PROBES.get(service, b"")
        if probe:
            probe = probe.replace(b"{host}", target.encode())
            sock.sendall(probe)

        banner = sock.recv(1024).decode(errors="replace").strip()
        sock.close()

        # Extract version info
        version = ""
        if service == "SSH" and banner.startswith("SSH-"):
            version = banner.split("\n")[0]
        elif service == "HTTP" and "Server:" in banner:
            for line in banner.split("\n"):
                if line.startswith("Server:"):
                    version = line.split(":", 1)[1].strip()
                    break
        elif service == "FTP" and banner:
            version = banner.split("\n")[0]
        elif service == "SMTP" and banner:
            version = banner.split("\n")[0]
        elif banner:
            version = banner.split("\n")[0][:80]

        return banner[:200], version
    except Exception:
        return "", ""


def print_progress(current: int, total: int, open_count: int):
    """Print a progress bar."""
    pct = current / total * 100
    bar_len = 40
    filled = int(bar_len * current / total)
    bar = "█" * filled + "░" * (bar_len - filled)
    sys.stdout.write(f"\r  [{bar}] {pct:.1f}% | {current}/{total} ports | {open_count} open")
    sys.stdout.flush()


def run_port_scanner(args):
    """Main port scanner entry point."""
    target = args.target
    timeout = args.timeout
    thread_count = args.threads
    detect_service = args.service_detect

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"  [✗] Could not resolve hostname: {target}")
        return

    print(f"  [*] Target: {target} ({ip})")
    ports = parse_ports(args.ports)
    print(f"  [*] Scanning {len(ports)} ports with {thread_count} threads...")
    if args.udp:
        print("  [*] UDP scanning enabled (this will be slower)")
    if detect_service:
        print("  [*] Service version detection enabled")
    print()

    report = ScanReport(target=target, ip=ip, start_time=time.time())
    open_count = 0
    lock = threading.Lock()

    def scan_port(port):
        nonlocal open_count
        result = tcp_scan_port(ip, port, timeout)
        if result.state == "open" and detect_service:
            banner, version = grab_banner(ip, port, result.service, timeout)
            result.banner = banner
            result.version = version
        if result.state == "open":
            with lock:
                open_count += 1
        return result

    # TCP Scan
    completed = 0
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {executor.submit(scan_port, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result.state == "open":
                report.results.append(result)
            completed += 1
            if completed % 10 == 0 or completed == len(ports):
                print_progress(completed, len(ports), open_count)

    # UDP Scan (if enabled)
    if args.udp:
        print("\n\n  [*] Starting UDP scan...")
        completed = 0
        with ThreadPoolExecutor(max_workers=min(thread_count, 20)) as executor:
            futures = {executor.submit(udp_scan_port, ip, port, timeout + 1): port for port in ports}
            for future in as_completed(futures):
                result = future.result()
                if result.state in ("open", "open|filtered"):
                    report.results.append(result)
                completed += 1
                if completed % 10 == 0 or completed == len(ports):
                    print_progress(completed, len(ports), len([r for r in report.results if r.protocol == "udp"]))

    report.end_time = time.time()
    print("\n")

    # Print results
    print("  ┌─────────────────────────────────────────────────────────────────┐")
    print(f"  │  SCAN RESULTS - {target} ({ip})")
    print(f"  │  Duration: {report.duration:.2f}s | Open ports: {len(report.open_ports)}")
    print("  ├──────┬──────────┬─────────────┬────────────────────────────────┤")
    print("  │ PORT │ PROTOCOL │ SERVICE     │ VERSION                        │")
    print("  ├──────┼──────────┼─────────────┼────────────────────────────────┤")

    for r in sorted(report.open_ports, key=lambda x: x.port):
        port_str = str(r.port).ljust(4)
        proto = r.protocol.upper().ljust(8)
        svc = (r.service or "unknown").ljust(11)
        ver = (r.version or "").ljust(30)[:30]
        print(f"  │ {port_str} │ {proto} │ {svc} │ {ver} │")

    print("  └──────┴──────────┴─────────────┴────────────────────────────────┘")

    if not report.open_ports:
        print("  [!] No open ports found. Target may be firewalled or down.")
