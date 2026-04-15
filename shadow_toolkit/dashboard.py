#!/usr/bin/env python3
"""
Interactive TUI Dashboard
=========================
Rich terminal UI with live panels for the Shadow Toolkit.
Requires: pip install rich
"""

import sys
import time
import threading
from datetime import datetime
from pathlib import Path

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.live import Live
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.prompt import Prompt, IntPrompt
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich import box
except ImportError:
    print("  [!] Install rich: pip install rich")
    sys.exit(1)

console = Console()

BANNER = r"""[bold #6366f1]
  ____  _               _                 _____           _ _    _ _   
 / ___|| |__   __ _  __| | _____      __ |_   _|__   ___ | | | _(_) |_ 
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | |/ _ \ / _ \| | |/ / | __|
  ___) | | | | (_| | (_| | (_) \ V  V /    | | (_) | (_) | |   <| | |_ 
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/     |_|\___/ \___/|_|_|\_\_|\__|
[/]"""

MODULES = [
    ("1", "portscan", "Network Port Scanner", "Scan TCP/UDP ports with service detection"),
    ("2", "crack", "Password Hash Cracker", "Dictionary attack with mutation rules"),
    ("3", "webscan", "Web Vulnerability Scanner", "SQLi, XSS, Traversal, Headers"),
    ("4", "sniff", "Packet Sniffer", "Capture & analyze network packets"),
    ("5", "dnsenum", "DNS Enumerator", "Subdomains, records, zone transfers"),
    ("6", "detect", "Malware Detector", "Processes, persistence, hooks, network"),
    ("7", "wifi", "WiFi Analyzer", "Scan networks, detect rogue APs"),
    ("8", "arpwatch", "ARP Spoof Detector", "Detect ARP poisoning / MITM"),
    ("9", "listener", "Reverse Shell Listener", "Catch incoming reverse shells"),
    ("10", "exploitdb", "Exploit DB Search", "Search CVEs for discovered services"),
    ("S", "sovereign", "Sovereign Pulse", "Baseline, Threat-Intel, Anomaly Dashboard"),
]


def make_menu_table() -> Table:
    """Create the main menu table."""
    table = Table(
        title="[bold]Available Modules[/]",
        box=box.ROUNDED,
        border_style="#6366f1",
        title_style="bold #6366f1",
        show_lines=True,
        padding=(0, 2),
    )
    table.add_column("#", style="bold #6366f1", width=4, justify="center")
    table.add_column("Module", style="bold white", width=20)
    table.add_column("Description", style="#94a3b8", width=50)

    for num, _, name, desc in MODULES:
        table.add_row(num, name, desc)

    return table


def make_status_panel() -> Panel:
    """Create the status panel."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    import platform, socket
    info = Text()
    info.append(f"  Host: ", style="bold #94a3b8")
    info.append(f"{socket.gethostname()}\n", style="white")
    info.append(f"  OS:   ", style="bold #94a3b8")
    info.append(f"{platform.system()} {platform.release()}\n", style="white")
    info.append(f"  Time: ", style="bold #94a3b8")
    info.append(f"{now}\n", style="white")
    info.append(f"  IP:   ", style="bold #94a3b8")
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = "Unknown"
    info.append(f"{ip}", style="white")

    return Panel(info, title="[bold]System Info[/]", border_style="#1e293b", box=box.ROUNDED)


def run_module_with_progress(module_name: str, run_func, *args):
    """Run a module with a Rich progress bar."""
    with Progress(
        SpinnerColumn(style="#6366f1"),
        TextColumn("[bold]{task.description}"),
        BarColumn(bar_width=40, complete_style="#6366f1"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task(f"Running {module_name}...", total=None)
        result = run_func(*args)
        progress.update(task, completed=True)
        return result


def prompt_portscan() -> dict:
    """Interactive prompts for port scanner."""
    console.print("\n[bold #6366f1]─── Port Scanner Configuration ───[/]\n")
    target = Prompt.ask("[bold]Target IP/hostname[/]", default="127.0.0.1")
    ports = Prompt.ask("[bold]Port range[/]", default="1-1024")
    threads = IntPrompt.ask("[bold]Threads[/]", default=100)
    service_detect = Prompt.ask("[bold]Service detection?[/]", choices=["y", "n"], default="y")
    return {"target": target, "ports": ports, "threads": threads, "service_detect": service_detect == "y"}


def prompt_crack() -> dict:
    """Interactive prompts for hash cracker."""
    console.print("\n[bold #6366f1]─── Hash Cracker Configuration ───[/]\n")
    hash_val = Prompt.ask("[bold]Hash to crack[/]")
    wordlist = Prompt.ask("[bold]Wordlist path[/]")
    algo = Prompt.ask("[bold]Algorithm[/]", choices=["auto", "md5", "sha1", "sha256", "sha512", "bcrypt", "ntlm"],
                      default="auto")
    rules = Prompt.ask("[bold]Enable mutation rules?[/]", choices=["y", "n"], default="y")
    return {"hash_value": hash_val, "wordlist": wordlist, "mode": algo, "rules": rules == "y"}


def prompt_webscan() -> dict:
    """Interactive prompts for web scanner."""
    console.print("\n[bold #6366f1]─── Web Scanner Configuration ───[/]\n")
    url = Prompt.ask("[bold]Target URL[/]")
    depth = IntPrompt.ask("[bold]Crawl depth[/]", default=2)
    tests = Prompt.ask("[bold]Tests[/]", choices=["all", "sqli", "xss", "traversal", "headers"], default="all")
    return {"url": url, "depth": depth, "tests": tests}


def prompt_sniff() -> dict:
    """Interactive prompts for packet sniffer."""
    console.print("\n[bold #6366f1]─── Packet Sniffer Configuration ───[/]\n")
    count = IntPrompt.ask("[bold]Packet count (0=unlimited)[/]", default=50)
    bpf = Prompt.ask("[bold]BPF filter (empty=none)[/]", default="")
    show_hex = Prompt.ask("[bold]Show hex dump?[/]", choices=["y", "n"], default="n")
    return {"count": count, "filter": bpf, "hex": show_hex == "y"}


def prompt_dnsenum() -> dict:
    """Interactive prompts for DNS enumerator."""
    console.print("\n[bold #6366f1]─── DNS Enumerator Configuration ───[/]\n")
    domain = Prompt.ask("[bold]Target domain[/]")
    records = Prompt.ask("[bold]Enumerate records?[/]", choices=["y", "n"], default="y")
    zone = Prompt.ask("[bold]Attempt zone transfer?[/]", choices=["y", "n"], default="n")
    threads = IntPrompt.ask("[bold]Threads[/]", default=50)
    return {"domain": domain, "records": records == "y", "zone_transfer": zone == "y", "threads": threads}


def prompt_detect() -> dict:
    """Interactive prompts for malware detector."""
    console.print("\n[bold #6366f1]─── Malware Detector Configuration ───[/]\n")
    scan_all = Prompt.ask("[bold]Run all checks?[/]", choices=["y", "n"], default="y")
    if scan_all == "y":
        return {"all": True}
    procs = Prompt.ask("[bold]Scan processes?[/]", choices=["y", "n"], default="y")
    persist = Prompt.ask("[bold]Check persistence?[/]", choices=["y", "n"], default="y")
    network = Prompt.ask("[bold]Check network?[/]", choices=["y", "n"], default="y")
    hooks = Prompt.ask("[bold]Check hooks?[/]", choices=["y", "n"], default="y")
    return {"processes": procs == "y", "persistence": persist == "y",
            "network": network == "y", "hooks": hooks == "y"}


def build_args_namespace(config: dict):
    """Build an argparse-like namespace from a dict."""
    import argparse
    return argparse.Namespace(**config)


# ---------------------------------------------------------------------------
# Sovereign Pulse — Dashboard Components
# ---------------------------------------------------------------------------
SPARKLINE_CHARS = " ▁▂▃▄▅▆▇█"


def _sparkline(values: list) -> str:
    """Render a list of numbers as a Unicode sparkline string."""
    if not values:
        return ""
    lo, hi = min(values), max(values)
    rng = hi - lo if hi != lo else 1
    return "".join(SPARKLINE_CHARS[min(int((v - lo) / rng * 7) + 1, 8)] for v in values)


def make_heartbeat_panel() -> Panel:
    """System Health heartbeat widget for the dashboard header."""
    from shadow_toolkit.sentinel_baseline import is_cache_fresh, baseline_age_seconds, load_samples

    cache_ok = is_cache_fresh()
    age = baseline_age_seconds()
    sample_count = len(load_samples())

    pulse_icon = "[bold #22c55e]● HEALTHY[/]" if cache_ok else "[bold #ef4444]● STALE[/]"
    age_str = f"{int(age // 60)}m ago" if age is not None else "No data"

    info = Text()
    info.append("  Heartbeat:  ", style="bold #94a3b8")
    info.append(pulse_icon + "\n" if cache_ok else pulse_icon + "\n")
    info.append("  Z-Score Cache: ", style="bold #94a3b8")
    info.append(f"{age_str}\n", style="white")
    info.append("  Baseline Samples: ", style="bold #94a3b8")
    info.append(f"{sample_count}\n", style="white")

    # CVE-43887 health check status
    hc_log = Path("C:/Logs/cve43887")
    hc_status = "[#22c55e]Available[/]" if hc_log.exists() else "[#ef4444]Missing[/]"
    info.append("  CVE-43887 Logs: ", style="bold #94a3b8")
    info.append(hc_status)

    border = "#22c55e" if cache_ok else "#ef4444"
    return Panel(info, title="[bold]System Health[/]", border_style=border, box=box.ROUNDED)


def make_sparkline_panel() -> Panel:
    """Sovereign Pulse sparkline — baseline vs actual activity."""
    from shadow_toolkit.sentinel_baseline import get_sparkline_data, METRICS

    lines = []
    for metric in METRICS:
        data = get_sparkline_data(metric, points=20)
        actual = data["actual"]
        spark = _sparkline(actual) if actual else "(no data)"
        mean = data["baseline"][0] if data["baseline"] else 0
        upper = data["threshold_upper"]
        label = metric.replace("_", " ").title()[:18].ljust(18)
        lines.append(f"  {label}  {spark}  avg={mean:.0f}  thresh={upper:.0f}")

    content = "\n".join(lines) if lines else "  No baseline data yet. Run sentinel collect."
    return Panel(
        content,
        title="[bold]Sovereign Pulse — Behavioral Baseline[/]",
        border_style="#6366f1",
        box=box.ROUNDED,
    )


def make_anomaly_table() -> Table:
    """Combined anomaly + threat-intel event table with context badges."""
    from shadow_toolkit.sentinel_baseline import load_anomalies
    from shadow_toolkit.threat_intel_service import load_threat_events

    table = Table(
        title="[bold]Flagged Events[/]",
        box=box.ROUNDED,
        border_style="#ef4444",
        show_lines=False,
    )
    table.add_column("Time", style="#94a3b8", width=19)
    table.add_column("Badge", width=14, justify="center")
    table.add_column("Detail", style="white")
    table.add_column("Severity", justify="center", width=10)

    # Collect both event types
    events = []
    for a in load_anomalies(7):
        events.append({
            "time": a.get("timestamp", "")[:19],
            "badge": "[bold #eab308]ANOMALY[/]",
            "detail": f"{a.get('metric', '')}: observed={a.get('observed', '')} z={a.get('zscore', 0):+.1f}",
            "severity": a.get("severity", "INFO"),
            "sort_ts": a.get("timestamp", ""),
        })
    for t in load_threat_events(7):
        events.append({
            "time": t.get("timestamp", "")[:19],
            "badge": "[bold #ef4444]THREAT-INTEL[/]",
            "detail": f"{t.get('indicator', '')} ({t.get('indicator_type', '')})",
            "severity": "HIGH" if t.get("confidence", 0) >= 70 else "MEDIUM",
            "sort_ts": t.get("timestamp", ""),
        })

    events.sort(key=lambda e: e["sort_ts"], reverse=True)

    for e in events[:20]:
        sev = e["severity"]
        sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
                     "LOW": "#22c55e", "INFO": "#94a3b8"}.get(sev, "#94a3b8")
        table.add_row(e["time"], e["badge"], e["detail"], f"[{sev_color}]{sev}[/]")

    if not events:
        table.add_row("-", "-", "No events in the last 7 days", "-")

    return table


def run_sovereign_pulse():
    """Interactive Sovereign Pulse dashboard."""
    from shadow_toolkit.sentinel_baseline import (
        collect_telemetry, record_sample, compute_baseline,
        detect_anomalies, log_anomalies, METRICS
    )
    from shadow_toolkit.threat_intel_service import lookup, add_indicator, ThreatEvent, log_threat_event

    console.clear()
    console.print(BANNER)
    console.print("[bold #6366f1]  ─── Sovereign Pulse Operational Layer ───[/]\n")

    while True:
        console.print()
        console.print(make_heartbeat_panel())
        console.print()
        console.print(make_sparkline_panel())
        console.print()
        console.print(make_anomaly_table())
        console.print()
        console.print("[bold #94a3b8]  [1] Collect Telemetry  [2] Threat Lookup  [3] Add Indicator  [4] Refresh  [0] Back[/]\n")

        choice = Prompt.ask("[bold #6366f1]Sovereign Pulse[/]", default="0")

        if choice in ("0", "back", "q"):
            break

        elif choice == "1":
            console.print("\n  [*] Collecting telemetry...")
            sample = collect_telemetry()
            samples = record_sample(sample)
            baseline = compute_baseline(samples)
            anomalies = detect_anomalies(sample, baseline)
            if anomalies:
                log_anomalies(anomalies)
                console.print(f"  [bold #ef4444][!] {len(anomalies)} anomalies flagged![/]")
            else:
                console.print("  [bold #22c55e][+] No anomalies. Sample recorded.[/]")

        elif choice == "2":
            indicator = Prompt.ask("[bold]Enter IP, hash, or domain[/]")
            result = lookup(indicator)
            verdict_color = "#ef4444" if result["verdict"] == "malicious" else "#22c55e"
            console.print(f"  Verdict: [{verdict_color}]{result['verdict'].upper()}[/]  "
                          f"Confidence: {result['confidence']}%  "
                          f"Sources: {', '.join(result['sources']) or 'none'}")
            if result["verdict"] == "malicious":
                from datetime import datetime
                event = ThreatEvent(
                    timestamp=datetime.utcnow().isoformat(),
                    indicator=result["indicator"],
                    indicator_type=result["type"],
                    matched_source=", ".join(result["sources"]),
                    confidence=result["confidence"],
                    category="dashboard_lookup",
                    context=f"Dashboard lookup flagged {result['indicator']}",
                )
                log_threat_event(event)

        elif choice == "3":
            indicator = Prompt.ask("[bold]Indicator (IP/hash/domain)[/]")
            category = Prompt.ask("[bold]Category[/]", default="malicious")
            desc = Prompt.ask("[bold]Description[/]", default="Manually flagged")
            add_indicator(indicator, source="manual", confidence=90,
                          category=category, description=desc)
            console.print(f"  [+] Added to threat database: {indicator}")

        elif choice == "4":
            continue  # refresh loop


def run_dashboard():
    """Main TUI dashboard loop."""
    console.clear()
    console.print(BANNER)
    console.print("[bold #94a3b8]  ⚠  AUTHORIZED USE ONLY — You are responsible for your actions  ⚠[/]\n")

    while True:
        console.print()
        # System Health heartbeat in header
        try:
            console.print(make_heartbeat_panel())
        except Exception:
            pass  # graceful if sentinel data doesn't exist yet
        console.print()
        console.print(make_status_panel())
        console.print()
        console.print(make_menu_table())
        console.print()
        console.print("[bold #94a3b8]  [0] Exit  |  [S] Sovereign Pulse  |  [R] Generate Report from last scan[/]\n")

        choice = Prompt.ask("[bold #6366f1]Select module[/]", default="0")

        if choice in ("0", "exit", "quit", "q"):
            console.print("\n[bold #6366f1]Goodbye.[/]\n")
            break

        elif choice.upper() == "S":
            run_sovereign_pulse()

        elif choice == "1":
            config = prompt_portscan()
            from shadow_toolkit.port_scanner import run_port_scanner
            args = build_args_namespace({
                "target": config["target"], "ports": config["ports"],
                "threads": config["threads"], "timeout": 1.0,
                "udp": False, "service_detect": config["service_detect"],
            })
            run_port_scanner(args)

        elif choice == "2":
            config = prompt_crack()
            from shadow_toolkit.hash_cracker import run_hash_cracker
            args = build_args_namespace(config)
            run_hash_cracker(args)

        elif choice == "3":
            config = prompt_webscan()
            from shadow_toolkit.web_scanner import run_web_scanner
            all_tests = config["tests"] == "all"
            args = build_args_namespace({
                "url": config["url"], "depth": config["depth"],
                "sqli": all_tests or config["tests"] == "sqli",
                "xss": all_tests or config["tests"] == "xss",
                "traversal": all_tests or config["tests"] == "traversal",
                "headers": all_tests or config["tests"] == "headers",
                "all": all_tests,
            })
            run_web_scanner(args)

        elif choice == "4":
            config = prompt_sniff()
            from shadow_toolkit.packet_sniffer import run_sniffer
            args = build_args_namespace({
                "count": config["count"], "filter": config["filter"],
                "hex": config["hex"], "interface": None, "output": None,
            })
            run_sniffer(args)

        elif choice == "5":
            config = prompt_dnsenum()
            from shadow_toolkit.dns_enum import run_dns_enum
            args = build_args_namespace({
                "domain": config["domain"], "records": config["records"],
                "zone_transfer": config["zone_transfer"], "threads": config["threads"],
                "wordlist": None,
            })
            run_dns_enum(args)

        elif choice == "6":
            config = prompt_detect()
            from shadow_toolkit.malware_detector import run_detector
            args = build_args_namespace({
                "all": config.get("all", False),
                "processes": config.get("processes", False),
                "persistence": config.get("persistence", False),
                "network": config.get("network", False),
                "hooks": config.get("hooks", False),
            })
            run_detector(args)

        elif choice == "7":
            console.print("[yellow]WiFi Analyzer module launching...[/]")
            from shadow_toolkit.wifi_analyzer import run_wifi_analyzer
            args = build_args_namespace({"scan": True, "monitor": False, "duration": 30})
            run_wifi_analyzer(args)

        elif choice == "8":
            console.print("[yellow]ARP Spoof Detector launching...[/]")
            from shadow_toolkit.arp_detector import run_arp_detector
            args = build_args_namespace({"duration": 60, "interface": None})
            run_arp_detector(args)

        elif choice == "9":
            console.print("[yellow]Reverse Shell Listener launching...[/]")
            from shadow_toolkit.reverse_listener import run_listener
            args = build_args_namespace({"port": 4444, "host": "0.0.0.0", "type": "tcp"})
            run_listener(args)

        elif choice == "10":
            console.print("[yellow]Exploit DB Search launching...[/]")
            from shadow_toolkit.exploit_search import run_exploit_search
            query = Prompt.ask("[bold]Search query (service name, CVE, etc)[/]")
            args = build_args_namespace({"query": query, "limit": 20})
            run_exploit_search(args)

        else:
            console.print("[red]Invalid selection[/]")

        console.print("\n[bold #94a3b8]Press Enter to return to menu...[/]")
        input()
        console.clear()
        console.print(BANNER)


if __name__ == "__main__":
    run_dashboard()
