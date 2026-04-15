#!/usr/bin/env python3
"""
Shadow Toolkit - Ethical Security Testing Suite
================================================
WARNING: For authorized use only. Only use on systems you own
or have explicit written permission to test.
Unauthorized access to computer systems is illegal.
"""

import argparse
import sys
from shadow_toolkit import __version__


BANNER = r"""
  ____  _               _                 _____           _ _    _ _   
 / ___|| |__   __ _  __| | _____      __ |_   _|__   ___ | | | _(_) |_ 
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | |/ _ \ / _ \| | |/ / | __|
  ___) | | | | (_| | (_| | (_) \ V  V /    | | (_) | (_) | |   <| | |_ 
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/     |_|\___/ \___/|_|_|\_\_|\__|
                                                                   v{version}
 ⚠  AUTHORIZED USE ONLY - You are responsible for your actions  ⚠
"""


def main():
    banner_text = BANNER.format(version=__version__)
    try:
        print(banner_text)
    except UnicodeEncodeError:
        # Fallback for terminals using limited code pages.
        safe_banner = banner_text.encode("ascii", errors="ignore").decode("ascii")
        print(safe_banner)

    parser = argparse.ArgumentParser(
        description="Shadow Toolkit - Ethical Security Testing Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="module", help="Available modules")

    # -- Port Scanner --
    scan_parser = subparsers.add_parser("portscan", help="Network port scanner")
    scan_parser.add_argument("target", help="Target IP or hostname")
    scan_parser.add_argument(
        "-p", "--ports", default="1-1024", help="Port range (e.g. 1-1024, 80,443,8080)"
    )
    scan_parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=100,
        help="Number of threads (default: 100)",
    )
    scan_parser.add_argument(
        "--timeout", type=float, default=1.0, help="Connection timeout in seconds"
    )
    scan_parser.add_argument(
        "--udp", action="store_true", help="Enable UDP scan (slower)"
    )
    scan_parser.add_argument(
        "-sV", "--service-detect", action="store_true", help="Detect service versions"
    )

    # -- Password Hash Cracker --
    crack_parser = subparsers.add_parser("crack", help="Password hash cracker")
    crack_parser.add_argument("hash_value", help="Hash to crack")
    crack_parser.add_argument(
        "-w", "--wordlist", required=True, help="Path to wordlist file"
    )
    crack_parser.add_argument(
        "-m",
        "--mode",
        choices=["md5", "sha1", "sha256", "sha512", "bcrypt", "ntlm", "auto"],
        default="auto",
        help="Hash algorithm (default: auto-detect)",
    )
    crack_parser.add_argument(
        "-r",
        "--rules",
        action="store_true",
        help="Apply mutation rules (l33t, capitalize, etc.)",
    )

    # -- Web Vulnerability Scanner --
    web_parser = subparsers.add_parser("webscan", help="Web vulnerability scanner")
    web_parser.add_argument("url", help="Target URL to scan")
    web_parser.add_argument(
        "--sqli", action="store_true", help="Test for SQL injection"
    )
    web_parser.add_argument("--xss", action="store_true", help="Test for XSS")
    web_parser.add_argument(
        "--traversal", action="store_true", help="Test for directory traversal"
    )
    web_parser.add_argument(
        "--headers", action="store_true", help="Analyze security headers"
    )
    web_parser.add_argument("--all", action="store_true", help="Run all tests")
    web_parser.add_argument(
        "--depth", type=int, default=2, help="Crawl depth (default: 2)"
    )
    web_parser.add_argument("--auth", help="Basic auth user:pass")
    web_parser.add_argument(
        "--delay", type=float, default=0.0, help="Delay between requests (s)"
    )
    web_parser.add_argument(
        "--concurrency", type=int, default=10, help="Max concurrent requests"
    )
    web_parser.add_argument(
        "--blind-sqli", action="store_true", help="Include time-based blind SQLi"
    )

    # -- Packet Sniffer --
    sniff_parser = subparsers.add_parser(
        "sniff", help="Packet sniffer & network analyzer"
    )
    sniff_parser.add_argument("-i", "--interface", help="Network interface to sniff on")
    sniff_parser.add_argument(
        "-c", "--count", type=int, default=0, help="Number of packets (0 = unlimited)"
    )
    sniff_parser.add_argument(
        "-f", "--filter", help="BPF filter expression (e.g. 'tcp port 80')"
    )
    sniff_parser.add_argument("-o", "--output", help="Save captured packets to file")
    sniff_parser.add_argument(
        "--hex", action="store_true", help="Show hex dump of packets"
    )

    # -- DNS Enumerator --
    dns_parser = subparsers.add_parser("dnsenum", help="Subdomain & DNS enumerator")
    dns_parser.add_argument("domain", help="Target domain")
    dns_parser.add_argument(
        "-w", "--wordlist", help="Subdomain wordlist for brute-forcing"
    )
    dns_parser.add_argument(
        "--records", action="store_true", help="Enumerate all DNS record types"
    )
    dns_parser.add_argument(
        "--zone-transfer", action="store_true", help="Attempt zone transfer"
    )
    dns_parser.add_argument(
        "-t", "--threads", type=int, default=50, help="Threads for brute-force"
    )

    # -- Malware Detector --
    detect_parser = subparsers.add_parser("detect", help="Keylogger & malware detector")
    detect_parser.add_argument(
        "--processes", action="store_true", help="Scan suspicious processes"
    )
    detect_parser.add_argument(
        "--persistence", action="store_true", help="Check persistence mechanisms"
    )
    detect_parser.add_argument(
        "--network", action="store_true", help="Check suspicious network connections"
    )
    detect_parser.add_argument(
        "--hooks", action="store_true", help="Detect keyboard hooks"
    )
    detect_parser.add_argument(
        "--all", action="store_true", help="Run all detection modules"
    )

    # -- WiFi Analyzer --
    wifi_parser = subparsers.add_parser("wifi", help="WiFi network analyzer")
    wifi_parser.add_argument(
        "--scan", action="store_true", default=True, help="Scan nearby networks"
    )
    wifi_parser.add_argument(
        "--monitor", action="store_true", help="Continuous monitoring mode"
    )
    wifi_parser.add_argument(
        "--duration", type=int, default=30, help="Monitor duration in seconds"
    )

    # -- ARP Spoof Detector --
    arp_parser = subparsers.add_parser("arpwatch", help="ARP spoof/MITM detector")
    arp_parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Monitor duration in seconds (default: 60)",
    )
    arp_parser.add_argument(
        "--interval", type=float, default=2.0, help="Scan interval in seconds"
    )
    arp_parser.add_argument("-i", "--interface", help="Network interface")

    # -- Reverse Shell Listener --
    listen_parser = subparsers.add_parser("listener", help="Reverse shell listener")
    listen_parser.add_argument(
        "-p", "--port", type=int, default=4444, help="Listening port (default: 4444)"
    )
    listen_parser.add_argument(
        "--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)"
    )
    listen_parser.add_argument(
        "--type", choices=["tcp", "tls"], default="tcp", help="Connection type"
    )

    # -- Exploit DB Search --
    exploit_parser = subparsers.add_parser("exploitdb", help="Search exploit databases")
    exploit_parser.add_argument(
        "query", help="Search query (service name, CVE, keyword)"
    )
    exploit_parser.add_argument(
        "-l", "--limit", type=int, default=20, help="Max results (default: 20)"
    )

    # -- SSL/TLS Certificate Analyzer (Phase 1) --
    ssl_parser = subparsers.add_parser(
        "sslanalyze", help="SSL/TLS certificate analyzer"
    )
    ssl_parser.add_argument("domain", help="Domain to analyze (e.g., example.com)")
    ssl_parser.add_argument(
        "-p", "--port", type=int, default=443, help="Port (default: 443)"
    )
    ssl_parser.add_argument(
        "--no-resolve", action="store_true", help="Skip DNS resolution"
    )
    ssl_parser.add_argument(
        "--timeout", type=float, default=5.0, help="Connection timeout (seconds)"
    )
    ssl_parser.add_argument(
        "--verify-chain", action="store_true", help="Verify certificate chain"
    )

    # -- Secret Detector (Phase 1) --
    secret_parser = subparsers.add_parser(
        "detect-secrets", help="Secret & credential detection engine"
    )
    secret_parser.add_argument(
        "target",
        help="Target file or directory to scan",
    )
    secret_parser.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        default=True,
        help="Recursive directory scan (default: true)",
    )
    secret_parser.add_argument(
        "--entropy-threshold",
        type=float,
        default=3.5,
        help="Entropy threshold for flagging (default: 3.5)",
    )
    secret_parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="Number of parallel workers (default: 4)",
    )

    # -- Compliance Scanner (Phase 1) --
    compliance_parser = subparsers.add_parser(
        "compliance", help="Compliance scanner (PCI-DSS, HIPAA, SOC2)"
    )
    compliance_parser.add_argument(
        "--config",
        required=True,
        help="Path to compliance config (JSON format)",
    )
    compliance_parser.add_argument(
        "--framework",
        choices=["pci_dss", "hipaa", "soc2", "gdpr", "iso_27001", "all"],
        default="all",
        help="Framework(s) to scan (default: all)",
    )
    compliance_parser.add_argument(
        "--severity",
        choices=["critical", "high", "medium", "low", "info", "all"],
        default="all",
        help="Filter by severity (default: all)",
    )

    # -- API Security Tester (Phase 2) --
    api_sec_parser = subparsers.add_parser(
        "api-security", help="API security tester (OpenAPI + live posture checks)"
    )
    api_sec_parser.add_argument(
        "target", help="Logical target name for report output"
    )
    api_sec_parser.add_argument(
        "--spec", help="Path to OpenAPI spec (JSON/YAML)"
    )
    api_sec_parser.add_argument(
        "--live", help="Live endpoint URL for safe posture checks"
    )
    api_sec_parser.add_argument(
        "--timeout", type=float, default=5.0, help="HTTP timeout in seconds"
    )

    # -- Kubernetes Pod Analyzer (Phase 2) --
    k8s_parser = subparsers.add_parser(
        "k8s-pod-audit", help="Kubernetes pod security analyzer"
    )
    k8s_parser.add_argument(
        "input", help="Path to pod JSON/YAML (kubectl get pods -o json)"
    )

    # -- Dashboard --
    subparsers.add_parser(
        "dashboard", help="Interactive TUI dashboard (requires: pip install rich)"
    )

    # -- Sentinel Baseline --
    sentinel_parser = subparsers.add_parser(
        "sentinel", help="Behavioral baseline & anomaly detection"
    )
    sentinel_parser.add_argument(
        "action",
        nargs="?",
        default="collect",
        choices=["collect", "status", "anomalies"],
        help="Action: collect telemetry, view status, or list anomalies",
    )
    sentinel_parser.add_argument(
        "--days", type=int, default=7, help="Days of history to show (default: 7)"
    )

    # -- Threat Intel --
    ti_parser = subparsers.add_parser("threatintel", help="Threat intelligence lookups")
    ti_parser.add_argument(
        "action",
        nargs="?",
        default="lookup",
        choices=["lookup", "add", "remove", "list", "events"],
        help="Action: lookup, add/remove indicators, list DB, show events",
    )
    ti_parser.add_argument(
        "indicator", nargs="?", default="", help="IP, hash, or domain to look up"
    )
    ti_parser.add_argument(
        "--category", default="malicious", help="Category for add action"
    )
    ti_parser.add_argument(
        "--description", default="", help="Description for add action"
    )
    ti_parser.add_argument(
        "--days", type=int, default=7, help="Days of history for events"
    )

    # -- Scaled Runtime --
    subparsers.add_parser(
        "scaled", help="Start collector + modules + FastAPI dashboard"
    )
    subparsers.add_parser(
        "scaled-lite", help="Start collector + FastAPI dashboard (no modules)"
    )
    subparsers.add_parser(
        "orchestrator", help="Start interactive module orchestrator shell"
    )
    subparsers.add_parser(
        "daily-report", help="Generate and dispatch business daily audit reports now"
    )

    # -- Report (global flags) --
    parser.add_argument(
        "--report", choices=["html", "json"], help="Export results to file"
    )
    parser.add_argument("--output", "-o", help="Report output filename")

    args = parser.parse_args()

    if not args.module:
        parser.print_help()
        sys.exit(1)

    if args.module == "dashboard":
        from shadow_toolkit.dashboard import run_dashboard

        run_dashboard()
    elif args.module == "portscan":
        from shadow_toolkit.port_scanner import run_port_scanner

        run_port_scanner(args)
    elif args.module == "crack":
        from shadow_toolkit.hash_cracker import run_hash_cracker

        run_hash_cracker(args)
    elif args.module == "webscan":
        from shadow_toolkit.web_scanner import run_web_scanner

        run_web_scanner(args)
    elif args.module == "sniff":
        from shadow_toolkit.packet_sniffer import run_sniffer

        run_sniffer(args)
    elif args.module == "dnsenum":
        from shadow_toolkit.dns_enum import run_dns_enum

        run_dns_enum(args)
    elif args.module == "detect":
        from shadow_toolkit.malware_detector import run_detector

        run_detector(args)
    elif args.module == "wifi":
        from shadow_toolkit.wifi_analyzer import run_wifi_analyzer

        run_wifi_analyzer(args)
    elif args.module == "arpwatch":
        from shadow_toolkit.arp_detector import run_arp_detector

        run_arp_detector(args)
    elif args.module == "listener":
        from shadow_toolkit.reverse_listener import run_listener

        run_listener(args)
    elif args.module == "exploitdb":
        from shadow_toolkit.exploit_search import run_exploit_search

        run_exploit_search(args)
    elif args.module == "sslanalyze":
        from shadow_toolkit.ssl_certificate_analyzer import SSLAnalyzer, format_report

        analyzer = SSLAnalyzer(timeout=args.timeout, verify_chain=args.verify_chain)
        result = analyzer.analyze_domain(
            args.domain,
            port=args.port,
            resolve_ip=not args.no_resolve,
        )
        print(format_report(result))
    elif args.module == "detect-secrets":
        from shadow_toolkit.secret_detector import SecretDetector, format_report
        from pathlib import Path

        target = Path(args.target)
        detector = SecretDetector(entropy_threshold=args.entropy_threshold)

        if target.is_dir():
            result = detector.scan_directory(
                target, max_workers=args.workers, recursive=args.recursive
            )
        else:
            secrets = detector.scan_file(target)
            from shadow_toolkit.secret_detector import ScanResult

            result = ScanResult(files_scanned=1, secrets_found=secrets)

        print(format_report(result))
    elif args.module == "compliance":
        import json
        from shadow_toolkit.compliance_scanner import (
            ComplianceScanner,
            ComplianceFramework,
            format_report,
        )
        from pathlib import Path

        # Load config
        config_path = Path(args.config)
        if not config_path.exists():
            print(f"[!] Config file not found: {args.config}")
            sys.exit(1)

        with open(config_path) as f:
            config = json.load(f)

        # Parse frameworks
        framework_map = {
            "pci_dss": ComplianceFramework.PCI_DSS,
            "hipaa": ComplianceFramework.HIPAA,
            "soc2": ComplianceFramework.SOC2,
            "gdpr": ComplianceFramework.GDPR,
            "iso_27001": ComplianceFramework.ISO_27001,
        }

        if args.framework == "all":
            frameworks = list(framework_map.values())
        else:
            frameworks = [framework_map[args.framework]]

        scanner = ComplianceScanner()
        result = scanner.scan(config, frameworks=frameworks)
        print(format_report(result))
    elif args.module == "api-security":
        from shadow_toolkit.api_security_tester import run_api_security_tester

        run_api_security_tester(args)
    elif args.module == "k8s-pod-audit":
        from shadow_toolkit.kubernetes_pod_analyzer import run_kubernetes_pod_analyzer

        run_kubernetes_pod_analyzer(args)
    elif args.module == "sentinel":
        from shadow_toolkit.sentinel_baseline import run_sentinel

        run_sentinel(args)
    elif args.module == "threatintel":
        from shadow_toolkit.threat_intel_service import run_threat_intel

        run_threat_intel(args)
    elif args.module == "scaled":
        import main as scaled_runtime

        scaled_runtime.run_scaled_runtime(include_modules=True, include_dashboard=True)
    elif args.module == "scaled-lite":
        import main as scaled_runtime

        scaled_runtime.main_lite()
    elif args.module == "orchestrator":
        import main as scaled_runtime

        scaled_runtime.main()
    elif args.module == "daily-report":
        from core.reporter import DailyReporter

        stats = DailyReporter().dispatch_reports()
        print(
            "[+] Daily reporting complete: "
            f"businesses={stats.get('businesses_reported', 0)} "
            f"emails={stats.get('emails_sent', 0)} "
            f"csv={stats.get('csv_written', 0)} "
            f"pdf={stats.get('pdf_written', 0)}"
        )


if __name__ == "__main__":
    main()
