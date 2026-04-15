#!/usr/bin/env python3
"""
Subdomain & DNS Enumerator
===========================
Discovers subdomains, enumerates DNS records, and attempts zone transfers.
For authorized use only.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.rdatatype
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field


# Built-in common subdomain wordlist
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
    "ns3", "ns4", "dns", "dns1", "dns2", "proxy", "imap", "pop3", "admin",
    "administrator", "gateway", "api", "dev", "staging", "stage", "test",
    "testing", "beta", "demo", "app", "apps", "blog", "shop", "store",
    "secure", "vpn", "remote", "portal", "login", "auth", "sso", "cdn",
    "static", "assets", "media", "images", "img", "video", "docs", "doc",
    "help", "support", "status", "monitor", "monitoring", "grafana", "kibana",
    "jenkins", "ci", "cd", "git", "gitlab", "github", "bitbucket", "jira",
    "confluence", "wiki", "internal", "intranet", "extranet", "dashboard",
    "panel", "cpanel", "whm", "webmin", "phpmyadmin", "mysql", "postgres",
    "db", "database", "redis", "mongo", "elastic", "elasticsearch", "search",
    "solr", "rabbitmq", "kafka", "queue", "mq", "backup", "backups", "bak",
    "old", "new", "dev1", "dev2", "test1", "test2", "staging2", "prod",
    "production", "m", "mobile", "wap", "api2", "v2", "www2", "www3",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "vault", "ldap",
    "ad", "exchange", "owa", "autodiscover", "mx", "mx1", "mx2",
    "relay", "smtp2", "imap2", "calendar", "cal", "meet", "chat",
    "slack", "teams", "zoom", "webex", "crm", "erp", "hr", "finance",
    "billing", "pay", "payment", "checkout", "order", "orders", "track",
    "report", "reports", "analytics", "stats", "log", "logs", "syslog",
    "nagios", "zabbix", "prometheus", "alertmanager", "pagerduty",
]

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "SRV", "PTR", "CAA"]


@dataclass
class DNSResult:
    subdomain: str
    record_type: str
    value: str
    ip: str = ""


@dataclass
class EnumReport:
    domain: str
    subdomains: list = field(default_factory=list)
    dns_records: list = field(default_factory=list)
    zone_transfer: list = field(default_factory=list)
    nameservers: list = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0


def resolve_subdomain(fqdn: str, timeout: float = 3.0) -> list[DNSResult]:
    """Try to resolve a subdomain."""
    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answers = resolver.resolve(fqdn, "A")
        for rdata in answers:
            results.append(DNSResult(
                subdomain=fqdn,
                record_type="A",
                value=str(rdata),
                ip=str(rdata),
            ))
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        pass
    except dns.exception.Timeout:
        pass
    except Exception:
        pass

    # Also check CNAME
    try:
        answers = resolver.resolve(fqdn, "CNAME")
        for rdata in answers:
            results.append(DNSResult(
                subdomain=fqdn,
                record_type="CNAME",
                value=str(rdata.target),
            ))
    except Exception:
        pass

    return results


def enumerate_dns_records(domain: str) -> list[DNSResult]:
    """Enumerate all DNS record types for a domain."""
    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            for rdata in answers:
                value = str(rdata)
                ip = ""
                if rtype == "A":
                    ip = value
                elif rtype == "MX":
                    value = f"{rdata.preference} {rdata.exchange}"
                results.append(DNSResult(
                    subdomain=domain,
                    record_type=rtype,
                    value=value,
                    ip=ip,
                ))
        except Exception:
            continue

    return results


def attempt_zone_transfer(domain: str, nameservers: list[str]) -> list[DNSResult]:
    """Attempt AXFR zone transfer against nameservers."""
    results = []

    for ns in nameservers:
        try:
            ns_ip = socket.gethostbyname(str(ns).rstrip("."))
            zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10))
            for name, node in zone.nodes.items():
                fqdn = f"{name}.{domain}" if str(name) != "@" else domain
                for rdataset in node.rdatasets:
                    for rdata in rdataset:
                        results.append(DNSResult(
                            subdomain=fqdn,
                            record_type=dns.rdatatype.to_text(rdataset.rdtype),
                            value=str(rdata),
                        ))
            if results:
                break  # Got zone data, no need to try other NS
        except Exception:
            continue

    return results


def get_nameservers(domain: str) -> list[str]:
    """Get nameservers for a domain."""
    try:
        answers = dns.resolver.resolve(domain, "NS")
        return [str(rdata.target) for rdata in answers]
    except Exception:
        return []


def reverse_lookup(ip: str) -> str:
    """Perform reverse DNS lookup."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def run_dns_enum(args):
    """Main DNS enumerator entry point."""
    domain = args.domain.strip().lower()
    if domain.startswith("http"):
        from urllib.parse import urlparse
        domain = urlparse(domain).netloc or domain

    thread_count = args.threads
    do_records = args.records
    do_zone_transfer = args.zone_transfer
    wordlist_path = args.wordlist

    print(f"  [*] Target domain: {domain}")

    report = EnumReport(domain=domain, start_time=time.time())

    # Get nameservers
    print("  [*] Discovering nameservers...")
    report.nameservers = get_nameservers(domain)
    if report.nameservers:
        for ns in report.nameservers:
            print(f"      NS: {ns}")
    else:
        print("  [!] No nameservers found")

    # DNS Records
    if do_records:
        print("\n  [*] Enumerating DNS records...")
        report.dns_records = enumerate_dns_records(domain)
        for rec in report.dns_records:
            print(f"      {rec.record_type:<6} {rec.value}")

    # Zone transfer
    if do_zone_transfer and report.nameservers:
        print("\n  [*] Attempting zone transfer (AXFR)...")
        report.zone_transfer = attempt_zone_transfer(domain, report.nameservers)
        if report.zone_transfer:
            print(f"  [!] Zone transfer SUCCESSFUL! Found {len(report.zone_transfer)} records")
            for rec in report.zone_transfer:
                print(f"      {rec.record_type:<6} {rec.subdomain:<40} {rec.value}")
        else:
            print("  [*] Zone transfer denied (good security practice)")

    # Subdomain brute-force
    print("\n  [*] Subdomain enumeration...")

    # Load wordlist
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                subdomains = [line.strip() for line in f if line.strip()]
            print(f"  [*] Loaded {len(subdomains):,} from wordlist")
        except FileNotFoundError:
            print(f"  [!] Wordlist not found: {wordlist_path}")
            subdomains = DEFAULT_SUBDOMAINS
            print(f"  [*] Using built-in list ({len(subdomains)} entries)")
    else:
        subdomains = DEFAULT_SUBDOMAINS
        print(f"  [*] Using built-in list ({len(subdomains)} entries)")

    print(f"  [*] Brute-forcing with {thread_count} threads...")
    print()

    found_count = 0
    completed = 0
    total = len(subdomains)

    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = {}
        for sub in subdomains:
            fqdn = f"{sub}.{domain}"
            futures[executor.submit(resolve_subdomain, fqdn)] = sub

        for future in as_completed(futures):
            completed += 1
            results = future.result()
            if results:
                found_count += 1
                for r in results:
                    report.subdomains.append(r)
                    ip_str = f" → {r.ip}" if r.ip else f" → {r.value}"
                    print(f"  [+] {r.subdomain:<45} {r.record_type:<6}{ip_str}")

            if completed % 50 == 0 or completed == total:
                pct = completed / total * 100
                bar_len = 30
                filled = int(bar_len * completed / total)
                bar = "█" * filled + "░" * (bar_len - filled)
                sys.stdout.write(
                    f"\r  [{bar}] {pct:.0f}% | {completed}/{total} | Found: {found_count}"
                )
                sys.stdout.flush()

    report.end_time = time.time()
    print("\n")

    # Results summary
    print("  ┌─────────────────────────────────────────────────────────────┐")
    print("  │  DNS ENUMERATION RESULTS                                   │")
    print("  ├─────────────────────────────────────────────────────────────┤")
    print(f"  │  Domain:     {domain}")
    print(f"  │  Duration:   {report.end_time - report.start_time:.2f}s")
    print(f"  │  Subdomains: {len(report.subdomains)} found")
    print(f"  │  DNS Records:{len(report.dns_records)} enumerated")
    zone_status = f"{len(report.zone_transfer)} records" if report.zone_transfer else "Denied"
    print(f"  │  Zone Xfer:  {zone_status}")
    print("  ├─────────────────────────────────────────────────────────────┤")

    if report.subdomains:
        # Deduplicate and sort
        seen = set()
        unique = []
        for s in report.subdomains:
            if s.subdomain not in seen:
                seen.add(s.subdomain)
                unique.append(s)
        unique.sort(key=lambda x: x.subdomain)

        print("  │  DISCOVERED SUBDOMAINS:                                    │")
        print("  │                                                            │")
        for s in unique:
            ip_str = s.ip or s.value
            print(f"  │  {s.subdomain:<40} {ip_str:<18} │")
    else:
        print("  │  No subdomains discovered                                  │")

    print("  └─────────────────────────────────────────────────────────────┘")

    # Interesting findings
    if report.zone_transfer:
        print("\n  ⚠  SECURITY FINDING: Zone transfer is enabled!")
        print("     This exposes the entire DNS zone to anyone.")
        print("     Recommendation: Restrict AXFR to authorized IPs only.")
