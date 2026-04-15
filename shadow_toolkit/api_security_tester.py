#!/usr/bin/env python3
"""
API Security Tester
===================
Performs basic API security posture checks against OpenAPI specs and live endpoints.
For authorized use only.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests
import yaml

from core.bus import TelemetryBus


@dataclass
class APIFinding:
    finding_type: str
    severity: str
    target: str
    evidence: str
    remediation: str


@dataclass
class APIReport:
    target: str
    findings: list[APIFinding] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time


def _normalize_severity(value: str) -> str:
    upper = (value or "").upper()
    if upper in {"CRITICAL", "HIGH"}:
        return "critical"
    if upper in {"MEDIUM", "WARNING"}:
        return "warning"
    return "info"


def _publish_findings(report: APIReport, bus_port: int = 5555) -> None:
    bus = TelemetryBus(port=bus_port)
    try:
        for finding in report.findings:
            bus.publish(
                module_name="api_security_tester",
                event_type=finding.finding_type,
                severity=_normalize_severity(finding.severity),
                data={
                    "target": finding.target,
                    "finding_type": finding.finding_type,
                    "severity": finding.severity,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "report_target": report.target,
                    "scan_duration": round(report.duration, 3),
                },
            )
    finally:
        bus.close()


def _load_openapi_spec(spec_path: str) -> dict[str, Any]:
    path = Path(spec_path)
    raw = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(raw) or {}
    return json.loads(raw)


def _collect_path_methods(spec: dict[str, Any]) -> list[tuple[str, str, dict[str, Any]]]:
    results: list[tuple[str, str, dict[str, Any]]] = []
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        for method, operation in methods.items():
            if method.lower() in {"get", "post", "put", "patch", "delete", "head", "options"}:
                results.append((path, method.upper(), operation or {}))
    return results


def analyze_openapi_security(spec: dict[str, Any], target_name: str) -> list[APIFinding]:
    findings: list[APIFinding] = []
    global_security = spec.get("security")
    schemes = spec.get("components", {}).get("securitySchemes", {})
    ops = _collect_path_methods(spec)

    if not schemes:
        findings.append(
            APIFinding(
                finding_type="missing_security_schemes",
                severity="HIGH",
                target=target_name,
                evidence="OpenAPI has no components.securitySchemes section.",
                remediation="Define security schemes (OAuth2/JWT/API key) and apply security requirements.",
            )
        )

    for path, method, operation in ops:
        op_id = operation.get("operationId", f"{method} {path}")
        op_security = operation.get("security", global_security)

        if op_security is None:
            findings.append(
                APIFinding(
                    finding_type="unauthenticated_operation",
                    severity="HIGH",
                    target=op_id,
                    evidence="Operation has no explicit or inherited security requirements.",
                    remediation="Require authentication/authorization on this endpoint.",
                )
            )

        if operation.get("deprecated") is True:
            findings.append(
                APIFinding(
                    finding_type="deprecated_operation",
                    severity="LOW",
                    target=op_id,
                    evidence="Endpoint is deprecated but still present.",
                    remediation="Remove or gate deprecated endpoints behind strict auth.",
                )
            )

        if "requestBody" in operation and "application/json" not in json.dumps(operation.get("requestBody", {})):
            findings.append(
                APIFinding(
                    finding_type="non_json_body_validation_gap",
                    severity="MEDIUM",
                    target=op_id,
                    evidence="Request body exists but JSON media type/schema is unclear.",
                    remediation="Define strict request schema and content types.",
                )
            )

    return findings


def test_live_endpoint(url: str, timeout: float = 5.0) -> list[APIFinding]:
    findings: list[APIFinding] = []
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        return [
            APIFinding(
                finding_type="endpoint_unreachable",
                severity="MEDIUM",
                target=url,
                evidence=str(exc),
                remediation="Verify endpoint availability and network policies.",
            )
        ]

    server = response.headers.get("Server")
    if server:
        findings.append(
            APIFinding(
                finding_type="server_header_exposed",
                severity="LOW",
                target=url,
                evidence=f"Server header exposed: {server}",
                remediation="Suppress or sanitize Server/X-Powered-By headers.",
            )
        )

    required_headers = {
        "Strict-Transport-Security": "Enable HSTS to prevent downgrade attacks.",
        "Content-Security-Policy": "Set CSP for browser-facing API docs/admin surfaces.",
        "X-Content-Type-Options": "Set nosniff to block MIME confusion.",
    }
    for header, fix in required_headers.items():
        if header not in response.headers:
            findings.append(
                APIFinding(
                    finding_type="missing_security_header",
                    severity="LOW",
                    target=url,
                    evidence=f"Missing {header}",
                    remediation=fix,
                )
            )

    if response.status_code == 200 and "openapi" in response.text.lower():
        findings.append(
            APIFinding(
                finding_type="spec_exposed_publicly",
                severity="MEDIUM",
                target=url,
                evidence="Endpoint appears to expose OpenAPI data publicly.",
                remediation="Restrict spec endpoints to authenticated/internal access.",
            )
        )

    return findings


def print_report(report: APIReport) -> None:
    print("\n" + "=" * 72)
    print(f"API SECURITY REPORT: {report.target}")
    print("=" * 72)
    print(f"Findings: {len(report.findings)} | Duration: {report.duration:.2f}s")

    if not report.findings:
        print("[+] No findings detected.")
        return

    for idx, finding in enumerate(report.findings, start=1):
        print(f"\n[{idx}] {finding.severity} | {finding.finding_type}")
        print(f"    Target: {finding.target}")
        print(f"    Evidence: {finding.evidence}")
        print(f"    Remediation: {finding.remediation}")


def run_api_security_tester(args) -> None:
    report = APIReport(target=args.target, start_time=time.time())

    if args.spec:
        spec = _load_openapi_spec(args.spec)
        report.findings.extend(analyze_openapi_security(spec, args.spec))

    if args.live:
        report.findings.extend(test_live_endpoint(args.live, timeout=args.timeout))

    report.end_time = time.time()
    print_report(report)

    if not getattr(args, "no_telemetry", False):
        _publish_findings(report, bus_port=getattr(args, "bus_port", 5555))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="API Security Tester")
    parser.add_argument("target", help="Logical target name for the report")
    parser.add_argument("--spec", help="Path to OpenAPI JSON/YAML file")
    parser.add_argument("--live", help="Live endpoint URL to test (safe header/posture checks)")
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--no-telemetry", action="store_true", help="Do not publish findings to telemetry bus")
    parser.add_argument("--bus-port", type=int, default=5555, help="Telemetry bus port")
    args = parser.parse_args()

    run_api_security_tester(args)
