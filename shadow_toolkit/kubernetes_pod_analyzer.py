#!/usr/bin/env python3
"""
Kubernetes Pod Analyzer
=======================
Analyzes pod specs for common security misconfigurations.
For authorized use only.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.bus import TelemetryBus


@dataclass
class PodFinding:
    namespace: str
    pod: str
    finding_type: str
    severity: str
    evidence: str
    remediation: str


@dataclass
class PodAnalysisReport:
    source: str
    findings: list[PodFinding] = field(default_factory=list)
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


def _publish_findings(report: PodAnalysisReport, bus_port: int = 5555) -> None:
    bus = TelemetryBus(port=bus_port)
    try:
        for finding in report.findings:
            bus.publish(
                module_name="kubernetes_pod_analyzer",
                event_type=finding.finding_type,
                severity=_normalize_severity(finding.severity),
                data={
                    "namespace": finding.namespace,
                    "pod": finding.pod,
                    "finding_type": finding.finding_type,
                    "severity": finding.severity,
                    "evidence": finding.evidence,
                    "remediation": finding.remediation,
                    "source": report.source,
                    "scan_duration": round(report.duration, 3),
                },
            )
    finally:
        bus.close()


def _load_input(path: str) -> dict[str, Any]:
    p = Path(path)
    raw = p.read_text(encoding="utf-8")
    if p.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(raw)
    else:
        data = json.loads(raw)

    if isinstance(data, dict) and "items" in data:
        return data

    if isinstance(data, dict) and data.get("kind") == "Pod":
        return {"items": [data]}

    raise ValueError(
        "Expected Kubernetes Pod JSON/YAML or kubectl list output with 'items'."
    )


def _iter_containers(pod: dict[str, Any]) -> list[dict[str, Any]]:
    spec = pod.get("spec", {})
    return (spec.get("containers") or []) + (spec.get("initContainers") or [])


def analyze_pods(data: dict[str, Any]) -> list[PodFinding]:
    findings: list[PodFinding] = []

    for pod in data.get("items", []):
        meta = pod.get("metadata", {})
        spec = pod.get("spec", {})
        namespace = meta.get("namespace", "default")
        pod_name = meta.get("name", "unknown-pod")

        if spec.get("hostNetwork") is True:
            findings.append(
                PodFinding(
                    namespace=namespace,
                    pod=pod_name,
                    finding_type="host_network_enabled",
                    severity="HIGH",
                    evidence="spec.hostNetwork = true",
                    remediation="Disable hostNetwork unless strictly required.",
                )
            )

        if spec.get("hostPID") is True or spec.get("hostIPC") is True:
            findings.append(
                PodFinding(
                    namespace=namespace,
                    pod=pod_name,
                    finding_type="host_namespace_sharing",
                    severity="HIGH",
                    evidence=f"hostPID={spec.get('hostPID')} hostIPC={spec.get('hostIPC')}",
                    remediation="Avoid host PID/IPC sharing for workload isolation.",
                )
            )

        for c in _iter_containers(pod):
            c_name = c.get("name", "container")
            sc = c.get("securityContext", {})
            image = c.get("image", "")
            resources = c.get("resources", {})

            if sc.get("privileged") is True:
                findings.append(
                    PodFinding(
                        namespace=namespace,
                        pod=pod_name,
                        finding_type="privileged_container",
                        severity="CRITICAL",
                        evidence=f"container={c_name} securityContext.privileged=true",
                        remediation="Run container unprivileged and drop capabilities.",
                    )
                )

            if sc.get("allowPrivilegeEscalation") is not False:
                findings.append(
                    PodFinding(
                        namespace=namespace,
                        pod=pod_name,
                        finding_type="privilege_escalation_allowed",
                        severity="HIGH",
                        evidence=f"container={c_name} allowPrivilegeEscalation is not false",
                        remediation="Set allowPrivilegeEscalation: false.",
                    )
                )

            run_as_non_root = sc.get("runAsNonRoot")
            if run_as_non_root is not True:
                findings.append(
                    PodFinding(
                        namespace=namespace,
                        pod=pod_name,
                        finding_type="runs_as_root_or_unknown",
                        severity="MEDIUM",
                        evidence=f"container={c_name} runAsNonRoot={run_as_non_root}",
                        remediation="Set runAsNonRoot: true and non-root UID.",
                    )
                )

            caps_add = (sc.get("capabilities", {}) or {}).get("add", [])
            risky_caps = {"NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE"}
            risky = [cap for cap in caps_add if cap in risky_caps]
            if risky:
                findings.append(
                    PodFinding(
                        namespace=namespace,
                        pod=pod_name,
                        finding_type="risky_linux_capabilities",
                        severity="HIGH",
                        evidence=f"container={c_name} added capabilities={risky}",
                        remediation="Drop unnecessary capabilities; keep minimum required set.",
                    )
                )

            if image.endswith(":latest") or ":" not in image:
                findings.append(
                    PodFinding(
                        namespace=namespace,
                        pod=pod_name,
                        finding_type="unpinned_image_tag",
                        severity="MEDIUM",
                        evidence=f"container={c_name} image={image}",
                        remediation="Pin immutable image tags or digests.",
                    )
                )

            limits = resources.get("limits", {})
            requests = resources.get("requests", {})
            if not limits or not requests:
                findings.append(
                    PodFinding(
                        namespace=namespace,
                        pod=pod_name,
                        finding_type="missing_resource_constraints",
                        severity="LOW",
                        evidence=f"container={c_name} limits/requests incomplete",
                        remediation="Set CPU/memory requests and limits.",
                    )
                )

    return findings


def print_report(report: PodAnalysisReport) -> None:
    print("\n" + "=" * 72)
    print(f"KUBERNETES POD SECURITY REPORT: {report.source}")
    print("=" * 72)
    print(f"Findings: {len(report.findings)} | Duration: {report.duration:.2f}s")

    if not report.findings:
        print("[+] No findings detected.")
        return

    for idx, finding in enumerate(report.findings, start=1):
        print(
            f"\n[{idx}] {finding.severity} | {finding.finding_type} | "
            f"{finding.namespace}/{finding.pod}"
        )
        print(f"    Evidence: {finding.evidence}")
        print(f"    Remediation: {finding.remediation}")


def run_kubernetes_pod_analyzer(args) -> None:
    report = PodAnalysisReport(source=args.input, start_time=time.time())
    data = _load_input(args.input)
    report.findings = analyze_pods(data)
    report.end_time = time.time()
    print_report(report)

    if not getattr(args, "no_telemetry", False):
        _publish_findings(report, bus_port=getattr(args, "bus_port", 5555))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Kubernetes Pod Analyzer")
    parser.add_argument(
        "input", help="Path to pod JSON/YAML (kubectl get pods -o json output)"
    )
    parser.add_argument("--no-telemetry", action="store_true", help="Do not publish findings to telemetry bus")
    parser.add_argument("--bus-port", type=int, default=5555, help="Telemetry bus port")
    args = parser.parse_args()

    run_kubernetes_pod_analyzer(args)
