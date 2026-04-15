#!/usr/bin/env python3
"""
Compliance Scanner
==================
Automated compliance checking for PCI-DSS, HIPAA, SOC2, CIS Benchmarks.
Validates configurations, access controls, logging, encryption, and data handling.
Part of the governance and risk management layer.
"""

import json
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Set, Optional, Callable
from abc import ABC, abstractmethod


# ---------------------------------------------------------------------------
# Enums & Data Structures
# ---------------------------------------------------------------------------
class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    PCI_DSS = "pci_dss"  # Payment Card Industry
    HIPAA = "hipaa"  # Health Insurance Portability
    SOC2 = "soc2"  # Service Organization Control
    CIS_BENCHMARKS = "cis_benchmarks"  # Center for Internet Security
    GDPR = "gdpr"  # General Data Protection Regulation
    ISO_27001 = "iso_27001"  # Info Security Management


class Severity(Enum):
    """Issue severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ComplianceIssue:
    """Represents a compliance violation or finding."""

    framework: ComplianceFramework
    control_id: str  # e.g., "PCI-DSS-1.1.1", "HIPAA-164.308"
    severity: Severity
    title: str
    description: str
    finding: str  # What was actually found (or not found)
    evidence: str  # Supporting evidence/context
    remediation: str
    check_name: str
    passed: bool = False


@dataclass
class ComplianceScanResult:
    """Results from compliance scan."""

    frameworks: List[ComplianceFramework] = field(default_factory=list)
    issues: List[ComplianceIssue] = field(default_factory=list)
    passed_checks: int = 0
    failed_checks: int = 0
    scan_timestamp: float = 0.0
    scan_duration: float = 0.0

    @property
    def critical_issues(self) -> List[ComplianceIssue]:
        return [i for i in self.issues if i.severity == Severity.CRITICAL]

    @property
    def compliance_score(self) -> float:
        """Calculate overall compliance percentage (0-100)."""
        total = self.passed_checks + self.failed_checks
        if total == 0:
            return 0.0
        return (self.passed_checks / total) * 100


# ---------------------------------------------------------------------------
# Compliance Checks Base Classes
# ---------------------------------------------------------------------------
class ComplianceCheck(ABC):
    """Base class for compliance checks."""

    def __init__(self, framework: ComplianceFramework):
        self.framework = framework

    @abstractmethod
    def execute(self, config: Dict) -> List[ComplianceIssue]:
        """Execute compliance check against configuration."""
        pass


# ---------------------------------------------------------------------------
# PCI-DSS Checks (v3.2.1)
# ---------------------------------------------------------------------------
class PCIDSSChecks(ComplianceCheck):
    """Payment Card Industry Data Security Standard checks."""

    def __init__(self):
        super().__init__(ComplianceFramework.PCI_DSS)

    def execute(self, config: Dict) -> List[ComplianceIssue]:
        """Run all PCI-DSS checks."""
        issues = []

        # 1.1: Firewall configuration
        issues.extend(self._check_firewall_policy(config))

        # 2.1: Default credentials
        issues.extend(self._check_default_credentials(config))

        # 3.2: Encryption at rest
        issues.extend(self._check_encryption_at_rest(config))

        # 4.1: Encryption in transit
        issues.extend(self._check_encryption_in_transit(config))

        # 6.2: Security patches
        issues.extend(self._check_security_patches(config))

        # 7.1: Access control
        issues.extend(self._check_access_control(config))

        # 8.2: Strong authentication
        issues.extend(self._check_authentication(config))

        # 10.2: Logging
        issues.extend(self._check_logging(config))

        return issues

    def _check_firewall_policy(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 1.1: Firewall configuration standards."""
        issues = []
        firewall_config = config.get("firewall", {})

        if not firewall_config.get("enabled"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-1.1",
                    severity=Severity.CRITICAL,
                    title="Firewall Not Enabled",
                    description="Firewalls must be enabled and properly configured",
                    finding="Firewall is not enabled in configuration",
                    evidence="firewall.enabled = false",
                    remediation="Enable firewall and implement proper rule sets",
                    check_name="firewall_enabled",
                    passed=False,
                )
            )

        if firewall_config.get("default_deny_inbound") is not True:
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-1.1.1",
                    severity=Severity.HIGH,
                    title="Default Deny Inbound Not Set",
                    description="Firewall rules must default to deny",
                    finding="Firewall default inbound policy is not deny",
                    evidence="firewall.default_deny_inbound != true",
                    remediation="Set firewall to default deny inbound traffic",
                    check_name="firewall_default_deny",
                    passed=False,
                )
            )

        return issues

    def _check_default_credentials(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 2.1: Default credentials."""
        issues = []
        services = config.get("services", [])

        for service in services:
            if service.get("use_defaults", False):
                issues.append(
                    ComplianceIssue(
                        framework=self.framework,
                        control_id="PCI-DSS-2.1",
                        severity=Severity.CRITICAL,
                        title="Default Credentials Active",
                        description="Default passwords must be changed",
                        finding=f"Service '{service.get('name')}' using default credentials",
                        evidence=service.get("name"),
                        remediation="Change default credentials immediately",
                        check_name="default_credentials",
                        passed=False,
                    )
                )

        return issues

    def _check_encryption_at_rest(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 3.2: Data encryption at rest."""
        issues = []
        storage = config.get("storage", {})

        if not storage.get("encryption_at_rest_enabled"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-3.2",
                    severity=Severity.CRITICAL,
                    title="Encryption at Rest Not Enabled",
                    description="Sensitive data must be encrypted at rest",
                    finding="Encryption at rest is not enabled for storage",
                    evidence="storage.encryption_at_rest_enabled = false",
                    remediation="Enable encryption for all storage containing sensitive data",
                    check_name="encryption_at_rest",
                    passed=False,
                )
            )

        if storage.get("encryption_algorithm") and storage[
            "encryption_algorithm"
        ] not in [
            "AES-256",
            "AES-192",
        ]:
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-3.2.1",
                    severity=Severity.HIGH,
                    title="Weak Encryption Algorithm",
                    description="Must use strong cryptography",
                    finding=f"Encryption algorithm: {storage.get('encryption_algorithm')}",
                    evidence="Weak algorithm detected",
                    remediation="Use AES-256 or equivalent strong cryptography",
                    check_name="encryption_algorithm",
                    passed=False,
                )
            )

        return issues

    def _check_encryption_in_transit(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 4.1: TLS/SSL for data in transit."""
        issues = []
        network = config.get("network", {})

        if not network.get("tls_enabled"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-4.1",
                    severity=Severity.CRITICAL,
                    title="TLS Not Enabled",
                    description="All data transmission must use TLS 1.2 or higher",
                    finding="TLS is not enabled for data transmission",
                    evidence="network.tls_enabled = false",
                    remediation="Enable TLS 1.2 or higher for all data transmission",
                    check_name="tls_enabled",
                    passed=False,
                )
            )

        tls_version = network.get("tls_version", "1.0")
        if float(tls_version) < 1.2:
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-4.1",
                    severity=Severity.HIGH,
                    title="Outdated TLS Version",
                    description="TLS 1.0 and 1.1 are deprecated",
                    finding=f"TLS version: {tls_version}",
                    evidence="Old TLS version is in use",
                    remediation="Upgrade to TLS 1.2 or TLS 1.3",
                    check_name="tls_version",
                    passed=False,
                )
            )

        return issues

    def _check_security_patches(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 6.2: Security patches."""
        issues = []
        systems = config.get("systems", [])

        for system in systems:
            patch_level = system.get("patch_level", "unknown")
            if patch_level != "current":
                issues.append(
                    ComplianceIssue(
                        framework=self.framework,
                        control_id="PCI-DSS-6.2",
                        severity=Severity.HIGH,
                        title="Security Patches Not Current",
                        description="All system components must have current security patches",
                        finding=f"System '{system.get('name')}' patch level: {patch_level}",
                        evidence=system.get("name"),
                        remediation="Apply all available security patches promptly",
                        check_name="security_patches",
                        passed=False,
                    )
                )

        return issues

    def _check_access_control(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 7.1: Access control."""
        issues = []
        rbac = config.get("rbac", {})

        if not rbac.get("enabled"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-7.1",
                    severity=Severity.CRITICAL,
                    title="RBAC Not Implemented",
                    description="Role-based access must be implemented",
                    finding="RBAC is not enabled",
                    evidence="rbac.enabled = false",
                    remediation="Implement role-based access control (RBAC)",
                    check_name="rbac_enabled",
                    passed=False,
                )
            )

        if not rbac.get("least_privilege"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-7.1",
                    severity=Severity.HIGH,
                    title="Least Privilege Not Applied",
                    description="Users must have minimum necessary access",
                    finding="Least privilege principle not enforced",
                    evidence="rbac.least_privilege = false",
                    remediation="Apply least privilege principle to all user accounts",
                    check_name="least_privilege",
                    passed=False,
                )
            )

        return issues

    def _check_authentication(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 8.2: Strong authentication."""
        issues = []
        auth = config.get("authentication", {})

        if not auth.get("mfa_enabled"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-8.2",
                    severity=Severity.HIGH,
                    title="Multi-Factor Authentication Not Enabled",
                    description="MFA must be required for admin access",
                    finding="MFA is not enabled",
                    evidence="authentication.mfa_enabled = false",
                    remediation="Implement MFA for all administrative access",
                    check_name="mfa_enabled",
                    passed=False,
                )
            )

        if auth.get("password_min_length", 0) < 8:
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-8.2.3",
                    severity=Severity.HIGH,
                    title="Weak Password Policy",
                    description="Passwords must be at least 8 characters",
                    finding=f"Minimum password length: {auth.get('password_min_length')}",
                    evidence="Weak password requirements",
                    remediation="Enforce minimum 8-character passwords",
                    check_name="password_policy",
                    passed=False,
                )
            )

        return issues

    def _check_logging(self, config: Dict) -> List[ComplianceIssue]:
        """Check PCI-DSS 10.2: Audit logging."""
        issues = []
        logging = config.get("logging", {})

        if not logging.get("enabled"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-10.2",
                    severity=Severity.CRITICAL,
                    title="Audit Logging Not Enabled",
                    description="User access and changes must be logged",
                    finding="Audit logging is not enabled",
                    evidence="logging.enabled = false",
                    remediation="Enable comprehensive audit logging of all access and changes",
                    check_name="audit_logging",
                    passed=False,
                )
            )

        if logging.get("retention_days", 0) < 90:
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="PCI-DSS-10.7",
                    severity=Severity.MEDIUM,
                    title="Insufficient Log Retention",
                    description="Logs must be retained for at least 1 year",
                    finding=f"Log retention: {logging.get('retention_days')} days",
                    evidence="Retention period too short",
                    remediation="Retain audit logs for at least 1 year (at least 3 months online)",
                    check_name="log_retention",
                    passed=False,
                )
            )

        return issues


# ---------------------------------------------------------------------------
# HIPAA Checks (45 CFR §§ 164.308-314)
# ---------------------------------------------------------------------------
class HIPAAChecks(ComplianceCheck):
    """Health Insurance Portability and Accountability Act checks."""

    def __init__(self):
        super().__init__(ComplianceFramework.HIPAA)

    def execute(self, config: Dict) -> List[ComplianceIssue]:
        """Run all HIPAA checks."""
        issues = []

        # 164.308: Administrative safeguards
        issues.extend(self._check_security_governance(config))
        issues.extend(self._check_access_management(config))

        # 164.312: Technical safeguards
        issues.extend(self._check_encryption(config))
        issues.extend(self._check_authentication_hipaa(config))

        # 164.314: Physical safeguards
        issues.extend(self._check_physical_access(config))

        return issues

    def _check_security_governance(self, config: Dict) -> List[ComplianceIssue]:
        """Check 164.308: Security governance."""
        issues = []
        governance = config.get("governance", {})

        if not governance.get("security_officer_assigned"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="HIPAA-164.308(a)(2)",
                    severity=Severity.CRITICAL,
                    title="Security Officer Not Assigned",
                    description="A security officer must be designated",
                    finding="No security officer assigned",
                    evidence="governance.security_officer_assigned = false",
                    remediation="Designate a qualified security officer",
                    check_name="security_officer",
                    passed=False,
                )
            )

        return issues

    def _check_access_management(self, config: Dict) -> List[ComplianceIssue]:
        """Check 164.308: Access management."""
        issues = []
        access = config.get("access_management", {})

        if not access.get("access_control_implemented"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="HIPAA-164.308(a)(4)",
                    severity=Severity.CRITICAL,
                    title="Access Control Not Implemented",
                    description="Access must be controlled and managed",
                    finding="Access control not implemented",
                    evidence="access_management.access_control_implemented = false",
                    remediation="Implement comprehensive access control system",
                    check_name="access_control_hipaa",
                    passed=False,
                )
            )

        return issues

    def _check_encryption(self, config: Dict) -> List[ComplianceIssue]:
        """Check 164.312: Encryption."""
        issues = []
        encryption = config.get("encryption", {})

        if not encryption.get("phi_encrypted_at_rest"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="HIPAA-164.312(a)(2)(ii)",
                    severity=Severity.CRITICAL,
                    title="PHI Not Encrypted at Rest",
                    description="Protected health information must be encrypted at rest",
                    finding="PHI encryption at rest not enabled",
                    evidence="encryption.phi_encrypted_at_rest = false",
                    remediation="Encrypt all PHI at rest using approved algorithms",
                    check_name="phi_encryption_rest",
                    passed=False,
                )
            )

        if not encryption.get("phi_encrypted_in_transit"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="HIPAA-164.312(a)(2)(i)",
                    severity=Severity.CRITICAL,
                    title="PHI Not Encrypted in Transit",
                    description="PHI must be encrypted during transmission",
                    finding="PHI encryption in transit not enabled",
                    evidence="encryption.phi_encrypted_in_transit = false",
                    remediation="Encrypt all PHI during transmission using TLS",
                    check_name="phi_encryption_transit",
                    passed=False,
                )
            )

        return issues

    def _check_authentication_hipaa(self, config: Dict) -> List[ComplianceIssue]:
        """Check 164.312: Authentication."""
        issues = []
        auth = config.get("authentication_hipaa", {})

        if not auth.get("unique_user_id"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="HIPAA-164.312(a)(2)(i)",
                    severity=Severity.HIGH,
                    title="Unique User IDs Not Required",
                    description="Each user must have a unique identifier",
                    finding="Unique user IDs not enforced",
                    evidence="authentication_hipaa.unique_user_id = false",
                    remediation="Require unique user IDs for all system users",
                    check_name="unique_user_ids",
                    passed=False,
                )
            )

        return issues

    def _check_physical_access(self, config: Dict) -> List[ComplianceIssue]:
        """Check 164.314: Physical safeguards."""
        issues = []
        physical = config.get("physical_security", {})

        if not physical.get("access_control_entry"):
            issues.append(
                ComplianceIssue(
                    framework=self.framework,
                    control_id="HIPAA-164.314(a)(1)",
                    severity=Severity.CRITICAL,
                    title="Physical Access Control Missing",
                    description="Physical access to facilities must be controlled",
                    finding="Physical access control not implemented",
                    evidence="physical_security.access_control_entry = false",
                    remediation="Implement badge readers, locks, or other access controls",
                    check_name="physical_access_control",
                    passed=False,
                )
            )

        return issues


# ---------------------------------------------------------------------------
# Compliance Scanner Engine
# ---------------------------------------------------------------------------
class ComplianceScanner:
    """Main compliance scanning engine."""

    def __init__(self):
        self.checks_map = {
            ComplianceFramework.PCI_DSS: PCIDSSChecks(),
            ComplianceFramework.HIPAA: HIPAAChecks(),
        }

    def scan(
        self,
        config: Dict,
        frameworks: List[ComplianceFramework] = None,
    ) -> ComplianceScanResult:
        """Execute compliance scan."""
        if frameworks is None:
            frameworks = [ComplianceFramework.PCI_DSS, ComplianceFramework.HIPAA]

        result = ComplianceScanResult(frameworks=frameworks)
        result.scan_timestamp = time.time()
        start_time = time.time()

        for framework in frameworks:
            if framework in self.checks_map:
                issues = self.checks_map[framework].execute(config)
                result.issues.extend(issues)

                # Count passed/failed
                for issue in issues:
                    if issue.passed:
                        result.passed_checks += 1
                    else:
                        result.failed_checks += 1

        result.scan_duration = time.time() - start_time
        return result


# ---------------------------------------------------------------------------
# Report Formatting
# ---------------------------------------------------------------------------
def format_report(result: ComplianceScanResult) -> str:
    """Format compliance report."""
    lines = [
        f"\n{'='*80}",
        f"COMPLIANCE SCAN REPORT",
        f"{'='*80}",
        f"Scan Time:        {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.scan_timestamp))}",
        f"Duration:         {result.scan_duration:.2f}s",
        f"Frameworks:       {', '.join(f.value for f in result.frameworks)}",
        f"Compliance Score: {result.compliance_score:.1f}%",
        f"",
        f"RESULTS:",
        f"  Passed Checks:  {result.passed_checks}",
        f"  Failed Checks:  {result.failed_checks}",
        f"  Critical Issues: {len(result.critical_issues)}",
        f"",
    ]

    if result.critical_issues:
        lines.extend(
            [
                f"CRITICAL ISSUES:",
                f"{'-'*80}",
            ]
        )
        for issue in result.critical_issues:
            lines.extend(
                [
                    f"",
                    f"  Control:     {issue.control_id} ({issue.framework.value})",
                    f"  Title:       {issue.title}",
                    f"  Finding:     {issue.finding}",
                    f"  Remediation: {issue.remediation}",
                ]
            )

    if result.issues:
        lines.extend(
            [
                f"",
                f"ALL ISSUES BY SEVERITY:",
                f"{'-'*80}",
            ]
        )
        by_severity = {}
        for issue in result.issues:
            sev = issue.severity.value
            if sev not in by_severity:
                by_severity[sev] = 0
            by_severity[sev] += 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in by_severity:
                lines.append(f"  {sev.upper():<10}: {by_severity[sev]}")

    lines.append(f"{'='*80}\n")
    return "\n".join(lines)


if __name__ == "__main__":
    # Demo config
    demo_config = {
        "firewall": {"enabled": False, "default_deny_inbound": False},
        "storage": {"encryption_at_rest_enabled": False},
        "network": {"tls_enabled": False, "tls_version": "1.0"},
        "authentication": {"mfa_enabled": False, "password_min_length": 6},
        "logging": {"enabled": False, "retention_days": 30},
        "systems": [{"name": "web-server", "patch_level": "outdated"}],
    }

    scanner = ComplianceScanner()
    result = scanner.scan(demo_config)
    print(format_report(result))
