from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel, Field


SeverityLevel = Literal["info", "warning", "critical"]


class TelemetryPacket(BaseModel):
    module: str
    event: str
    severity: SeverityLevel = "info"
    timestamp: float = Field(default_factory=time.time)
    payload: dict[str, Any] = Field(default_factory=dict)


# -----------------------------------------------
# Phase 1: Advanced Detection Module Events
# -----------------------------------------------


class SSLCertificateEvent(BaseModel):
    """SSL/TLS certificate analysis event."""

    domain: str
    port: int = 443
    certificate_valid: bool
    days_remaining: int
    issues_count: int
    critical_issues: list[str] = Field(default_factory=list)
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0


class SecretDetectionEvent(BaseModel):
    """Secret/credential detection event."""

    file_path: str
    secret_type: str  # api_key, password, private_key, etc.
    pattern_name: str
    confidence: int  # 0-100
    entropy_score: float
    line_number: int
    line_content: str = ""  # First 50 chars only for safe logging


class ComplianceEvent(BaseModel):
    """Compliance scan event."""

    framework: str  # pci_dss, hipaa, soc2, etc.
    control_id: str
    severity: str  # critical, high, medium, low, info
    title: str
    finding: str
    remediation: str
    compliance_score: float = 0.0  # 0-100
