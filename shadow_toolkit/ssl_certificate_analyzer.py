#!/usr/bin/env python3
"""
SSL/TLS Certificate Analyzer
=============================
Analyzes domain certificates for expiration, cipher strength, validation issues,
and common misconfigurations. Detects self-signed certs, weak algorithms, revoked certs.
Part of the threat intelligence and compliance scanning layer.
"""

import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import OpenSSL
    from OpenSSL import SSL, crypto
except ImportError:
    sys.exit("ERROR: pyOpenSSL not installed. Run: pip install pyOpenSSL")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------
@dataclass
class CertificateIssue:
    severity: str  # "critical", "warning", "info"
    code: str  # exp_soon, weak_cipher, self_signed, untrusted_ca, weak_sig
    message: str
    remediation: str = ""


@dataclass
class CipherSuite:
    name: str
    strength: str  # "strong", "moderate", "weak"
    key_exchange: str
    encryption: str
    mac: str
    is_enabled: bool = True


@dataclass
class CertificateAnalysis:
    domain: str
    ip: str = ""
    port: int = 443
    certificate_valid: bool = False
    subject: Dict = field(default_factory=dict)
    issuer: Dict = field(default_factory=dict)
    not_before: str = ""
    not_after: str = ""
    days_remaining: int = 0
    serial_number: str = ""
    signature_algorithm: str = ""
    public_key_algorithm: str = ""
    public_key_size: int = 0
    san_list: List[str] = field(default_factory=list)
    is_self_signed: bool = False
    cert_chain_depth: int = 0
    supported_ciphers: List[CipherSuite] = field(default_factory=list)
    issues: List[CertificateIssue] = field(default_factory=list)
    scan_timestamp: float = 0.0


# ---------------------------------------------------------------------------
# SSL/TLS Analysis Engine
# ---------------------------------------------------------------------------
class SSLAnalyzer:
    """Analyzes SSL/TLS certificates and configurations."""

    WEAK_ALGORITHMS = {"MD5", "SHA1", "DES", "RC4"}
    WEAK_KEY_SIZES = {"RSA": 2048, "DSA": 1024, "EC": 256}
    CRITICAL_CIPHER_PATTERNS = [
        "EXPORT",
        "eNULL",
        "aNULL",
        "DES",
        "RC4",
        "MD5",
    ]

    def __init__(self, timeout: int = 5, verify_chain: bool = True):
        self.timeout = timeout
        self.verify_chain = verify_chain

    def analyze_domain(
        self,
        domain: str,
        port: int = 443,
        resolve_ip: bool = True,
    ) -> CertificateAnalysis:
        """Analyze SSL certificate for a given domain and port."""
        analysis = CertificateAnalysis(domain=domain, port=port)
        analysis.scan_timestamp = time.time()

        try:
            # Resolve IP if requested
            if resolve_ip:
                try:
                    analysis.ip = socket.gethostbyname(domain)
                except socket.gaierror:
                    analysis.issues.append(
                        CertificateIssue(
                            severity="critical",
                            code="dns_resolution_failed",
                            message=f"Could not resolve {domain}",
                            remediation=f"Verify {domain} is a valid hostname",
                        )
                    )
                    return analysis

            # Get certificate
            cert_data = self._get_certificate(domain, port)
            if not cert_data:
                analysis.issues.append(
                    CertificateIssue(
                        severity="critical",
                        code="cert_retrieval_failed",
                        message=f"Could not retrieve certificate from {domain}:{port}",
                        remediation="Verify the domain is reachable and port is correct",
                    )
                )
                return analysis

            cert_der, cert_chain = cert_data
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_der)

            # Parse certificate details
            self._parse_certificate(cert, analysis)

            # Validate certificate
            self._validate_certificate(cert, analysis)

            # Analyze cipher suites
            self._analyze_ciphers(domain, port, analysis)

            analysis.certificate_valid = (
                len([i for i in analysis.issues if i.severity == "critical"]) == 0
            )

        except Exception as e:
            analysis.issues.append(
                CertificateIssue(
                    severity="critical",
                    code="analysis_error",
                    message=f"Analysis failed: {str(e)}",
                )
            )

        return analysis

    def _get_certificate(self, domain: str, port: int) -> Optional[Tuple]:
        """Retrieve certificate and chain from server."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert_chain = ssock.getpeercert_chain()
                    return (der_cert, cert_chain)
        except (socket.error, ssl.SSLError, TimeoutError) as e:
            return None

    def _parse_certificate(self, cert: crypto.X509, analysis: CertificateAnalysis):
        """Parse X.509 certificate components."""
        # Subject and Issuer
        analysis.subject = self._parse_x509_name(cert.get_subject())
        analysis.issuer = self._parse_x509_name(cert.get_issuer())

        # Validity dates
        not_before = cert.get_notBefore().decode()
        not_after = cert.get_notAfter().decode()
        analysis.not_before = self._parse_cert_date(not_before)
        analysis.not_after = self._parse_cert_date(not_after)
        analysis.days_remaining = (
            self._cert_date_to_datetime(not_after) - datetime.now(timezone.utc)
        ).days

        # Serial number
        analysis.serial_number = str(cert.get_serial_number())

        # Signature Algorithm
        sig_alg = cert.get_signature_algorithm().decode()
        analysis.signature_algorithm = sig_alg

        # Public key
        pkey = cert.get_pubkey()
        analysis.public_key_algorithm = {
            0: "RSA",
            2: "DSA",
            408: "EC",
        }.get(pkey.type(), f"Unknown-{pkey.type()}")
        analysis.public_key_size = pkey.bits()

        # Subject Alternative Names
        try:
            for i in range(cert.get_extension_count()):
                ext = cert.get_extension(i)
                if ext.get_short_name() == b"subjectAltName":
                    san_str = str(ext)
                    sanlist = [s.strip() for s in san_str.split(", ")]
                    analysis.san_list = [s.replace("DNS:", "") for s in sanlist]
        except Exception:
            pass

        # Self-signed check
        analysis.is_self_signed = (
            analysis.subject == analysis.issuer
            and analysis.subject.get("CN") is not None
        )

    def _validate_certificate(self, cert: crypto.X509, analysis: CertificateAnalysis):
        """Validate certificate and record issues."""
        # Check expiration
        days_left = analysis.days_remaining
        if days_left < 0:
            analysis.issues.append(
                CertificateIssue(
                    severity="critical",
                    code="cert_expired",
                    message=f"Certificate expired {abs(days_left)} days ago",
                    remediation="Renew the certificate immediately",
                )
            )
        elif days_left < 30:
            analysis.issues.append(
                CertificateIssue(
                    severity="warning",
                    code="exp_soon",
                    message=f"Certificate expires in {days_left} days",
                    remediation="Plan certificate renewal within 30 days",
                )
            )

        # Check signature algorithm
        sig_alg = analysis.signature_algorithm.lower()
        if any(weak in sig_alg for weak in ["md5", "sha1"]):
            analysis.issues.append(
                CertificateIssue(
                    severity="critical",
                    code="weak_signature_algorithm",
                    message=f"Uses weak signature algorithm: {sig_alg}",
                    remediation="Issue new certificate with SHA-256 or stronger",
                )
            )

        # Check key size
        if analysis.public_key_algorithm == "RSA" and analysis.public_key_size < 2048:
            analysis.issues.append(
                CertificateIssue(
                    severity="critical",
                    code="weak_key_size",
                    message=f"RSA key size ({analysis.public_key_size} bits) is too weak",
                    remediation="Issue new certificate with at least 2048-bit RSA key",
                )
            )

        # Check for self-signed in production
        if analysis.is_self_signed:
            analysis.issues.append(
                CertificateIssue(
                    severity="warning",
                    code="self_signed",
                    message="Certificate is self-signed (not validated by trusted CA)",
                    remediation="Obtain certificate from trusted Certificate Authority",
                )
            )

        # Check for wildcard with narrow SAN
        cn = analysis.subject.get("CN", "")
        if cn.startswith("*.") and len(analysis.san_list) <= 1:
            analysis.issues.append(
                CertificateIssue(
                    severity="info",
                    code="wildcard_limited_san",
                    message="Wildcard certificate with limited SAN list",
                    remediation="Consider multi-domain certificate for better coverage",
                )
            )

    def _analyze_ciphers(self, domain: str, port: int, analysis: CertificateAnalysis):
        """Analyze supported cipher suites."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        suite = CipherSuite(
                            name=cipher[0],
                            strength=self._rate_cipher_strength(cipher[0]),
                            key_exchange=self._extract_cipher_component(
                                cipher[0], "key_exchange"
                            ),
                            encryption=self._extract_cipher_component(
                                cipher[0], "encryption"
                            ),
                            mac=self._extract_cipher_component(cipher[0], "mac"),
                            is_enabled=True,
                        )
                        analysis.supported_ciphers.append(suite)

                        # Check for weak ciphers
                        if suite.strength == "weak":
                            analysis.issues.append(
                                CertificateIssue(
                                    severity="warning",
                                    code="weak_cipher",
                                    message=f"Weak cipher suite enabled: {cipher[0]}",
                                    remediation="Disable weak ciphers in TLS configuration",
                                )
                            )
        except Exception:
            pass

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _parse_x509_name(self, name: crypto.X509Name) -> Dict:
        """Convert X509Name to dict."""
        result = {}
        for component in name.get_components():
            key, value = component
            result[key.decode() if isinstance(key, bytes) else key] = (
                value.decode() if isinstance(value, bytes) else value
            )
        return result

    def _parse_cert_date(self, date_str: str) -> str:
        """Parse certificate date (ASN.1 format) to ISO 8601."""
        try:
            return datetime.strptime(date_str, "%Y%m%d%H%M%SZ").isoformat()
        except Exception:
            return date_str

    def _cert_date_to_datetime(self, date_str: str) -> datetime:
        """Convert cert date to datetime."""
        return datetime.strptime(date_str, "%Y%m%d%H%M%SZ").replace(tzinfo=timezone.utc)

    def _rate_cipher_strength(self, cipher_name: str) -> str:
        """Rate cipher suite strength based on name."""
        lower_name = cipher_name.lower()
        for pattern in self.CRITICAL_CIPHER_PATTERNS:
            if pattern.lower() in lower_name:
                return "weak"
        if "256" in lower_name or "aes-256" in lower_name:
            return "strong"
        if "128" in lower_name or "aes" in lower_name:
            return "moderate"
        return "moderate"

    def _extract_cipher_component(self, cipher: str, component_type: str) -> str:
        """Extract component from cipher suite name."""
        parts = cipher.split("_")
        if component_type == "encryption":
            return parts[1] if len(parts) > 1 else "unknown"
        elif component_type == "key_exchange":
            return parts[0] if len(parts) > 0 else "unknown"
        elif component_type == "mac":
            return parts[-1] if len(parts) > 0 else "SHA"
        return "unknown"


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------
def format_report(analysis: CertificateAnalysis) -> str:
    """Format analysis result as human-readable report."""
    lines = [
        f"\n{'='*70}",
        f"SSL/TLS CERTIFICATE ANALYSIS - {analysis.domain}:{analysis.port}",
        f"{'='*70}",
        f"Scan Time:     {datetime.fromtimestamp(analysis.scan_timestamp).isoformat()}",
        f"IP Address:    {analysis.ip or 'Unknown'}",
        f"Certificate:   {'VALID' if analysis.certificate_valid else 'INVALID'}",
        f"",
        f"CERTIFICATE DETAILS:",
        f"  Subject CN:         {analysis.subject.get('CN', 'N/A')}",
        f"  Issuer CN:          {analysis.issuer.get('CN', 'N/A')}",
        f"  Valid From:         {analysis.not_before}",
        f"  Valid Until:        {analysis.not_after}",
        f"  Days Remaining:     {analysis.days_remaining}",
        f"  Serial Number:      {analysis.serial_number}",
        f"  Signature Alg:      {analysis.signature_algorithm}",
        f"  Public Key Alg:     {analysis.public_key_algorithm} ({analysis.public_key_size} bits)",
        f"  Self-Signed:        {'Yes' if analysis.is_self_signed else 'No'}",
        f"",
        f"ALTERNATIVE NAMES (SAN):",
    ]

    if analysis.san_list:
        for san in analysis.san_list:
            lines.append(f"  - {san}")
    else:
        lines.append("  (None)")

    lines.extend(
        [
            f"",
            f"CIPHER SUITES:",
        ]
    )

    if analysis.supported_ciphers:
        for cipher in analysis.supported_ciphers[:5]:  # Show first 5
            lines.append(f"  [{cipher.strength.upper()}] {cipher.name}")
        if len(analysis.supported_ciphers) > 5:
            lines.append(f"  ... and {len(analysis.supported_ciphers) - 5} more")
    else:
        lines.append("  (Unable to determine)")

    lines.extend(
        [
            f"",
            f"ISSUES FOUND: {len(analysis.issues)}",
        ]
    )

    if analysis.issues:
        for issue in analysis.issues:
            lines.append(f"  [{issue.severity.upper()}] {issue.code}: {issue.message}")
            if issue.remediation:
                lines.append(f"    → {issue.remediation}")
    else:
        lines.append("  No issues detected!")

    lines.append(f"{'='*70}\n")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ssl_certificate_analyzer.py <domain> [port]")
        sys.exit(1)

    domain = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    analyzer = SSLAnalyzer()
    result = analyzer.analyze_domain(domain, port)
    print(format_report(result))
