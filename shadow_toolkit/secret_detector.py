#!/usr/bin/env python3
"""
Secret Detection Engine
=======================
Scans code, configurations, and repositories for exposed secrets:
API keys, tokens, credentials, certificates, SSH keys, database passwords.
Uses entropy analysis, regex patterns, and entropy-based detection.
Part of the compliance and threat detection layer.
"""

import re
import sys
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set
from concurrent.futures import ThreadPoolExecutor, as_completed


# ---------------------------------------------------------------------------
# Enums & Data Structures
# ---------------------------------------------------------------------------
class SecretType(Enum):
    """Categories of secrets."""

    API_KEY = "api_key"
    DATABASE_PASSWORD = "db_password"
    PRIVATE_KEY = "private_key"
    ACCESS_TOKEN = "access_token"
    WEBHOOK_URL = "webhook_url"
    SSH_KEY = "ssh_key"
    AWS_CREDENTIALS = "aws_credentials"
    AZURE_CREDENTIALS = "azure_credentials"
    GCP_CREDENTIALS = "gcp_credentials"
    SLACK_TOKEN = "slack_token"
    GITHUB_TOKEN = "github_token"
    GENERIC_PASSWORD = "generic_password"
    CONNECTION_STRING = "connection_string"
    ENCRYPTION_KEY = "encryption_key"
    JWT_TOKEN = "jwt_token"


@dataclass
class Secret:
    """Represents a detected secret."""

    type: SecretType
    pattern_name: str
    matched_value: str  # First 20 chars + "..." for display
    full_match: str  # Full matched string (for confirmation)
    line_number: int
    column_start: int
    column_end: int
    file_path: str
    confidence: int  # 0-100
    entropy_score: float  # 0.0-8.0 (Shannon entropy)
    context: str  # Surrounding code snippet
    remediation: str = ""


@dataclass
class ScanResult:
    """Results from secret scanning session."""

    files_scanned: int = 0
    secrets_found: List[Secret] = field(default_factory=list)
    scan_duration: float = 0.0
    scan_timestamp: float = 0.0
    files_skipped: List[str] = field(default_factory=list)

    @property
    def high_confidence_secrets(self) -> List[Secret]:
        """Filter secrets with confidence >= 80."""
        return [s for s in self.secrets_found if s.confidence >= 80]

    @property
    def critical_secrets(self) -> List[Secret]:
        """Filter critical secret types."""
        critical_types = {
            SecretType.AWS_CREDENTIALS,
            SecretType.AZURE_CREDENTIALS,
            SecretType.PRIVATE_KEY,
            SecretType.DATABASE_PASSWORD,
        }
        return [s for s in self.secrets_found if s.type in critical_types]


# ---------------------------------------------------------------------------
# Secret Patterns Database
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    # AWS Credentials
    "AWS_KEY": {
        "pattern": r"(AKIA[0-9A-Z]{16})",
        "type": SecretType.AWS_CREDENTIALS,
        "confidence": 95,
        "description": "AWS Access Key ID",
    },
    "AWS_SECRET": {
        "pattern": r"aws_secret_access_key\s*=\s*['\"]([a-zA-Z0-9/+=]{40})['\"]",
        "type": SecretType.AWS_CREDENTIALS,
        "confidence": 90,
        "description": "AWS Secret Key",
    },
    # Azure Credentials
    "AZURE_CONN_STRING": {
        "pattern": r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+;",
        "type": SecretType.AZURE_CREDENTIALS,
        "confidence": 95,
        "description": "Azure Storage Connection String",
    },
    "AZURE_SAS": {
        "pattern": r"(?:sv|sig)=\w+&(?:se|sp)[^'\"]*(?:skn|sks)=\w+",
        "type": SecretType.AZURE_CREDENTIALS,
        "confidence": 85,
        "description": "Azure SAS Token",
    },
    # GitHub/GitLab Tokens
    "GITHUB_TOKEN": {
        "pattern": r"(ghp_[a-zA-Z0-9_]{36}|gho_[a-zA-Z0-9_]{36}|ghu_[a-zA-Z0-9_]{36})",
        "type": SecretType.GITHUB_TOKEN,
        "confidence": 95,
        "description": "GitHub Personal Access Token",
    },
    "GITLAB_TOKEN": {
        "pattern": r"(?:glpat-|glprivate-)[a-zA-Z0-9\-_]{20,}",
        "type": SecretType.GITHUB_TOKEN,
        "confidence": 90,
        "description": "GitLab Private Token",
    },
    # API Keys (Generic)
    "API_KEY_GENERIC": {
        "pattern": r"(?:api_key|apikey|api-key|key)\s*[=:]\s*['\"]([a-zA-Z0-9\-_]{20,})['\"]",
        "type": SecretType.API_KEY,
        "confidence": 60,
        "description": "Generic API Key",
    },
    "SLACK_BOT_TOKEN": {
        "pattern": r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}",
        "type": SecretType.SLACK_TOKEN,
        "confidence": 95,
        "description": "Slack Bot Token",
    },
    "SLACK_WEBHOOK": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        "type": SecretType.WEBHOOK_URL,
        "confidence": 95,
        "description": "Slack Webhook URL",
    },
    # Database Passwords
    "DB_PASSWORD": {
        "pattern": r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]",
        "type": SecretType.DATABASE_PASSWORD,
        "confidence": 65,
        "description": "Database Password",
    },
    "MONGODB_URI": {
        "pattern": r"mongodb\+srv://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]{8,}@",
        "type": SecretType.CONNECTION_STRING,
        "confidence": 90,
        "description": "MongoDB Connection String",
    },
    "MYSQL_CONN": {
        "pattern": r"mysql://[a-zA-Z0-9]+:[a-zA-Z0-9!@#$%^&*()_+=\-]{6,}@",
        "type": SecretType.CONNECTION_STRING,
        "confidence": 85,
        "description": "MySQL Connection String",
    },
    # SSH/Private Keys
    "PRIVATE_KEY": {
        "pattern": r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY",
        "type": SecretType.PRIVATE_KEY,
        "confidence": 98,
        "description": "Private Key File",
    },
    # JWT Tokens
    "JWT_TOKEN": {
        "pattern": r"eyJhbGciOiJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_\-]+",
        "type": SecretType.JWT_TOKEN,
        "confidence": 85,
        "description": "JWT Token",
    },
    # Connection Strings
    "CONNECTION_STRING": {
        "pattern": r"(?:server|host)=[^;]+;(?:password|pwd)=[^;]+;",
        "type": SecretType.CONNECTION_STRING,
        "confidence": 70,
        "description": "Database Connection String",
    },
    # Encryption Keys
    "ENCRYPTION_KEY": {
        "pattern": r"encryption_key\s*[=:]\s*['\"]([a-zA-Z0-9/+=]{16,})['\"]",
        "type": SecretType.ENCRYPTION_KEY,
        "confidence": 75,
        "description": "Encryption Key",
    },
}

# File extensions to skip (binaries, compiled code, etc.)
SKIP_EXTENSIONS = {
    ".pyc",
    ".exe",
    ".dll",
    ".so",
    ".bin",
    ".zip",
    ".tar",
    ".gz",
    ".jpg",
    ".png",
    ".gif",
    ".pdf",
}

SKIP_DIRS = {".git", ".venv", "node_modules", "__pycache__", ".egg-info"}


# ---------------------------------------------------------------------------
# Secret Detection Engine
# ---------------------------------------------------------------------------
class SecretDetector:
    """Detects secrets in code and configuration files."""

    def __init__(self, entropy_threshold: float = 3.5):
        """
        Initialize detector.
        Args:
            entropy_threshold: Minimum Shannon entropy to flag as potential secret
        """
        self.entropy_threshold = entropy_threshold
        self.compiled_patterns = {
            name: re.compile(spec["pattern"], re.IGNORECASE)
            for name, spec in SECRET_PATTERNS.items()
        }

    def scan_directory(
        self,
        directory: Path,
        max_workers: int = 4,
        recursive: bool = True,
    ) -> ScanResult:
        """Scan directory for secrets."""
        result = ScanResult(scan_timestamp=time.time())
        start_time = time.time()

        # Collect files to scan
        files_to_scan = self._collect_files(directory, recursive)
        result.files_scanned = len(files_to_scan)

        # Scan files in parallel
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(self.scan_file, file_path): file_path
                for file_path in files_to_scan
            }

            for future in as_completed(futures):
                file_path = futures[future]
                try:
                    secrets = future.result()
                    result.secrets_found.extend(secrets)
                except Exception as e:
                    result.files_skipped.append(str(file_path))

        result.scan_duration = time.time() - start_time
        return result

    def scan_file(self, file_path: Path) -> List[Secret]:
        """Scan single file for secrets."""
        secrets = []

        # Skip files by extension or size
        if file_path.suffix in SKIP_EXTENSIONS:
            return secrets
        if file_path.stat().st_size > 10 * 1024 * 1024:  # Skip files > 10MB
            return secrets

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return secrets

        # Apply patterns
        for pattern_name, compiled_regex in self.compiled_patterns.items():
            spec = SECRET_PATTERNS[pattern_name]
            for match_obj in compiled_regex.finditer(content):
                # Calculate line number
                line_num = content[: match_obj.start()].count("\n") + 1
                line_start = content.rfind("\n", 0, match_obj.start()) + 1
                col_start = match_obj.start() - line_start
                col_end = match_obj.end() - line_start

                full_match = match_obj.group(0)
                display_value = (
                    full_match[:20] + "..." if len(full_match) > 20 else full_match
                )

                # Get context lines
                lines = content.split("\n")
                context_start = max(0, line_num - 2)
                context_end = min(len(lines), line_num + 1)
                context = "\n".join(lines[context_start:context_end])

                # Calculate entropy
                entropy = self._shannon_entropy(full_match)

                # Confidence adjustment based on entropy
                confidence = spec["confidence"]
                if entropy > 5.0:  # High entropy boosting confidence
                    confidence = min(100, confidence + 10)

                secret = Secret(
                    type=spec["type"],
                    pattern_name=pattern_name,
                    matched_value=display_value,
                    full_match=full_match,
                    line_number=line_num,
                    column_start=col_start,
                    column_end=col_end,
                    file_path=str(file_path),
                    confidence=confidence,
                    entropy_score=entropy,
                    context=context,
                    remediation=self._get_remediation(spec["type"]),
                )
                secrets.append(secret)

        return secrets

    def scan_text(self, text: str, source_name: str = "input") -> List[Secret]:
        """Scan arbitrary text for secrets."""
        secrets = []

        for pattern_name, compiled_regex in self.compiled_patterns.items():
            spec = SECRET_PATTERNS[pattern_name]
            for match_obj in compiled_regex.finditer(text):
                line_num = text[: match_obj.start()].count("\n") + 1
                full_match = match_obj.group(0)
                display_value = (
                    full_match[:20] + "..." if len(full_match) > 20 else full_match
                )

                secret = Secret(
                    type=spec["type"],
                    pattern_name=pattern_name,
                    matched_value=display_value,
                    full_match=full_match,
                    line_number=line_num,
                    column_start=0,
                    column_end=len(full_match),
                    file_path=source_name,
                    confidence=spec["confidence"],
                    entropy_score=self._shannon_entropy(full_match),
                    context=text,
                    remediation=self._get_remediation(spec["type"]),
                )
                secrets.append(secret)

        return secrets

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------
    def _collect_files(self, directory: Path, recursive: bool) -> List[Path]:
        """Collect files to scan."""
        files = []
        if recursive:
            for path in directory.rglob("*"):
                if path.is_file() and not self._should_skip_path(path):
                    files.append(path)
        else:
            for path in directory.iterdir():
                if path.is_file() and not self._should_skip_path(path):
                    files.append(path)
        return files

    def _should_skip_path(self, path: Path) -> bool:
        """Check if path should be skipped."""
        for skip_dir in SKIP_DIRS:
            if skip_dir in path.parts:
                return True
        return False

    def _shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text."""
        if not text:
            return 0.0
        entropy = 0.0
        for byte in set(text):
            freq = text.count(byte) / len(text)
            entropy -= freq * (freq and __import__("math").log2(freq) or 0)
        return entropy

    def _get_remediation(self, secret_type: SecretType) -> str:
        """Get remediation guidance for secret type."""
        remediations = {
            SecretType.AWS_CREDENTIALS: "Rotate AWS credentials immediately and audit access logs",
            SecretType.AZURE_CREDENTIALS: "Revoke access keys/SAS tokens and regenerate",
            SecretType.PRIVATE_KEY: "Revoke private key and generate new one; audit logs",
            SecretType.DATABASE_PASSWORD: "Change database password immediately",
            SecretType.GITHUB_TOKEN: "Revoke token in GitHub settings and regenerate",
            SecretType.SLACK_TOKEN: "Revoke token in Slack workspace settings",
            SecretType.CONNECTION_STRING: "Rotate database credentials",
            SecretType.JWT_TOKEN: "Regenerate JWT; audit token usage",
            SecretType.ENCRYPTION_KEY: "Change encryption key and re-encrypt data",
        }
        return remediations.get(secret_type, "Rotate credential and audit usage")


# ---------------------------------------------------------------------------
# Report Formatting
# ---------------------------------------------------------------------------
def format_report(result: ScanResult) -> str:
    """Format scan result as human-readable report."""
    lines = [
        f"\n{'='*80}",
        f"SECRET DETECTION SCAN REPORT",
        f"{'='*80}",
        f"Scan Time:        {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(result.scan_timestamp))}",
        f"Duration:         {result.scan_duration:.2f}s",
        f"Files Scanned:    {result.files_scanned}",
        f"Files Skipped:    {len(result.files_skipped)}",
        f"Secrets Found:    {len(result.secrets_found)}",
        f"Critical Secrets: {len(result.critical_secrets)}",
        f"High Confidence:  {len(result.high_confidence_secrets)}",
        f"",
    ]

    if result.secrets_found:
        lines.extend(
            [
                f"DETECTED SECRETS (sorted by confidence):",
                f"{'-'*80}",
            ]
        )
        for secret in sorted(
            result.secrets_found, key=lambda s: s.confidence, reverse=True
        )[
            :10
        ]:  # Show top 10
            lines.extend(
                [
                    f"",
                    f"  Type:        {secret.type.value}",
                    f"  Pattern:     {secret.pattern_name}",
                    f"  File:        {secret.file_path}",
                    f"  Line:        {secret.line_number}",
                    f"  Confidence:  {secret.confidence}%",
                    f"  Entropy:     {secret.entropy_score:.2f}",
                    f"  Value:       {secret.matched_value}",
                    f"  Remediation: {secret.remediation}",
                ]
            )
    else:
        lines.append("✓ No secrets detected!")

    lines.append(f"{'='*80}\n")
    return "\n".join(lines)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python secret_detector.py <directory_or_file>")
        sys.exit(1)

    target = Path(sys.argv[1])
    detector = SecretDetector()

    if target.is_dir():
        result = detector.scan_directory(target)
    else:
        secrets = detector.scan_file(target)
        result = ScanResult(files_scanned=1, secrets_found=secrets)

    print(format_report(result))
