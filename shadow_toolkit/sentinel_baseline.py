#!/usr/bin/env python3
"""
Sentinel Baseline — Behavioral Baseline & Z-Score Anomaly Engine
================================================================
Collects system telemetry (processes, connections, bandwidth),
maintains a rolling 7-day baseline, and flags anomalies via Z-score.
Part of the Sovereign Pulse operational layer.
"""

import json
import os
import time
import math
import socket
import subprocess
import platform
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", os.path.join("C:\\Logs", "sentinel")))
BASELINE_FILE = DATA_DIR / "baseline_samples.json"
ANOMALY_LOG = DATA_DIR / "anomalies.json"
ZSCORE_THRESHOLD = 3.0
ROLLING_WINDOW_DAYS = 7
MAX_SAMPLES = ROLLING_WINDOW_DAYS * 24  # hourly samples for 7 days


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------
@dataclass
class TelemetrySample:
    timestamp: str
    process_count: int = 0
    connection_count: int = 0
    listening_ports: int = 0
    established_connections: int = 0
    unique_remote_ips: int = 0
    cpu_load: float = 0.0


@dataclass
class BaselineStats:
    metric: str
    mean: float = 0.0
    std_dev: float = 0.0
    sample_count: int = 0
    last_updated: str = ""


@dataclass
class AnomalyEvent:
    timestamp: str
    metric: str
    observed: float
    mean: float
    std_dev: float
    zscore: float
    severity: str  # INFO / LOW / MEDIUM / HIGH / CRITICAL
    source: str = "behavioral"

    @property
    def badge(self) -> str:
        return "ANOMALY"


# ---------------------------------------------------------------------------
# Telemetry Collection
# ---------------------------------------------------------------------------
def collect_telemetry() -> TelemetrySample:
    """Gather a single telemetry snapshot from the host."""
    sample = TelemetrySample(timestamp=datetime.utcnow().isoformat())

    # Process count
    if platform.system() == "Windows":
        try:
            out = subprocess.check_output(
                ["tasklist", "/FO", "CSV", "/NH"],
                stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
            sample.process_count = len([l for l in out.strip().splitlines() if l.strip()])
        except Exception:
            pass

        # Network connections via netstat
        try:
            out = subprocess.check_output(
                ["netstat", "-an"],
                stderr=subprocess.DEVNULL, text=True, timeout=10,
            )
            lines = out.strip().splitlines()
            remote_ips = set()
            for line in lines:
                parts = line.split()
                if len(parts) >= 4:
                    state = parts[-1] if len(parts) >= 5 else ""
                    if "ESTABLISHED" in state:
                        sample.established_connections += 1
                    if "LISTENING" in state or "LISTEN" in state:
                        sample.listening_ports += 1
                    # Extract remote IP
                    if len(parts) >= 3 and ":" in parts[2]:
                        ip = parts[2].rsplit(":", 1)[0]
                        if ip not in ("0.0.0.0", "*", "[::]", "[::1]", "127.0.0.1"):
                            remote_ips.add(ip)
            sample.connection_count = sample.established_connections + sample.listening_ports
            sample.unique_remote_ips = len(remote_ips)
        except Exception:
            pass
    else:
        # Linux / macOS
        try:
            out = subprocess.check_output(["ps", "aux"], stderr=subprocess.DEVNULL, text=True, timeout=10)
            sample.process_count = max(0, len(out.strip().splitlines()) - 1)
        except Exception:
            pass
        try:
            out = subprocess.check_output(["ss", "-tun"], stderr=subprocess.DEVNULL, text=True, timeout=10)
            lines = out.strip().splitlines()[1:]  # skip header
            remote_ips = set()
            for line in lines:
                parts = line.split()
                if len(parts) >= 5:
                    if "ESTAB" in parts[0]:
                        sample.established_connections += 1
                    if "LISTEN" in parts[0]:
                        sample.listening_ports += 1
                    peer = parts[4]
                    ip = peer.rsplit(":", 1)[0]
                    if ip not in ("0.0.0.0", "*", "::", "::1", "127.0.0.1"):
                        remote_ips.add(ip)
            sample.connection_count = sample.established_connections + sample.listening_ports
            sample.unique_remote_ips = len(remote_ips)
        except Exception:
            pass

    return sample


# ---------------------------------------------------------------------------
# Baseline Storage
# ---------------------------------------------------------------------------
def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_samples() -> List[dict]:
    """Load stored telemetry samples from disk."""
    if not BASELINE_FILE.exists():
        return []
    with open(BASELINE_FILE, "r") as f:
        return json.load(f)


def save_samples(samples: List[dict]):
    """Persist telemetry samples, trimming to rolling window."""
    _ensure_data_dir()
    cutoff = (datetime.utcnow() - timedelta(days=ROLLING_WINDOW_DAYS)).isoformat()
    trimmed = [s for s in samples if s.get("timestamp", "") >= cutoff]
    trimmed = trimmed[-MAX_SAMPLES:]
    with open(BASELINE_FILE, "w") as f:
        json.dump(trimmed, f, indent=2)


def record_sample(sample: TelemetrySample) -> List[dict]:
    """Add a new sample and persist."""
    samples = load_samples()
    samples.append(asdict(sample))
    save_samples(samples)
    return samples


# ---------------------------------------------------------------------------
# Z-Score Calculation
# ---------------------------------------------------------------------------
METRICS = [
    "process_count",
    "connection_count",
    "listening_ports",
    "established_connections",
    "unique_remote_ips",
]


def compute_baseline(samples: List[dict]) -> dict:
    """Compute mean and std_dev for each metric from stored samples."""
    stats = {}
    for metric in METRICS:
        values = [s.get(metric, 0) for s in samples]
        n = len(values)
        if n == 0:
            stats[metric] = BaselineStats(metric=metric)
            continue
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        std_dev = math.sqrt(variance)
        stats[metric] = BaselineStats(
            metric=metric,
            mean=round(mean, 2),
            std_dev=round(std_dev, 2),
            sample_count=n,
            last_updated=datetime.utcnow().isoformat(),
        )
    return stats


def calculate_zscore(value: float, mean: float, std_dev: float) -> float:
    """Calculate Z-score. Returns 0.0 if std_dev is zero."""
    if std_dev == 0:
        return 0.0
    return round((value - mean) / std_dev, 2)


def classify_severity(zscore: float) -> str:
    """Map absolute Z-score to severity level."""
    az = abs(zscore)
    if az >= 5.0:
        return "CRITICAL"
    elif az >= 4.0:
        return "HIGH"
    elif az >= 3.0:
        return "MEDIUM"
    elif az >= 2.0:
        return "LOW"
    return "INFO"


def detect_anomalies(sample: TelemetrySample, baseline: dict, threshold: float = ZSCORE_THRESHOLD) -> List[AnomalyEvent]:
    """Compare a telemetry sample against the baseline and flag anomalies."""
    anomalies = []
    sample_dict = asdict(sample)
    for metric in METRICS:
        stats = baseline.get(metric)
        if not stats or stats.sample_count < 3:
            continue
        value = sample_dict.get(metric, 0)
        z = calculate_zscore(value, stats.mean, stats.std_dev)
        if abs(z) >= threshold:
            anomalies.append(AnomalyEvent(
                timestamp=sample.timestamp,
                metric=metric,
                observed=value,
                mean=stats.mean,
                std_dev=stats.std_dev,
                zscore=z,
                severity=classify_severity(z),
            ))
    return anomalies


def log_anomalies(anomalies: List[AnomalyEvent]):
    """Append anomaly events to the persistent log."""
    _ensure_data_dir()
    existing = []
    if ANOMALY_LOG.exists():
        with open(ANOMALY_LOG, "r") as f:
            existing = json.load(f)
    existing.extend([asdict(a) for a in anomalies])
    # Keep last 1000 events
    existing = existing[-1000:]
    with open(ANOMALY_LOG, "w") as f:
        json.dump(existing, f, indent=2)


def load_anomalies(days: int = 7) -> List[dict]:
    """Load recent anomaly events."""
    if not ANOMALY_LOG.exists():
        return []
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    with open(ANOMALY_LOG, "r") as f:
        events = json.load(f)
    return [e for e in events if e.get("timestamp", "") >= cutoff]


# ---------------------------------------------------------------------------
# Sparkline Data
# ---------------------------------------------------------------------------
def get_sparkline_data(metric: str = "process_count", points: int = 24) -> dict:
    """Return baseline vs actual data for sparkline rendering."""
    samples = load_samples()
    baseline = compute_baseline(samples)
    stats = baseline.get(metric)
    recent = samples[-points:] if len(samples) >= points else samples

    actual_values = [s.get(metric, 0) for s in recent]
    timestamps = [s.get("timestamp", "")[:16] for s in recent]
    baseline_value = stats.mean if stats else 0

    return {
        "metric": metric,
        "timestamps": timestamps,
        "actual": actual_values,
        "baseline": [baseline_value] * len(actual_values),
        "threshold_upper": round(baseline_value + (stats.std_dev * ZSCORE_THRESHOLD if stats else 0), 2),
        "threshold_lower": round(baseline_value - (stats.std_dev * ZSCORE_THRESHOLD if stats else 0), 2),
        "sample_count": stats.sample_count if stats else 0,
    }


# ---------------------------------------------------------------------------
# Cache Freshness
# ---------------------------------------------------------------------------
def baseline_age_seconds() -> Optional[float]:
    """Return how many seconds since the last baseline sample, or None if no data."""
    samples = load_samples()
    if not samples:
        return None
    last_ts = samples[-1].get("timestamp", "")
    try:
        last_dt = datetime.fromisoformat(last_ts)
        return (datetime.utcnow() - last_dt).total_seconds()
    except (ValueError, TypeError):
        return None


def is_cache_fresh(max_age_seconds: int = 7200) -> bool:
    """True if baseline data was updated within max_age_seconds (default 2h)."""
    age = baseline_age_seconds()
    if age is None:
        return False
    return age <= max_age_seconds


# ---------------------------------------------------------------------------
# BehavioralEngine — Unified Class Interface
# ---------------------------------------------------------------------------
class BehavioralEngine:
    """
    High-level interface for the Sentinel Baseline subsystem.
    Stores rolling 7-day averages, detects anomalies via Z-score,
    and exposes data for the Sovereign Pulse dashboard.
    """

    def __init__(self, data_dir: str = None, threshold: float = ZSCORE_THRESHOLD,
                 window_days: int = ROLLING_WINDOW_DAYS):
        if data_dir:
            self._data_dir = Path(data_dir)
        else:
            self._data_dir = DATA_DIR
        self.threshold = threshold
        self.window_days = window_days
        self._baseline_file = self._data_dir / "baseline_samples.json"
        self._anomaly_file = self._data_dir / "anomalies.json"
        self._data_dir.mkdir(parents=True, exist_ok=True)

    # -- Storage --
    def _load_samples(self) -> List[dict]:
        if not self._baseline_file.exists():
            return []
        with open(self._baseline_file, "r") as f:
            return json.load(f)

    def _save_samples(self, samples: List[dict]):
        cutoff = (datetime.utcnow() - timedelta(days=self.window_days)).isoformat()
        trimmed = [s for s in samples if s.get("timestamp", "") >= cutoff]
        max_s = self.window_days * 24
        trimmed = trimmed[-max_s:]
        with open(self._baseline_file, "w") as f:
            json.dump(trimmed, f, indent=2)

    # -- Core API --
    def collect_and_evaluate(self) -> dict:
        """Collect telemetry, update baseline, detect anomalies. Returns summary."""
        sample = collect_telemetry()
        samples = self._load_samples()
        samples.append(asdict(sample))
        self._save_samples(samples)

        baseline = compute_baseline(samples)
        anomalies = detect_anomalies(sample, baseline, self.threshold)
        if anomalies:
            log_anomalies(anomalies)

        return {
            "sample": asdict(sample),
            "baseline": {k: asdict(v) for k, v in baseline.items()},
            "anomalies": [asdict(a) for a in anomalies],
            "sample_count": len(samples),
            "cache_fresh": self.is_cache_fresh(),
        }

    def get_baseline_status(self) -> dict:
        """Return current baseline statistics."""
        samples = self._load_samples()
        baseline = compute_baseline(samples)
        return {
            "metrics": {k: asdict(v) for k, v in baseline.items()},
            "sample_count": len(samples),
            "cache_fresh": self.is_cache_fresh(),
            "window_days": self.window_days,
        }

    def get_sparkline_data(self, metric: str = "process_count", points: int = 24) -> dict:
        """Return baseline-vs-actual data for sparkline rendering."""
        samples = self._load_samples()
        baseline = compute_baseline(samples)
        stats = baseline.get(metric)
        recent = samples[-points:] if len(samples) >= points else samples
        actual_values = [s.get(metric, 0) for s in recent]
        timestamps = [s.get("timestamp", "")[:16] for s in recent]
        baseline_value = stats.mean if stats else 0
        return {
            "metric": metric,
            "timestamps": timestamps,
            "actual": actual_values,
            "baseline": [baseline_value] * len(actual_values),
            "threshold_upper": round(baseline_value + (stats.std_dev * self.threshold if stats else 0), 2),
            "threshold_lower": round(baseline_value - (stats.std_dev * self.threshold if stats else 0), 2),
            "sample_count": stats.sample_count if stats else 0,
        }

    def get_all_sparklines(self, points: int = 24) -> List[dict]:
        """Return sparkline data for every tracked metric."""
        return [self.get_sparkline_data(m, points) for m in METRICS]

    def evaluate_value(self, metric: str, current: float) -> dict:
        """Evaluate a single metric value against the current baseline."""
        samples = self._load_samples()
        baseline = compute_baseline(samples)
        stats = baseline.get(metric)
        if not stats or stats.sample_count < 3:
            return {"metric": metric, "zscore": 0.0, "anomaly": False,
                    "severity": "INFO", "message": "Insufficient baseline data"}
        z = calculate_zscore(current, stats.mean, stats.std_dev)
        is_anomaly = abs(z) >= self.threshold
        return {
            "metric": metric,
            "current": current,
            "mean": stats.mean,
            "std_dev": stats.std_dev,
            "zscore": z,
            "anomaly": is_anomaly,
            "severity": classify_severity(z) if is_anomaly else "INFO",
        }

    def is_cache_fresh(self, max_age_seconds: int = 7200) -> bool:
        """True if baseline was updated within max_age_seconds."""
        samples = self._load_samples()
        if not samples:
            return False
        last_ts = samples[-1].get("timestamp", "")
        try:
            last_dt = datetime.fromisoformat(last_ts)
            return (datetime.utcnow() - last_dt).total_seconds() <= max_age_seconds
        except (ValueError, TypeError):
            return False

    def get_recent_anomalies(self, days: int = 7) -> List[dict]:
        """Load anomalies from the last N days."""
        return load_anomalies(days)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def run_sentinel(args):
    """Entry point matching Shadow Toolkit convention: run_<name>(args)."""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich import box
        console = Console()
    except ImportError:
        print("  [!] Install rich: pip install rich")
        return

    mode = getattr(args, "action", "collect")

    console.print("\n[bold #6366f1]  ─── Sentinel Baseline Engine ───[/]\n")

    if mode == "collect":
        console.print("  [*] Collecting telemetry snapshot...")
        sample = collect_telemetry()
        samples = record_sample(sample)
        baseline = compute_baseline(samples)
        anomalies = detect_anomalies(sample, baseline)

        # Current snapshot table
        table = Table(title="Current Telemetry", box=box.ROUNDED, border_style="#6366f1")
        table.add_column("Metric", style="bold white")
        table.add_column("Value", style="#22c55e", justify="right")
        table.add_column("Baseline (mean)", style="#94a3b8", justify="right")
        table.add_column("Z-Score", justify="right")

        sample_dict = asdict(sample)
        for metric in METRICS:
            val = sample_dict.get(metric, 0)
            stats = baseline.get(metric)
            mean_str = f"{stats.mean:.1f}" if stats else "N/A"
            z = calculate_zscore(val, stats.mean, stats.std_dev) if stats and stats.sample_count >= 3 else 0
            z_style = "#ef4444" if abs(z) >= ZSCORE_THRESHOLD else "#22c55e"
            table.add_row(
                metric.replace("_", " ").title(),
                str(val),
                mean_str,
                f"[{z_style}]{z:+.2f}[/]",
            )

        console.print(table)
        console.print(f"\n  [*] Samples in window: {len(samples)} / {MAX_SAMPLES}")
        console.print(f"  [*] Cache fresh: {'Yes' if is_cache_fresh() else 'No'}")

        if anomalies:
            log_anomalies(anomalies)
            console.print(f"\n  [bold #ef4444][!] {len(anomalies)} anomalies detected![/]")
            for a in anomalies:
                console.print(f"      [{a.severity}] {a.metric}: observed={a.observed} z={a.zscore:+.2f}")
        else:
            console.print("\n  [bold #22c55e][+] No anomalies detected.[/]")

    elif mode == "status":
        samples = load_samples()
        baseline = compute_baseline(samples)
        anomalies = load_anomalies()

        table = Table(title="Baseline Status", box=box.ROUNDED, border_style="#6366f1")
        table.add_column("Metric", style="bold white")
        table.add_column("Mean", justify="right")
        table.add_column("Std Dev", justify="right")
        table.add_column("Samples", justify="right")

        for metric in METRICS:
            stats = baseline.get(metric)
            if stats:
                table.add_row(metric.replace("_", " ").title(),
                              f"{stats.mean:.1f}", f"{stats.std_dev:.2f}", str(stats.sample_count))

        console.print(table)
        console.print(f"\n  [*] Recent anomalies (7d): {len(anomalies)}")
        console.print(f"  [*] Cache fresh: {'Yes' if is_cache_fresh() else 'No'}")

    elif mode == "anomalies":
        days = getattr(args, "days", 7)
        anomalies = load_anomalies(days)
        if not anomalies:
            console.print("  [*] No anomalies in the last {days} days.")
            return

        table = Table(title=f"Anomalies (last {days} days)", box=box.ROUNDED, border_style="#ef4444")
        table.add_column("Time", style="#94a3b8")
        table.add_column("Metric", style="bold white")
        table.add_column("Observed", justify="right")
        table.add_column("Mean", justify="right")
        table.add_column("Z-Score", justify="right")
        table.add_column("Severity", justify="center")
        table.add_column("Source", style="#94a3b8")

        for a in anomalies[-50:]:
            sev = a.get("severity", "INFO")
            sev_color = {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308",
                         "LOW": "#22c55e", "INFO": "#94a3b8"}.get(sev, "#94a3b8")
            table.add_row(
                a.get("timestamp", "")[:19],
                a.get("metric", ""),
                str(a.get("observed", "")),
                str(a.get("mean", "")),
                f"{a.get('zscore', 0):+.2f}",
                f"[{sev_color}]{sev}[/]",
                a.get("source", "behavioral"),
            )
        console.print(table)
