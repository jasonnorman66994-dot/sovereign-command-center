#!/usr/bin/env python3
"""
Threat Intelligence Backend Service
====================================
Provides IP/hash/domain lookups against a local "Known-Bad" list
and external APIs. Tags events as ANOMALY when they match the
threat-intel list OR exceed a Z-score threshold.

Part of the Sovereign Pulse operational layer.
"""

import json
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", os.path.join("C:\\Logs", "sentinel")))
THREAT_LOG = DATA_DIR / "threat_events.json"
THREAT_DB = DATA_DIR / "threat_intel_db.json"
ZSCORE_THRESHOLD = 3.0


# ---------------------------------------------------------------------------
# Known-Bad Lists (seed data — extend via API or manual add)
# ---------------------------------------------------------------------------
KNOWN_BAD_IPS = {
    "45.33.32.156":    {"category": "scanner",     "confidence": 80, "desc": "Known scanner host"},
    "185.220.101.1":   {"category": "tor_exit",    "confidence": 70, "desc": "Tor exit node"},
    "23.129.64.100":   {"category": "tor_exit",    "confidence": 70, "desc": "Tor exit node"},
    "194.26.29.120":   {"category": "c2",          "confidence": 90, "desc": "Known C2 server"},
    "91.243.44.0":     {"category": "brute_force", "confidence": 85, "desc": "SSH brute-force origin"},
}

KNOWN_BAD_HASHES = {
    "d41d8cd98f00b204e9800998ecf8427e": {"category": "suspicious", "confidence": 50, "desc": "Empty file MD5"},
    "e3b0c44298fc1c149afbf4c8996fb924": {"category": "suspicious", "confidence": 50, "desc": "Empty file SHA256 prefix"},
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4": {"category": "malware",    "confidence": 95, "desc": "Known trojan sample"},
}

KNOWN_BAD_DOMAINS = {
    "evil.example.com":   {"category": "phishing",  "confidence": 90, "desc": "Phishing domain"},
    "malware.test.local": {"category": "malware",   "confidence": 85, "desc": "Malware distribution"},
}


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------
@dataclass
class ThreatMatch:
    timestamp: str
    indicator: str
    indicator_type: str       # ip / hash / domain
    source: str               # known_bad_list / z_score / manual
    confidence: int           # 0-100
    category: str
    description: str
    tag: str = "ANOMALY"      # always ANOMALY for backend logs
    badge: str = ""           # UI badge: "Threat Match" or "Z-Score Alert"


# ---------------------------------------------------------------------------
# Lookup Functions
# ---------------------------------------------------------------------------
def lookup_ip(ip: str) -> Optional[ThreatMatch]:
    """Check an IP against the Known-Bad list."""
    entry = KNOWN_BAD_IPS.get(ip.strip())
    if not entry:
        # Also check local DB file
        entry = _check_local_db(ip.strip(), "ip")
    if entry:
        return ThreatMatch(
            timestamp=datetime.utcnow().isoformat(),
            indicator=ip.strip(),
            indicator_type="ip",
            source="known_bad_list",
            confidence=int(entry.get("confidence", 70)),
            category=str(entry.get("category", "unknown")),
            description=str(entry.get("desc", entry.get("description", ""))),
            badge="Threat Match",
        )
    return None


def lookup_hash(file_hash: str) -> Optional[ThreatMatch]:
    """Check a file hash against the Known-Bad list."""
    h = file_hash.strip().lower()
    entry = KNOWN_BAD_HASHES.get(h)
    if not entry:
        entry = _check_local_db(h, "hash")
    if entry:
        return ThreatMatch(
            timestamp=datetime.utcnow().isoformat(),
            indicator=h,
            indicator_type="hash",
            source="known_bad_list",
            confidence=int(entry.get("confidence", 60)),
            category=str(entry.get("category", "suspicious")),
            description=str(entry.get("desc", entry.get("description", ""))),
            badge="Threat Match",
        )
    return None


def lookup_domain(domain: str) -> Optional[ThreatMatch]:
    """Check a domain against the Known-Bad list."""
    d = domain.strip().lower()
    entry = KNOWN_BAD_DOMAINS.get(d)
    if not entry:
        entry = _check_local_db(d, "domain")
    if entry:
        return ThreatMatch(
            timestamp=datetime.utcnow().isoformat(),
            indicator=d,
            indicator_type="domain",
            source="known_bad_list",
            confidence=int(entry.get("confidence", 70)),
            category=str(entry.get("category", "unknown")),
            description=str(entry.get("desc", entry.get("description", ""))),
            badge="Threat Match",
        )
    return None


def lookup(indicator: str) -> Optional[ThreatMatch]:
    """Unified lookup — auto-detect indicator type."""
    indicator = indicator.strip()
    # Simple type detection
    import re
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return lookup_ip(indicator)
    if re.match(r"^[0-9a-fA-F]{32,128}$", indicator):
        return lookup_hash(indicator)
    if re.match(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", indicator):
        return lookup_domain(indicator)
    return None


# ---------------------------------------------------------------------------
# Z-Score Integration
# ---------------------------------------------------------------------------
def evaluate_with_zscore(indicator: str, metric_name: str, current_value: float,
                         mean: float, std_dev: float) -> Optional[ThreatMatch]:
    """
    Tag an event as ANOMALY if:
      (A) It matches the threat-intel list, OR
      (B) Its Z-score exceeds the threshold.
    Returns a ThreatMatch with the appropriate badge.
    """
    from shadow_toolkit.sentinel_baseline import calculate_zscore

    # Check threat-intel first
    threat_match = lookup(indicator)

    # Calculate Z-score
    z = calculate_zscore(current_value, mean, std_dev)
    z_anomaly = abs(z) >= ZSCORE_THRESHOLD

    if threat_match and z_anomaly:
        threat_match.badge = "Threat Match + Z-Score Alert"
        threat_match.description += f" | Z-score={z:+.2f} on {metric_name}"
        return threat_match
    elif threat_match:
        return threat_match
    elif z_anomaly:
        return ThreatMatch(
            timestamp=datetime.utcnow().isoformat(),
            indicator=indicator,
            indicator_type="metric",
            source="z_score",
            confidence=min(int(abs(z) * 20), 100),
            category="behavioral_anomaly",
            description=f"{metric_name}: value={current_value}, mean={mean:.1f}, z={z:+.2f}",
            badge="Z-Score Alert",
        )
    return None


# ---------------------------------------------------------------------------
# Local DB Helpers
# ---------------------------------------------------------------------------
def _check_local_db(indicator: str, itype: str) -> Optional[dict[str, Any]]:
    """Check indicator against the persistent local threat DB file."""
    if not THREAT_DB.exists():
        return None
    with open(THREAT_DB, "r", encoding="utf-8") as f:
        db = json.load(f)
    for entry in db:
        if entry.get("indicator") == indicator and entry.get("indicator_type", "") == itype:
            return entry
    return None


def add_to_known_bad(indicator: str, indicator_type: str, category: str = "manual",
                     confidence: int = 90, description: str = "Manually added"):
    """Add an indicator to the persistent local DB."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    db = []
    if THREAT_DB.exists():
        with open(THREAT_DB, "r", encoding="utf-8") as f:
            db = json.load(f)
    now = datetime.utcnow().isoformat()
    existing = next((e for e in db if e["indicator"] == indicator.strip().lower()), None)
    if existing:
        existing["last_seen"] = now
        existing["confidence"] = max(existing.get("confidence", 0), confidence)
    else:
        db.append({
            "indicator": indicator.strip().lower(),
            "indicator_type": indicator_type,
            "source": "manual",
            "confidence": confidence,
            "category": category,
            "description": description,
            "first_seen": now,
            "last_seen": now,
        })
    with open(THREAT_DB, "w", encoding="utf-8") as f:
        json.dump(db, f, indent=2)


# ---------------------------------------------------------------------------
# Event Logging
# ---------------------------------------------------------------------------
def log_threat_match(match: ThreatMatch):
    """Append a tagged ANOMALY event to the backend log."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    events = []
    if THREAT_LOG.exists():
        with open(THREAT_LOG, "r", encoding="utf-8") as f:
            events = json.load(f)
    events.append(asdict(match))
    events = events[-1000:]
    with open(THREAT_LOG, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)


def get_recent_events(days: int = 7) -> List[dict]:
    """Load recent threat events with badges."""
    if not THREAT_LOG.exists():
        return []
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    with open(THREAT_LOG, "r", encoding="utf-8") as f:
        events = json.load(f)
    return [e for e in events if e.get("timestamp", "") >= cutoff]
