#!/usr/bin/env python3
"""
Threat Intel Service — IP/Hash Reputation & Threat Feed
=======================================================
Provides lookups against local blocklists and public APIs
(AbuseIPDB, VirusTotal) with caching. Flags events that
match known-bad indicators. Part of the Sovereign Pulse layer.
"""

import json
import hashlib
import os
import re
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Optional, Set

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", os.path.join("C:\\Logs", "sentinel")))
THREAT_DB_FILE = DATA_DIR / "threat_intel_db.json"
CACHE_FILE = DATA_DIR / "threat_cache.json"
EVENT_LOG_FILE = DATA_DIR / "threat_events.json"
CACHE_TTL_HOURS = 24

# API keys (set via environment variables — never hardcode)
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------
@dataclass
class ThreatIndicator:
    indicator: str  # IP address, domain, or hash
    indicator_type: str  # ip, domain, hash
    source: str  # local, abuseipdb, virustotal, manual
    confidence: int = 0  # 0-100
    category: str = ""  # malware, c2, scanner, phishing, brute_force
    first_seen: str = ""
    last_seen: str = ""
    description: str = ""


@dataclass
class ThreatEvent:
    timestamp: str
    indicator: str
    indicator_type: str
    matched_source: str
    confidence: int
    category: str
    context: str = ""
    source: str = "threat-intel"

    @property
    def badge(self) -> str:
        return "THREAT-INTEL"


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------
IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
)
HASH_PATTERN = re.compile(r"^[0-9a-fA-F]{32,128}$")
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def classify_indicator(value: str) -> str:
    """Return the type of an indicator: ip, hash, domain, or unknown."""
    value = value.strip()
    if IPV4_PATTERN.match(value):
        return "ip"
    if HASH_PATTERN.match(value):
        return "hash"
    if DOMAIN_PATTERN.match(value):
        return "domain"
    return "unknown"


# ---------------------------------------------------------------------------
# Local Threat Database
# ---------------------------------------------------------------------------
# Built-in known-bad indicators (seed list)
BUILTIN_BAD_IPS: Set[str] = {
    "45.33.32.156",    # known scanner
    "185.220.101.1",   # tor exit node (example)
    "23.129.64.100",   # tor exit node (example)
}

BUILTIN_BAD_HASHES: Set[str] = {
    "d41d8cd98f00b204e9800998ecf8427e",  # empty file md5
    "e3b0c44298fc1c149afbf4c8996fb924",  # empty file sha256 prefix
}


def _ensure_data_dir():
    DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_threat_db() -> List[dict]:
    """Load the local threat intelligence database."""
    if not THREAT_DB_FILE.exists():
        return []
    with open(THREAT_DB_FILE, "r") as f:
        return json.load(f)


def save_threat_db(entries: List[dict]):
    """Persist the threat intelligence database."""
    _ensure_data_dir()
    with open(THREAT_DB_FILE, "w") as f:
        json.dump(entries, f, indent=2)


def add_indicator(indicator: str, source: str = "manual", confidence: int = 80,
                  category: str = "", description: str = "") -> ThreatIndicator:
    """Add an indicator to the local threat database."""
    itype = classify_indicator(indicator)
    now = datetime.utcnow().isoformat()
    entry = ThreatIndicator(
        indicator=indicator.strip().lower(),
        indicator_type=itype,
        source=source,
        confidence=confidence,
        category=category,
        first_seen=now,
        last_seen=now,
        description=description,
    )
    db = load_threat_db()
    # Update existing or append
    existing = next((e for e in db if e["indicator"] == entry.indicator), None)
    if existing:
        existing["last_seen"] = now
        existing["confidence"] = max(existing.get("confidence", 0), confidence)
        if description:
            existing["description"] = description
    else:
        db.append(asdict(entry))
    save_threat_db(db)
    return entry


def remove_indicator(indicator: str) -> bool:
    """Remove an indicator from the local database."""
    db = load_threat_db()
    original = len(db)
    db = [e for e in db if e["indicator"] != indicator.strip().lower()]
    if len(db) < original:
        save_threat_db(db)
        return True
    return False


# ---------------------------------------------------------------------------
# Lookup Cache
# ---------------------------------------------------------------------------
def _load_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    with open(CACHE_FILE, "r") as f:
        return json.load(f)


def _save_cache(cache: dict):
    _ensure_data_dir()
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def _cache_get(key: str) -> Optional[dict]:
    cache = _load_cache()
    entry = cache.get(key)
    if entry:
        cached_at = entry.get("cached_at", "")
        try:
            dt = datetime.fromisoformat(cached_at)
            if (datetime.utcnow() - dt).total_seconds() < CACHE_TTL_HOURS * 3600:
                return entry.get("result")
        except (ValueError, TypeError):
            pass
    return None


def _cache_set(key: str, result: dict):
    cache = _load_cache()
    cache[key] = {"cached_at": datetime.utcnow().isoformat(), "result": result}
    # Limit cache size
    if len(cache) > 5000:
        sorted_keys = sorted(cache, key=lambda k: cache[k].get("cached_at", ""))
        for k in sorted_keys[:1000]:
            del cache[k]
    _save_cache(cache)


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------
def lookup_local(indicator: str) -> Optional[ThreatIndicator]:
    """Check indicator against built-in lists and local DB."""
    ind = indicator.strip().lower()
    itype = classify_indicator(ind)

    # Built-in lists
    if itype == "ip" and ind in BUILTIN_BAD_IPS:
        return ThreatIndicator(
            indicator=ind, indicator_type="ip", source="builtin",
            confidence=70, category="scanner",
            description="Known scanner/malicious IP (built-in list)",
        )
    if itype == "hash" and ind in BUILTIN_BAD_HASHES:
        return ThreatIndicator(
            indicator=ind, indicator_type="hash", source="builtin",
            confidence=60, category="suspicious",
            description="Known suspicious hash (built-in list)",
        )

    # Local DB
    db = load_threat_db()
    match = next((e for e in db if e["indicator"] == ind), None)
    if match:
        return ThreatIndicator(**{k: match[k] for k in ThreatIndicator.__dataclass_fields__ if k in match})

    return None


def lookup_abuseipdb(ip: str) -> Optional[dict]:
    """Query AbuseIPDB for IP reputation (requires API key)."""
    if not ABUSEIPDB_KEY or classify_indicator(ip) != "ip":
        return None

    cached = _cache_get(f"abuseipdb:{ip}")
    if cached:
        return cached

    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
    req = urllib.request.Request(url, headers={
        "Key": ABUSEIPDB_KEY,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            result = data.get("data", {})
            _cache_set(f"abuseipdb:{ip}", result)
            return result
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def lookup_virustotal(indicator: str) -> Optional[dict]:
    """Query VirusTotal for hash/IP/domain reputation (requires API key)."""
    if not VIRUSTOTAL_KEY:
        return None

    itype = classify_indicator(indicator)
    if itype == "hash":
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    elif itype == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif itype == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    else:
        return None

    cached = _cache_get(f"vt:{indicator}")
    if cached:
        return cached

    req = urllib.request.Request(url, headers={"x-apikey": VIRUSTOTAL_KEY})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
            _cache_set(f"vt:{indicator}", data)
            return data
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError):
        return None


def lookup(indicator: str) -> dict:
    """Unified lookup: local DB, then external APIs. Returns a verdict dict."""
    ind = indicator.strip().lower()
    itype = classify_indicator(ind)

    result = {
        "indicator": ind,
        "type": itype,
        "verdict": "clean",
        "confidence": 0,
        "sources": [],
        "details": [],
    }

    # Local / built-in
    local = lookup_local(ind)
    if local:
        result["verdict"] = "malicious"
        result["confidence"] = local.confidence
        result["sources"].append(local.source)
        result["details"].append(asdict(local))

    # AbuseIPDB
    if itype == "ip":
        abuse = lookup_abuseipdb(ind)
        if abuse and abuse.get("abuseConfidenceScore", 0) > 25:
            result["verdict"] = "malicious"
            result["confidence"] = max(result["confidence"], abuse["abuseConfidenceScore"])
            result["sources"].append("abuseipdb")
            result["details"].append({"source": "abuseipdb", "score": abuse["abuseConfidenceScore"],
                                       "reports": abuse.get("totalReports", 0)})

    # VirusTotal
    vt = lookup_virustotal(ind)
    if vt:
        attrs = vt.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        if mal > 3:
            result["verdict"] = "malicious"
            result["confidence"] = max(result["confidence"], min(mal * 10, 100))
            result["sources"].append("virustotal")
            result["details"].append({"source": "virustotal", "malicious_detections": mal})

    return result


# ---------------------------------------------------------------------------
# Event Logging
# ---------------------------------------------------------------------------
def log_threat_event(event: ThreatEvent):
    """Append a threat event to persistent storage."""
    _ensure_data_dir()
    events = []
    if EVENT_LOG_FILE.exists():
        with open(EVENT_LOG_FILE, "r") as f:
            events = json.load(f)
    events.append(asdict(event))
    events = events[-1000:]
    with open(EVENT_LOG_FILE, "w") as f:
        json.dump(events, f, indent=2)


def load_threat_events(days: int = 7) -> List[dict]:
    """Load recent threat events."""
    if not EVENT_LOG_FILE.exists():
        return []
    cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
    with open(EVENT_LOG_FILE, "r") as f:
        events = json.load(f)
    return [e for e in events if e.get("timestamp", "") >= cutoff]


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
def run_threat_intel(args):
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

    action = getattr(args, "action", "lookup")
    console.print("\n[bold #6366f1]  ─── Threat Intelligence Service ───[/]\n")

    if action == "lookup":
        indicator = getattr(args, "indicator", "")
        if not indicator:
            console.print("  [!] No indicator provided.")
            return

        console.print(f"  [*] Looking up: {indicator}")
        result = lookup(indicator)
        verdict_color = "#ef4444" if result["verdict"] == "malicious" else "#22c55e"

        table = Table(box=box.ROUNDED, border_style="#6366f1", title="Lookup Result")
        table.add_column("Field", style="bold white")
        table.add_column("Value")
        table.add_row("Indicator", result["indicator"])
        table.add_row("Type", result["type"])
        table.add_row("Verdict", f"[{verdict_color}]{result['verdict'].upper()}[/]")
        table.add_row("Confidence", f"{result['confidence']}%")
        table.add_row("Sources", ", ".join(result["sources"]) if result["sources"] else "none")
        console.print(table)

        if result["verdict"] == "malicious":
            event = ThreatEvent(
                timestamp=datetime.utcnow().isoformat(),
                indicator=result["indicator"],
                indicator_type=result["type"],
                matched_source=", ".join(result["sources"]),
                confidence=result["confidence"],
                category="lookup",
                context=f"Manual lookup flagged {result['indicator']} as malicious",
            )
            log_threat_event(event)

    elif action == "add":
        indicator = getattr(args, "indicator", "")
        category = getattr(args, "category", "malicious")
        description = getattr(args, "description", "Manually added")
        entry = add_indicator(indicator, source="manual", confidence=90,
                              category=category, description=description)
        console.print(f"  [+] Added: {entry.indicator} ({entry.indicator_type})")

    elif action == "remove":
        indicator = getattr(args, "indicator", "")
        if remove_indicator(indicator):
            console.print(f"  [-] Removed: {indicator}")
        else:
            console.print(f"  [!] Not found: {indicator}")

    elif action == "list":
        db = load_threat_db()
        if not db:
            console.print("  [*] Threat database is empty.")
            return

        table = Table(title="Local Threat Database", box=box.ROUNDED, border_style="#ef4444")
        table.add_column("Indicator", style="bold white")
        table.add_column("Type")
        table.add_column("Source")
        table.add_column("Confidence", justify="right")
        table.add_column("Category")
        table.add_column("Last Seen", style="#94a3b8")

        for e in db[-50:]:
            table.add_row(
                e.get("indicator", ""),
                e.get("indicator_type", ""),
                e.get("source", ""),
                f"{e.get('confidence', 0)}%",
                e.get("category", ""),
                e.get("last_seen", "")[:19],
            )
        console.print(table)

    elif action == "events":
        days = getattr(args, "days", 7)
        events = load_threat_events(days)
        if not events:
            console.print(f"  [*] No threat events in the last {days} days.")
            return

        table = Table(title=f"Threat Events (last {days}d)", box=box.ROUNDED, border_style="#ef4444")
        table.add_column("Time", style="#94a3b8")
        table.add_column("Indicator", style="bold white")
        table.add_column("Type")
        table.add_column("Source")
        table.add_column("Confidence", justify="right")
        table.add_column("Context")

        for e in events[-50:]:
            table.add_row(
                e.get("timestamp", "")[:19],
                e.get("indicator", ""),
                e.get("indicator_type", ""),
                e.get("matched_source", ""),
                f"{e.get('confidence', 0)}%",
                (e.get("context", "")[:40] + "...") if len(e.get("context", "")) > 40 else e.get("context", ""),
            )
        console.print(table)
