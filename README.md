# Shadow Toolkit — Ethical Security Testing Suite

```text
  ____  _               _                 _____           _ _    _ _   
 / ___|| |__   __ _  __| | _____      __ |_   _|__   ___ | | | _(_) |_ 
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | |/ _ \ / _ \| | |/ / | __|
  ___) | | | | (_| | (_| | (_) \ V  V /    | | (_) | (_) | |   <| | |_ 
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/     |_|\___/ \___/|_|_|\_\_|\__|
```

> ⚠ **FOR AUTHORIZED USE ONLY** — Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

[![Quality Gates](https://github.com/jasonnorman66994-dot/sovereign-command-center/actions/workflows/quality-gates.yml/badge.svg?branch=main)](https://github.com/jasonnorman66994-dot/sovereign-command-center/actions/workflows/quality-gates.yml)
[![Release](https://img.shields.io/github/v/tag/jasonnorman66994-dot/sovereign-command-center?label=release)](https://github.com/jasonnorman66994-dot/sovereign-command-center/releases)

A Python-based offensive security toolkit with 10 modules for penetration testing, vulnerability assessment, and defensive security.

---

## ✅ Quality Gates

This repository enforces validation in local Git hooks and CI:

- Pre-commit hook runs `smoke_check.ps1 -Mode Quick`
- Pre-push hook runs `smoke_check.ps1 -Mode Full`
- GitHub Actions workflow runs Quick checks on pull requests and Full checks on pushes/tags
- Contributor workflow and release guidance: [CONTRIBUTING.md](CONTRIBUTING.md)

Run locally:

```powershell
powershell -ExecutionPolicy Bypass -File .\smoke_check.ps1 -Mode Quick
powershell -ExecutionPolicy Bypass -File .\smoke_check.ps1 -Mode Full
```

Run Phase 2 telemetry verification harness locally:

```powershell
python scripts/phase2_telemetry_harness.py
```

Expected pass indicators:

- `Events consumed: 2`
- `DB rows delta (phase2 modules): 2`
- `Notification calls: slack=2, email=1, telegram=1`
- `RESULT: PASS`

If the first run reports `RESULT: FAIL`, run the harness one more time.

Manual CI validation is available in GitHub Actions via `Telemetry Harness` workflow dispatch.

---

## 📊 Scenario Analysis & Reporting Tools

SHADOW-TOOLZ includes data-driven analysis tools for cross-scenario attack pattern assessment and leadership reporting.

### Attack Chain Timeline Generator

Map synthetic event JSON to ATT&CK-style phases with automatic classification:

```powershell
python attack_chain_timeline.py scenario13_events.json --format table
python attack_chain_timeline.py scenario13_events.json --format json
python attack_chain_timeline.py scenario13_events.json --no-colour
```

Input format: JSON array of event objects with `event`, `timestamp`, and optional metadata.

Output: Markdown table or JSON with phase classification, timestamps, and details.

### Unified MITRE ATT&CK Heatmap

Generate ATT&CK technique coverage heatmaps from scenario mappings:

```powershell
python generate_unified_mitre_heatmap.py
python generate_unified_mitre_heatmap.py --input data/unified_mitre_heatmap.json --output my_heatmap.md
```

Heat levels:

- High: 5+ scenarios
- Medium: 3-4 scenarios
- Low: 1-2 scenarios
- None: not observed

Default dataset: `data/unified_mitre_heatmap.json` (Scenario 10–16 mapping)

Output: Markdown report with technique frequency, summary, and interpretation.

### Leadership Report

Pre-generated consolidated report combining ATT&CK coverage and timeline narrative across all scenarios:

- File: [leadership_attack_coverage_timeline_report.md](leadership_attack_coverage_timeline_report.md)
- Covers: Scenario 10–16 timeline progression and heat analysis
- Audience: Executive and detection engineering leadership

### Release Notes and Templates

Use the scenario-analysis release-note artifacts to summarize milestone progress for stakeholders:

- Latest milestone note: [docs/SCENARIO_ANALYSIS_RELEASE_NOTES_2026-04-15.md](docs/SCENARIO_ANALYSIS_RELEASE_NOTES_2026-04-15.md)
- Reusable template: [docs/SCENARIO_ANALYSIS_RELEASE_NOTES_TEMPLATE.md](docs/SCENARIO_ANALYSIS_RELEASE_NOTES_TEMPLATE.md)
- Operator guide: [docs/SCENARIO_ANALYSIS_TOOLS_GUIDE.md](docs/SCENARIO_ANALYSIS_TOOLS_GUIDE.md)

---

## 📧 Email Security Playbooks & Automation

| 📄 Resource | Description |
| --- | --- |
| [✅ Email Spam Incident Response Checklist](email_spam_incident_response_checklist.md) | Step-by-step guide for spam outbreaks, with commands and key actions. |
| [🛡️ Unified Email Threat Response Playbook](unified_email_threat_response_playbook.md) | Unified workflow for spam, phishing, malware, and unauthorized access. |
| [🐧 Linux Incident Response Script](email_incident_response.sh) | Automated Bash script for Linux-based email incident response. |
| [🪟 Windows Incident Response Script](email_incident_response.ps1) | Automated PowerShell script for Windows/Exchange environments. |
| [📬 Extracted Email Addresses](extracted_emails.md) | All unique email addresses and their context, extracted from the workspace. |
| [📚 Documentation Index](EMAIL_SECURITY_DOCS_INDEX.md) | Central index for all email security documentation and automation. |

---

## Notification Hub (Collector-Centric Alerts)

SHADOW-TOOLZ routes external alerts through a centralized notification engine in the collector. Modules publish telemetry only; the collector decides when to notify Slack, Telegram, and Email.

### Action/Response Matrix

| Source Module | Event | Severity | Notification Path |
| --- | --- | --- | --- |
| ARP Detector | spoof_alert | critical | Slack + Telegram + Email + Dashboard |
| Sentinel | cpu_halt | critical | Slack + Telegram + Email + Dashboard |
| Net Mapper | new_host | info | Dashboard only |
| Orchestrator | module_crash | warning | Slack + Telegram |

### Secure Configuration

Do not hardcode credentials in module code. Use environment variables via `.env` loaded by the collector.

1. Copy `.env.example` to `.env`.
2. Populate webhook, Telegram, and email credentials.
3. Restart scaled runtime.

Required keys:

- `SHADOW_SLACK_WEBHOOK`
- `SHADOW_TELEGRAM_BOT_TOKEN`
- `SHADOW_TELEGRAM_CHAT_ID`
- `SHADOW_EMAIL_USER`
- `SHADOW_EMAIL_PASS`
- `SHADOW_ADMIN_EMAIL`
- `SHADOW_NOTIFY_COOLDOWN_SECONDS` (default: 300)

### Notification Health Endpoint

Use the protected readiness endpoint to verify which channels are configured:

```bash
curl -H "Authorization: Bearer shadow-secure-default-token-2026" http://127.0.0.1:8055/health/notifications
```

### Alert Storm Protection

NotificationHub applies cooldown-based deduping per channel/event key to avoid repeated Slack/Email spam during sustained incidents.

---

## 🏢 Multi-Tenant MSSP Operations

SHADOW-TOOLZ supports Managed Security Service Provider (MSSP) workflows by mapping network ranges to business contacts and routing alerts per-company.

### Business Registry (`data/targets.json`)

Define companies, their monitored IP ranges, and contact escalation paths:

```json
{
  "Company_Alpha": {
    "network_range": "192.168.1.0/24",
    "contacts": ["it_admin@alpha.com", "sec_ops@alpha.com"],
    "slack_channel": "#alpha-security-alerts",
    "enabled": true
  },
  "Business_Beta": {
    "network_range": "10.0.0.0/16",
    "contacts": ["security@beta-corp.net"],
    "slack_channel": "#beta-ops",
    "enabled": true
  }
}
```

### Business-Aware Alert Routing

When the collector detects a critical event (e.g., ARP spoof, module crash), it:

1. Extracts IP address from telemetry payload (`ip`, `source_ip`, `target_ip`)
2. Matches IP against registered `network_range` in targets.json
3. Routes alert to that business's email contacts and Slack channel
4. Falls back to global admin channel if no business match

**Routing Example:**

| Event | IP | Business Matched | Notification Path |
| --- | --- | --- | --- |
| ARP Spoof Alert | 192.168.1.50 | Company_Alpha | Email: Company_Alpha contact list; Slack: #alpha-security-alerts |
| Sentinel CPU Halt | 10.5.2.100 | Business_Beta | Email: Business_Beta contact list; Slack: #beta-ops |
| Unknown Source | 172.16.0.1 | None | Global admin email (fallback) |

### Dashboard Business Filter

The web dashboard includes a **Target Selector** dropdown to filter telemetry by business:

```text
📊 MSSP Target Filter
┌─────────────────────┐
│ All Targets ▼       │
│ Company_Alpha       │
│ Business_Beta       │
│ Tech_Gamma          │
└─────────────────────┘
```

- Filters live console stream to show only events from selected business
- Displays "Company_Name" prefix in event log when filtering "All Targets"
- Session filter persists in browser localStorage

### Business Health Reports

Export business-segmented telemetry and generate multi-tenant health summaries:

```python
from core.report_exporter import export_telemetry_csv, generate_business_health_report
import sqlite3

# Export CSV with Business column
export_telemetry_csv(events, "weekly_health_report.csv")

# Generate HTML health summary
html = generate_business_health_report(targets, events)
```

### Database Schema

Events table now includes `business` column for per-company tracking:

```sql
CREATE TABLE events (
  id INTEGER,
  timestamp DATETIME,
  module TEXT,
  event TEXT,
  severity TEXT,
  business TEXT,              -- New: Company name or "global"
  data_json TEXT
);
```

### API Endpoints

**List configured businesses:**

```bash
curl -H "Authorization: Bearer shadow-secure-default-token-2026" \
  http://127.0.0.1:8055/targets
```

**Response:**

```json
{
  "targets": {
    "Company_Alpha": {
      "network_range": "192.168.1.0/24",
      "contacts": ["it_admin@alpha.com"],
      "slack_channel": "#alpha-ops",
      "enabled": true
    },
    ...
  }
}
```

### Automated Daily Business Audits

SHADOW-TOOLZ now includes a daily maintenance reporter that sends executive summaries per business.

- Source: last 24 hours of telemetry from SQLite (WAL-safe reads)
- Grouping: by business tag stored in events table
- Delivery: email contacts per business, plus Slack and Telegram digest mirrors
- Compliance: unauthorized port scan against per-business `allowed_ports` policy
- Artifacts: daily CSV and PDF files under `data/reports/`

Runtime scheduler config:

- `SHADOW_DAILY_REPORT_TIME` (default: `00:00`, 24h format `HH:MM`)
- `SHADOW_SMTP_TIMEOUT` (default: `10` seconds for email delivery timeout)
- `SHADOW_PORT_SCAN_INTERVAL_SECONDS` (default: `86400`)
- `SHADOW_PORT_SCAN_TIMEOUT` (default: `0.35`)
- `SHADOW_PORT_SCAN_WORKERS` (default: `64`)

Manual trigger:

```bash
python -m shadow_toolkit.cli daily-report
```

Dashboard trigger:

- Click **Run Daily Report Now** on the dashboard filter panel.

When running `scaled`, the maintenance scheduler runs in the background and dispatches once per day.

---

## Campaign Launcher (Single, Chain, Full-Spectrum)

Use the generated launcher manifest and runner script to execute campaign profiles safely.

1. Regenerate artifacts to refresh launcher profiles:

python run_reporting_pipeline.py

1. List available profiles:

python launch_campaign.py --list

1. Inspect a profile without running:

python launch_campaign.py chain-01 --show

1. Dry-run command rendering (default behavior):

python launch_campaign.py full-spectrum-01

1. Execute a selected profile explicitly:

python launch_campaign.py chain-01 --execute

The launcher is dry-run by default and requires --execute for command execution.

---

## Installation

```bash
# Install from source (editable)
pip install -e ".[all]"

# Or install dependencies manually
pip install -r requirements.txt
pip install rich   # optional, for TUI dashboard
```

After installation, the `shadow` command is available globally:

```bash
shadow portscan 127.0.0.1
shadow dashboard
```

Or run via module:

```bash
python -m shadow_toolkit.cli portscan 127.0.0.1
```

## IAM 2.0 Zero Trust Mode

SHADOW-TOOLZ now supports claims-based identity using OIDC JWT verification and OAuth2 PKCE for dashboard authentication.

### Auth Modes

- legacy: accepts SHADOW_API_TOKEN bearer token only
- oidc: strict JWT verification against OIDC provider
- hybrid: accepts legacy token or OIDC JWT (migration mode)

### OIDC Environment Variables

- SHADOW_AUTH_MODE=oidc
- OIDC_ISSUER: keycloak realm issuer URL
- OIDC_JWKS_URL: keycloak JWKS endpoint URL (optional if issuer set)
- OIDC_AUDIENCE=shadow-toolz
- OIDC_CLIENT_ID=shadow-toolz-dashboard
- OIDC_REDIRECT_URI: dashboard callback URL
- OIDC_SCOPES=openid profile email

### ABAC Clearance Rules

- /maintenance/daily-report requires security_clearance >= 2
- /forensics/pcaps requires security_clearance >= 3

In Keycloak, add a token mapper for claim name security_clearance.

### Dashboard Login

- Use OIDC Login button on dashboard (PKCE S256 flow)
- Dashboard stores access token in session storage and passes it to REST and WebSocket endpoints

### Keycloak on Kubernetes

- Helm values: k8s/keycloak/values.yaml
- Deploy steps: k8s/keycloak/README.txt

### Local Keycloak Operator Runbook

Use the dedicated workstation runbook in [LOCAL_KEYCLOAK_OPERATOR_RUNBOOK.md](LOCAL_KEYCLOAK_OPERATOR_RUNBOOK.md) for:

- starting local Keycloak
- temporary admin recovery
- reseeding the realm and dashboard client
- rotating permanent `admin` and `operator` credentials
- validating direct token issuance and PKCE after changes
- The dashboard PKCE flow is the source-of-truth browser login path; keep validating it after any local Keycloak change.

### Gauntlet Validation Matrix

| Simulation Step | Expected Vector | Defense Mechanism |
| --- | --- | --- |
| The Rogue Pulse | Sustained 95% CPU Load | Auto-Kill-Switch halts dispatch. |
| The Shadow Device | Unauthorized Port or ARP Change | Net Mapper and Port Scanner trigger Slack, Telegram, Email. |
| The Credential Theft | Attempted login without MFA | OIDC provider policy blocks access (WebAuthn/FIDO2 in Keycloak). |
| The Module Crash | Manual kill on Sniffer | Watchdog Orchestrator revives the process. |
| The Audit Gap | High-volume log generation | Rotating log handler maintains disk integrity. |

## Modules

### 1. 🔍 Network Port Scanner (`portscan`)

Multi-threaded TCP/UDP port scanner with service detection and banner grabbing.

```bash
# Scan common ports
python -m shadow_toolkit.cli portscan 192.168.1.1

# Scan specific ports with service detection
python -m shadow_toolkit.cli portscan 192.168.1.1 -p 80,443,8080,3306 -sV

# Full range scan with 200 threads
python -m shadow_toolkit.cli portscan 10.0.0.1 -p 1-65535 -t 200

# Include UDP scan
python -m shadow_toolkit.cli portscan 192.168.1.1 -p 1-1024 --udp
```

### 2. 🔓 Password Hash Cracker (`crack`)

Dictionary attack with mutation rules. Supports MD5, SHA1, SHA256, SHA512, NTLM, bcrypt.

```bash
# Auto-detect hash type
python -m shadow_toolkit.cli crack "5f4dcc3b5aa765d61d8327deb882cf99" -w wordlist.txt

# Specify algorithm + enable mutations
python -m shadow_toolkit.cli crack "e10adc3949ba59abbe56e057f20f883e" -w rockyou.txt -m md5 -r

# Crack bcrypt hash
python -m shadow_toolkit.cli crack '$2b$12$LJ3...' -w wordlist.txt -m bcrypt
```

### 3. 🌐 Web Vulnerability Scanner (`webscan`)

Tests for SQL injection, XSS, directory traversal, and missing security headers.

```bash
# Run all tests
python -m shadow_toolkit.cli webscan http://testapp.local --all

# SQL injection only
python -m shadow_toolkit.cli webscan http://testapp.local/search?q=test --sqli

# XSS + security headers
python -m shadow_toolkit.cli webscan http://testapp.local --xss --headers

# Deep crawl
python -m shadow_toolkit.cli webscan http://testapp.local --all --depth 4
```

### 4. 📡 Packet Sniffer (`sniff`)

Network packet capture with protocol dissection. Requires admin/root.

```bash
# Capture all traffic (run as Administrator)
python -m shadow_toolkit.cli sniff

# Filter TCP port 80, save to file
python -m shadow_toolkit.cli sniff -f "tcp port 80" -o capture.bin

# Capture 100 packets with hex dump
python -m shadow_toolkit.cli sniff -c 100 --hex

# Specific interface
python -m shadow_toolkit.cli sniff -i 192.168.1.100
```

### 5. 🌍 Subdomain & DNS Enumerator (`dnsenum`)

Subdomain discovery, DNS record enumeration, and zone transfer testing.

```bash
# Quick enumeration with built-in wordlist
python -m shadow_toolkit.cli dnsenum example.com

# Full enumeration with custom wordlist
python -m shadow_toolkit.cli dnsenum example.com -w subdomains.txt --records --zone-transfer

# Fast scan with more threads
python -m shadow_toolkit.cli dnsenum example.com -t 100 --records
```

### 6. 🛡 Keylogger & Malware Detector (`detect`)

Scans for suspicious processes, persistence mechanisms, hooks, and network anomalies (Windows).

```bash
# Full system scan
python -m shadow_toolkit.cli detect --all

# Check processes only
python -m shadow_toolkit.cli detect --processes

# Check for persistence + network anomalies
python -m shadow_toolkit.cli detect --persistence --network

# Check for keyboard hooks
python -m shadow_toolkit.cli detect --hooks
```

### 7. 📶 WiFi Network Analyzer (`wifi`)

Scan nearby WiFi networks, analyze channel congestion, assess encryption strength, and detect rogue APs.

```bash
# Scan nearby networks
python -m shadow_toolkit.cli wifi

# Continuous monitoring
python -m shadow_toolkit.cli wifi --monitor --duration 60
```

### 8. 🔗 ARP Spoof Detector (`arpwatch`)

Monitors ARP tables for signs of poisoning or MITM attacks.

```bash
# Monitor for 60 seconds (default)
python -m shadow_toolkit.cli arpwatch

# Custom duration and interval
python -m shadow_toolkit.cli arpwatch --duration 120 --interval 1.0
```

### 9. 🐚 Reverse Shell Listener (`listener`)

Catch incoming reverse shell connections for authorized penetration tests. Generates common payloads.

```bash
# Listen on port 4444 (default)
python -m shadow_toolkit.cli listener

# Custom port and TLS encryption
python -m shadow_toolkit.cli listener -p 9001 --type tls

# Bind to specific address
python -m shadow_toolkit.cli listener --host 10.0.0.5 -p 4444
```

### 10. 🔎 Exploit DB Search (`exploitdb`)

Search for known CVEs and exploits via local database + NIST NVD API.

```bash
# Search by service name
python -m shadow_toolkit.cli exploitdb "openssh"

# Search by CVE ID
python -m shadow_toolkit.cli exploitdb "CVE-2024-6387"

# Limit results
python -m shadow_toolkit.cli exploitdb "apache" -l 10
```

### 🎛 Interactive Dashboard (`dashboard`)

Rich terminal UI for launching all modules interactively. Requires `pip install rich`.

```bash
python -m shadow_toolkit.cli dashboard
```

### ⚙ Scaled Runtime (`scaled`)

Starts the full scaled stack in one command:

- Collector (SQLite WAL persistence)
- Auto-discovered module processes from `modules/`
- FastAPI dashboard server

```bash
python -m shadow_toolkit.cli scaled
# Dashboard: http://127.0.0.1:8055
```

### ⚙ Scaled Lite (`scaled-lite`)

Starts collector + dashboard bridge only (no module workers):

```bash
python -m shadow_toolkit.cli scaled-lite
```

### 🧠 Orchestrator Shell (`orchestrator`)

Interactive module lifecycle manager (modules run as isolated subprocesses):

```bash
python main.py
# or
python -m shadow_toolkit.cli orchestrator
```

Supported commands inside shell:

- `list` — Show available and running modules
- `start <module_name>` — Start a specific module
- `stop <module_name>` — Stop a specific module
- `start-all` — Start all available modules
- `stop-all` — Stop all modules
- `status` — Show PID, status (ALIVE/CRASHED) of each running module
- `purge-logs` — Clear all audit and forensic logs with confirmation
- `exit` — Shutdown all modules and exit

#### 🤖 Watchdog Auto-Restart

The orchestrator includes an automatic watchdog that detects module crashes and restarts them:

```bash
shadow > start smoke_test
[+] Launched smoke_test (PID: 12345)
shadow > status
MODULE               | PID      | STATUS    
------------------------------------------
smoke_test           | 12345    | 🟢 ALIVE

# Simulate a crash (manually kill the process)
shadow > status
[!] Module smoke_test crashed. Attempting auto-restart...
MODULE               | PID      | STATUS    
------------------------------------------
smoke_test           | 12346    | 🟢 ALIVE
```

The watchdog checks module health every 2 seconds and automatically revives crashed processes, logging each incident to `data/master_audit.log`.

### 🔌 WebSocket Bridge

The distributed dashboard bridge is available at:

```text
ws://127.0.0.1:8055/ws/telemetry
```

Packet contract:

- `module`: source module id
- `event`: event type
- `severity`: info | warning | critical
- `timestamp`: Unix epoch float
- `payload`: module-specific JSON object

### 🧾 Dual-Layer Audit Logs

- Master orchestrator audit: `data/master_audit.log` (with automatic rotation)
- Sentinel local forensic log: `modules/sentinel/sentinel_local.log`
- Dashboard audit API: `GET /logs/audit` (requires Bearer token authentication)

#### Log Rotation

The master audit log automatically rotates to prevent disk exhaustion:

- **Limit per file**: 5 MB
- **Backups retained**: 5 copies (master_audit.log.1 through .5)
- **Behavior**: When the active log reaches 5 MB, it's renamed to .1, old .1→.2, and so on. .5 is discarded.

This ensures consistent dashboard performance and prevents the log from growing unbounded.

#### Audit Log Security

The audit logs endpoint (`GET /logs/audit`) requires Bearer token authentication to prevent unauthorized access:

```bash
# Set your API token (or use the default if not specified)
export SHADOW_API_TOKEN="your-secure-token-here"

# The dashboard automatically includes the token in audit requests
curl -H "Authorization: Bearer shadow-secure-default-token-2026" http://127.0.0.1:8055/logs/audit
```

**Default token** (for development): `shadow-secure-default-token-2026`  
**Override** with `SHADOW_API_TOKEN` environment variable before running the dashboard.

#### Purging Logs

Manually clear all audit and forensic logs to reset the forensic state:

```bash
shadow > purge-logs
[!] Are you sure you want to clear all audit logs? (y/n): y
[+] All logs cleared. Forensic state reset.
```

This clears:

- `data/master_audit.log` (reset with purge timestamp header)
- All module-local logs (e.g., `modules/sentinel/sentinel_local.log`)

### 📊 Report Exporter

Export scan results to HTML (dark cyberpunk theme) or JSON. Add `--report` to any module:

```bash
python -m shadow_toolkit.cli portscan 192.168.1.1 --report html -o scan_report.html
python -m shadow_toolkit.cli webscan http://target --all --report json -o vulns.json
```

---

### � Smoke Test Module

Live telemetry verification for system health checks before deployment. Generates high-frequency test packets (10/sec) to validate the ZeroMQ-to-WebSocket pipeline and stress-test log rotation.

```bash
shadow > start smoke_test
[+] Launched smoke_test (PID: 12345)

# Watch the dashboard at http://127.0.0.1:8055
# You should see rapid telemetry packets appearing in the console
# Once master_audit.log reaches 5MB, observe automatic log rotation

shadow > status
MODULE               | PID      | STATUS    
------------------------------------------
smoke_test           | 12345    | 🟢 ALIVE

# To verify watchdog, manually kill the process in another terminal:
# Get-Process python | Where-Object { $_.ProcessName -eq "smoke_test" } | Stop-Process

# The orchestrator will detect the crash and restart it:
[!] Module smoke_test crashed. Attempting auto-restart...

shadow > status
MODULE               | PID      | STATUS    
------------------------------------------
smoke_test           | 12346    | 🟢 ALIVE
```

**Use smoke_test to verify:**

- ✅ ZeroMQ bus connectivity
- ✅ WebSocket dashboard real-time updates
- ✅ Log rotation behavior (5MB limit)
- ✅ Watchdog auto-restart functionality

---

### �🩺 CVE-43887 Pipeline Health Check

Validate reporting pipeline dependencies, logs, PDF generation, and email delivery.

```bash
# Detailed mode (full diagnostic output)
./cve43887_healthcheck.sh

# Summary-only mode
./cve43887_healthcheck.sh --quiet

# Failure-only notifications
ALERT_EMAIL=jasonnorman66994@gmail.com ./cve43887_healthcheck.sh --quiet
```

### Daily Heartbeat Check

Lightweight daily verification (cron, logs, directory):

```bash
./cve43887_heartbeat.sh
```

### Weekly Dashboard Summary

Consolidated report for leadership from heartbeat + health-check logs:

```bash
./cve43887_dashboard.sh
```

### Cron Schedule (Linux)

```bash
# Daily heartbeat (6 AM)
0 6 * * * /usr/local/bin/cve43887_heartbeat.sh

# Weekly full health check (Sunday midnight)
0 0 * * 0 ALERT_EMAIL=jasonnorman66994@gmail.com /usr/local/bin/cve43887_healthcheck.sh --quiet

# Weekly dashboard summary (Sunday 6 AM)
0 6 * * 0 /usr/local/bin/cve43887_dashboard.sh
```

### Windows PowerShell Versions (No WSL Required)

```powershell
# Health check (detailed)
pwsh -ExecutionPolicy Bypass -File .\cve43887_healthcheck.ps1

# Health check (quiet mode)
pwsh -ExecutionPolicy Bypass -File .\cve43887_healthcheck.ps1 -Quiet

# Health check with failure alerts
pwsh -ExecutionPolicy Bypass -File .\cve43887_healthcheck.ps1 -Quiet -AlertEmail "jasonnorman66994@gmail.com"

# Heartbeat check
pwsh -ExecutionPolicy Bypass -File .\cve43887_heartbeat.ps1

# Dashboard summary
pwsh -ExecutionPolicy Bypass -File .\cve43887_dashboard.ps1
```

Logs are written to `C:\Logs\cve43887\` and reports to `C:\Reports\cve43887\`.

---

## Project Structure

```text
shadow_toolkit/
├── __init__.py           # Package init (v2.0.0)
├── cli.py                # Main CLI entry point
├── dashboard.py          # Interactive TUI dashboard (Rich)
├── report_exporter.py    # HTML/JSON report exporter
├── port_scanner.py       # Network port scanner
├── hash_cracker.py       # Password hash cracker
├── web_scanner.py        # Web vulnerability scanner
├── packet_sniffer.py     # Packet sniffer & analyzer
├── dns_enum.py           # DNS & subdomain enumerator
├── malware_detector.py   # Keylogger & malware detector
├── wifi_analyzer.py      # WiFi network analyzer
├── arp_detector.py       # ARP spoof / MITM detector
├── reverse_listener.py   # Reverse shell listener
└── exploit_search.py     # Exploit DB / CVE search
pyproject.toml            # Package config (pip installable)
requirements.txt          # Core dependencies
vuln_test_server.py       # Intentionally vulnerable test server
test_wordlist.txt         # Sample wordlist for testing
```

## Legal Disclaimer

This toolkit is provided for **educational and authorized security testing purposes only**. You are solely responsible for ensuring you have proper authorization before using any of these tools against any system. The authors are not responsible for any misuse or damage caused by this toolkit.

**Always get written permission before testing systems you do not own.**

---

## Phase 8: Network Security Monitoring Modules

Production-grade network integrity monitoring for NOC environments. Automatically detects ARP spoofing attacks and unauthorized network devices.

### 🛡️ ARP Spoof Detector (`arp_detector`)

Detects MAC address flipping on the gateway (indicator of Man-in-the-Middle attacks). Monitors network integrity by tracking gateway identity.

**Requirements:** Administrator/root privileges on Linux for Layer 2 packet access. On Windows, install [Npcap](https://nmap.org/npcap/) or [WinPcap](https://www.winpcap.org/) for full Scapy functionality.

**Configuration** (in `config.yaml`):

```yaml
arp_detector:
  gateway_ip: "192.168.1.1"      # Target gateway to monitor
  scan_interval: 5                # Seconds between MAC checks
  alert_threshold: 3              # Consecutive detections before alert
```

**Usage:**

```bash
shadow > start arp_detector
[+] Launched arp_detector (PID: 13704)
2026-04-12 14:18:57 [INFO] Initializing with gateway 192.168.1.1
2026-04-12 14:18:57 [INFO] Baseline MAC: a1:b2:c3:d4:e5:f6

# The module continuously monitors gateway MAC, publishes spoof alerts:
# - Severity: critical
# - Payload: {"gateway_ip": "192.168.1.1", "expected_mac": "a1:b2:c3:d4:e5:f6", "detected_mac": "x1:x2:x3:x4:x5:x6"}

shadow > status
MODULE               | PID      | STATUS
------------------------------------------
arp_detector         | 13704    | 🟢 ALIVE
```

**Dashboard Integration:** Spoof alerts appear in the Threat Alert panel with red background (critical severity).

---

### 🗺️ Active Network Mapper (`network_mapper`)

Discovers all active devices on the subnet. Useful for identifying shadow IT (unauthorized hardware) and maintaining asset baselines for NOC operations.

**Configuration** (in `config.yaml`):

```yaml
network_mapper:
  target_network: "192.168.1.0/24"  # CIDR notation
  scan_interval: 60                  # Seconds between discovery scans
```

**Usage:**

```bash
shadow > start network_mapper
[+] Launched network_mapper (PID: 17340)
2026-04-12 14:19:04 [INFO] Initializing with target network 192.168.1.0/24

# The module periodically scans subnet, publishes discovery updates:
# - Severity: info (warning if new devices detected)
# - Payload: {"device_count": 18, "hosts": [{"ip": "192.168.1.100", "mac": "aa:bb:cc:dd:ee:ff"}, ...]}

shadow > status
MODULE               | PID      | STATUS
------------------------------------------
network_mapper       | 17340    | 🟢 ALIVE
```

**Dashboard Integration:** Device inventory appears in Discovery Panel, updated every 60 seconds (configurable).

---

### 💡 Deployment Scenario: Complete Network Visibility

Run both modules together for full network integrity monitoring:

```bash
shadow > start-all
[+] Launched sentinel (PID: 2476)
[+] Launched smoke_test (PID: 18504)
[+] Launched arp_detector (PID: 13704)
[+] Launched network_mapper (PID: 17340)
[+] Launched wifi_analyzer (PID: 18496)

shadow > status
MODULE               | PID      | STATUS
------------------------------------------
sentinel             | 2476     | 🟢 ALIVE
smoke_test           | 18504    | 🟢 ALIVE
arp_detector         | 13704    | 🟢 ALIVE
network_mapper       | 17340    | 🟢 ALIVE
wifi_analyzer        | 18496    | 🟢 ALIVE

# Open dashboard at http://127.0.0.1:8055
# Real-time telemetry from all modules + threat intelligence feed
```

---
