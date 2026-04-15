# SIEM Automation & Integration Guide

## 1. SIEM Log Forwarding
- Configure your log parsing scripts (e.g., analyze_mail_log.py, parse_windows_event_logs.ps1) to output in a SIEM-friendly format (CEF, JSON, or syslog).
- Use a syslog forwarder (e.g., nxlog, rsyslog, or PowerShell's Send-UDPSyslogMessage) to send parsed events to your SIEM (Splunk, Sentinel, QRadar, etc.).

## 2. Example: PowerShell Syslog Forwarding
```powershell
# Send a parsed event to SIEM via syslog
$event = '{"event_type":"bec_detection","user":"ceo@example.com","ip":"45.199.12.88","indicator":"new_device_fingerprint"}'
$udpClient = New-Object System.Net.Sockets.UdpClient
$bytes = [System.Text.Encoding]::UTF8.GetBytes($event)
$udpClient.Send($bytes, $bytes.Length, "siem.company.local", 514)
$udpClient.Close()
```

## 3. SIEM Alert Rules
- Create correlation rules for:
  - New device fingerprint for executive
  - Reply-to header change to external domain
  - Mailbox rule creation (delete/move security/finance)
  - Financial keyword detection
- Use the SQL queries from scenario4_bec_detection.md as logic for SIEM rules.

## 4. Automation
- Schedule log parsing and forwarding scripts to run every 5 minutes.
- Use SIEM dashboards to visualize and alert on BEC, malware, spam, and unauthorized access scenarios.

---

# Further Integration
- Extend log parsers to handle new log types (e.g., mailboxd, device_fingerprints, rule changes).
- Normalize all events to a common schema (timestamp, user, event_type, indicator, details).
- Feed all events to both Grafana and SIEM for unified visibility.
