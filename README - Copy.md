# Shadow Toolkit — Ethical Security Testing Suite

```text
  ____  _               _                 _____           _ _    _ _   
 / ___|| |__   __ _  __| | _____      __ |_   _|__   ___ | | | _(_) |_ 
 \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / /   | |/ _ \ / _ \| | |/ / | __|
  ___) | | | | (_| | (_| | (_) \ V  V /    | | (_) | (_) | |   <| | |_ 
 |____/|_| |_|\__,_|\__,_|\___/ \_/\_/     |_|\___/ \___/|_|_|\_\_|\__|
```

> ⚠ **FOR AUTHORIZED USE ONLY** — Only use on systems you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

A Python-based offensive security toolkit with 10 modules for penetration testing, vulnerability assessment, and defensive security.

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

### 📊 Report Exporter

Export scan results to HTML (dark cyberpunk theme) or JSON. Add `--report` to any module:

```bash
python -m shadow_toolkit.cli portscan 192.168.1.1 --report html -o scan_report.html
python -m shadow_toolkit.cli webscan http://target --all --report json -o vulns.json
```

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
