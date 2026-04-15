#!/usr/bin/env python3
"""
Report Exporter
===============
Generates HTML and JSON reports from scan results.
"""

import html
import json
import os
import time
from dataclasses import asdict, dataclass, field, is_dataclass
from datetime import datetime
from pathlib import Path


def dataclass_to_dict(obj):
    """Recursively convert dataclasses to dicts, handling bytes and other non-serializable types."""
    if is_dataclass(obj) and not isinstance(obj, type):
        result = {}
        for k, v in obj.__dict__.items():
            if isinstance(v, bytes):
                result[k] = v.hex()
            elif isinstance(v, list):
                result[k] = [dataclass_to_dict(i) for i in v]
            elif is_dataclass(v):
                result[k] = dataclass_to_dict(v)
            else:
                result[k] = v
        return result
    return obj


def export_json(data: dict, filepath: str):
    """Export scan results to JSON."""
    report = {
        "tool": "Shadow Toolkit",
        "version": "1.0.0",
        "generated_at": datetime.now().isoformat(),
        "data": data,
    }
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    return filepath


SEVERITY_COLORS = {
    "CRITICAL": "#e74c3c",
    "HIGH": "#e67e22",
    "MEDIUM": "#f39c12",
    "LOW": "#3498db",
    "INFO": "#95a5a6",
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow Toolkit - {title}</title>
<style>
  :root {{ --bg: #0a0e17; --card: #111827; --border: #1e293b; --text: #e2e8f0;
           --accent: #6366f1; --critical: #ef4444; --high: #f97316;
           --medium: #eab308; --low: #3b82f6; --info: #6b7280; }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
          line-height: 1.6; padding: 2rem; }}
  .container {{ max-width: 1200px; margin: 0 auto; }}
  header {{ text-align: center; padding: 2rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }}
  header h1 {{ font-size: 2rem; color: var(--accent); letter-spacing: 2px; }}
  header .subtitle {{ color: #94a3b8; font-size: 0.9rem; margin-top: 0.5rem; }}
  .banner {{ background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
             border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 2rem; }}
  .banner pre {{ color: var(--accent); font-size: 0.6rem; line-height: 1.2; text-align: center; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem; margin-bottom: 2rem; }}
  .stat-card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
                padding: 1.2rem; text-align: center; }}
  .stat-card .value {{ font-size: 2rem; font-weight: bold; color: var(--accent); }}
  .stat-card .label {{ color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }}
  .severity-summary {{ display: flex; gap: 1rem; justify-content: center; flex-wrap: wrap;
                       margin-bottom: 2rem; }}
  .severity-badge {{ padding: 0.5rem 1.2rem; border-radius: 20px; font-weight: bold; font-size: 0.9rem; }}
  .sev-critical {{ background: rgba(239,68,68,0.15); color: var(--critical); border: 1px solid var(--critical); }}
  .sev-high {{ background: rgba(249,115,22,0.15); color: var(--high); border: 1px solid var(--high); }}
  .sev-medium {{ background: rgba(234,179,8,0.15); color: var(--medium); border: 1px solid var(--medium); }}
  .sev-low {{ background: rgba(59,130,246,0.15); color: var(--low); border: 1px solid var(--low); }}
  .sev-info {{ background: rgba(107,114,128,0.15); color: var(--info); border: 1px solid var(--info); }}
  .findings {{ margin-bottom: 2rem; }}
  .finding {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px;
              margin-bottom: 1rem; overflow: hidden; }}
  .finding-header {{ padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem;
                     border-bottom: 1px solid var(--border); }}
  .finding-header .sev {{ padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem;
                          font-weight: bold; text-transform: uppercase; }}
  .finding-header .title {{ font-weight: 600; flex: 1; }}
  .finding-body {{ padding: 1rem 1.5rem; }}
  .finding-body .detail {{ display: grid; grid-template-columns: 120px 1fr; gap: 0.5rem;
                           margin-bottom: 0.3rem; }}
  .finding-body .detail .key {{ color: #64748b; font-size: 0.85rem; }}
  .finding-body .detail .val {{ font-family: 'Cascadia Code', 'Fira Code', monospace;
                                font-size: 0.85rem; word-break: break-all; }}
  .payload {{ background: #1e1e2e; padding: 0.3rem 0.6rem; border-radius: 4px; color: #f97316; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--card);
           border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
  th {{ background: #1e293b; padding: 0.75rem 1rem; text-align: left; font-size: 0.85rem;
       text-transform: uppercase; letter-spacing: 1px; color: #94a3b8; }}
  td {{ padding: 0.75rem 1rem; border-top: 1px solid var(--border); font-size: 0.9rem; }}
  tr:hover td {{ background: rgba(99,102,241,0.05); }}
  .section-title {{ font-size: 1.3rem; color: var(--accent); margin: 2rem 0 1rem; padding-bottom: 0.5rem;
                    border-bottom: 1px solid var(--border); }}
  footer {{ text-align: center; padding: 2rem 0; color: #475569; font-size: 0.8rem;
            border-top: 1px solid var(--border); margin-top: 2rem; }}
  .recommendation {{ background: rgba(99,102,241,0.1); border-left: 3px solid var(--accent);
                     padding: 0.5rem 1rem; margin-top: 0.5rem; border-radius: 0 4px 4px 0; }}
  @media print {{ body {{ background: #fff; color: #000; }}
                  .finding {{ page-break-inside: avoid; }} }}
</style>
</head>
<body>
<div class="container">
  <div class="banner">
    <pre>
  ____  _               _                 _____           _ _    _ _
 / ___|| |__   __ _  __| | _____      __ |_   _|__   ___ | | | _(_) |_
 \\___ \\| '_ \\ / _` |/ _` |/ _ \\ \\ /\\ / /   | |/ _ \\ / _ \\| | |/ / | __|
  ___) | | | | (_| | (_| | (_) \\ V  V /    | | (_) | (_) | |   &lt;| | |_
 |____/|_| |_|\\__,_|\\__,_|\\___/ \\_/\\_/     |_|\\___/ \\___/|_|_|\\_\\_|\\__|
    </pre>
  </div>
  <header>
    <h1>{title}</h1>
    <div class="subtitle">Generated: {timestamp} | Shadow Toolkit v1.0.0</div>
  </header>
  {content}
  <footer>
    Shadow Toolkit &mdash; Ethical Security Testing Suite &mdash; For authorized use only
  </footer>
</div>
</body>
</html>"""


def _severity_class(sev: str) -> str:
    return f"sev-{sev.lower()}"


def generate_vuln_report_html(scan_data: dict) -> str:
    """Generate HTML for web vulnerability scan results."""
    vulns = scan_data.get("vulnerabilities", [])
    target = scan_data.get("target", "Unknown")
    duration = scan_data.get("duration", 0)
    urls_crawled = scan_data.get("links_crawled", 0)
    forms_found = scan_data.get("forms_found", 0)

    # Stats
    counts = {}
    for v in vulns:
        s = v.get("severity", "INFO")
        counts[s] = counts.get(s, 0) + 1

    stats_html = f"""
    <div class="stats">
      <div class="stat-card"><div class="value">{len(vulns)}</div><div class="label">Vulnerabilities</div></div>
      <div class="stat-card"><div class="value">{urls_crawled}</div><div class="label">URLs Crawled</div></div>
      <div class="stat-card"><div class="value">{forms_found}</div><div class="label">Forms Found</div></div>
      <div class="stat-card"><div class="value">{duration:.1f}s</div><div class="label">Scan Duration</div></div>
    </div>"""

    # Severity summary
    sev_html = '<div class="severity-summary">'
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in counts:
            sev_html += f'<span class="severity-badge {_severity_class(sev)}">{sev}: {counts[sev]}</span>'
    sev_html += "</div>"

    # Findings
    findings_html = '<div class="findings"><h2 class="section-title">Findings</h2>'
    for v in sorted(vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.get("severity", "INFO"))):
        sev = v.get("severity", "INFO")
        findings_html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="sev {_severity_class(sev)}">{sev}</span>
            <span class="title">{html.escape(v.get('vuln_type', ''))}</span>
          </div>
          <div class="finding-body">
            <div class="detail"><span class="key">URL</span><span class="val">{html.escape(v.get('url', ''))}</span></div>"""
        if v.get("parameter"):
            findings_html += f'<div class="detail"><span class="key">Parameter</span><span class="val">{html.escape(v["parameter"])}</span></div>'
        if v.get("payload"):
            findings_html += f'<div class="detail"><span class="key">Payload</span><span class="val"><span class="payload">{html.escape(v["payload"])}</span></span></div>'
        if v.get("evidence"):
            findings_html += f'<div class="detail"><span class="key">Evidence</span><span class="val">{html.escape(v["evidence"])}</span></div>'
        if v.get("description"):
            findings_html += f'<div class="detail"><span class="key">Detail</span><span class="val">{html.escape(v["description"])}</span></div>'
        findings_html += "</div></div>"
    findings_html += "</div>"

    return HTML_TEMPLATE.format(
        title=f"Web Scan Report — {html.escape(target)}",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        content=stats_html + sev_html + findings_html,
    )


def generate_port_report_html(scan_data: dict) -> str:
    """Generate HTML for port scan results."""
    target = scan_data.get("target", "Unknown")
    ip = scan_data.get("ip", "")
    results = scan_data.get("results", [])
    duration = scan_data.get("duration", 0)

    open_ports = [r for r in results if r.get("state") == "open"]

    stats_html = f"""
    <div class="stats">
      <div class="stat-card"><div class="value">{len(open_ports)}</div><div class="label">Open Ports</div></div>
      <div class="stat-card"><div class="value">{ip}</div><div class="label">Target IP</div></div>
      <div class="stat-card"><div class="value">{duration:.2f}s</div><div class="label">Scan Duration</div></div>
    </div>"""

    table_html = """
    <h2 class="section-title">Open Ports</h2>
    <table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr></thead><tbody>"""
    for r in sorted(open_ports, key=lambda x: x.get("port", 0)):
        table_html += f"""<tr>
            <td>{r.get('port', '')}</td><td>{r.get('protocol', 'tcp').upper()}</td>
            <td>{html.escape(r.get('service', 'unknown'))}</td>
            <td>{html.escape(r.get('version', '') or '')}</td></tr>"""
    table_html += "</tbody></table>"

    return HTML_TEMPLATE.format(
        title=f"Port Scan Report — {html.escape(target)}",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        content=stats_html + table_html,
    )


def generate_dns_report_html(scan_data: dict) -> str:
    """Generate HTML for DNS enumeration results."""
    domain = scan_data.get("domain", "Unknown")
    subdomains = scan_data.get("subdomains", [])
    dns_records = scan_data.get("dns_records", [])
    duration = scan_data.get("duration", 0)

    stats_html = f"""
    <div class="stats">
      <div class="stat-card"><div class="value">{len(subdomains)}</div><div class="label">Subdomains</div></div>
      <div class="stat-card"><div class="value">{len(dns_records)}</div><div class="label">DNS Records</div></div>
      <div class="stat-card"><div class="value">{duration:.2f}s</div><div class="label">Duration</div></div>
    </div>"""

    # Subdomains table
    table_html = """<h2 class="section-title">Discovered Subdomains</h2>
    <table><thead><tr><th>Subdomain</th><th>Type</th><th>Value</th></tr></thead><tbody>"""
    seen = set()
    for s in sorted(subdomains, key=lambda x: x.get("subdomain", "")):
        key = s.get("subdomain", "")
        if key in seen:
            continue
        seen.add(key)
        table_html += f"""<tr><td>{html.escape(s.get('subdomain', ''))}</td>
            <td>{html.escape(s.get('record_type', ''))}</td>
            <td>{html.escape(s.get('ip', '') or s.get('value', ''))}</td></tr>"""
    table_html += "</tbody></table>"

    # DNS Records
    if dns_records:
        table_html += """<h2 class="section-title">DNS Records</h2>
        <table><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>"""
        for r in dns_records:
            table_html += f"""<tr><td>{html.escape(r.get('record_type', ''))}</td>
                <td>{html.escape(r.get('value', ''))}</td></tr>"""
        table_html += "</tbody></table>"

    return HTML_TEMPLATE.format(
        title=f"DNS Enumeration Report — {html.escape(domain)}",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        content=stats_html + table_html,
    )


def generate_detect_report_html(scan_data: dict) -> str:
    """Generate HTML for malware detection results."""
    hostname = scan_data.get("hostname", "Unknown")
    findings = scan_data.get("findings", [])
    os_info = scan_data.get("os_info", "")
    threat_score = scan_data.get("threat_score", 0)

    notable = [f for f in findings if f.get("severity") != "INFO"]

    stats_html = f"""
    <div class="stats">
      <div class="stat-card"><div class="value">{len(notable)}</div><div class="label">Notable Findings</div></div>
      <div class="stat-card"><div class="value">{len(findings)}</div><div class="label">Total Findings</div></div>
      <div class="stat-card"><div class="value">{threat_score}</div><div class="label">Threat Score</div></div>
      <div class="stat-card"><div class="value">{html.escape(os_info[:30])}</div><div class="label">OS</div></div>
    </div>"""

    findings_html = '<div class="findings"><h2 class="section-title">Findings</h2>'
    for f in sorted(notable, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.get("severity", "LOW"))):
        sev = f.get("severity", "INFO")
        cat = f.get("category", "")
        findings_html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="sev {_severity_class(sev)}">{sev}</span>
            <span class="title">[{html.escape(cat)}] {html.escape(f.get('title', ''))}</span>
          </div>
          <div class="finding-body">
            <div class="detail"><span class="key">Details</span><span class="val">{html.escape(f.get('details', ''))}</span></div>"""
        if f.get("recommendation"):
            findings_html += f'<div class="recommendation">💡 {html.escape(f["recommendation"])}</div>'
        findings_html += "</div></div>"
    findings_html += "</div>"

    return HTML_TEMPLATE.format(
        title=f"Malware Detection Report — {html.escape(hostname)}",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        content=stats_html + findings_html,
    )


def save_report(content: str, filepath: str):
    """Save report content to file."""
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath


def export_telemetry_csv(events: list[dict], filepath: str = None) -> str:
    """
    Export telemetry events to CSV with business segmentation.
    
    Args:
        events: List of event dicts from telemetry database
        filepath: Output CSV path (default: data/telemetry_report.csv)
    
    Returns:
        Filepath of generated CSV
    """
    import csv
    from datetime import datetime
    
    filepath = filepath or f"data/telemetry_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    os.makedirs(os.path.dirname(filepath) or ".", exist_ok=True)
    
    if not events:
        # Create empty report with headers
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['Timestamp', 'Business', 'Module', 'Event', 'Severity', 'Payload'])
        return filepath
    
    # Determine columns from first event
    fieldnames = ['Timestamp', 'Business', 'Module', 'Event', 'Severity', 'Payload']
    
    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        
        for event in events:
            writer.writerow({
                'Timestamp': event.get('timestamp', ''),
                'Business': event.get('business', 'global'),
                'Module': event.get('module', ''),
                'Event': event.get('event', ''),
                'Severity': event.get('severity', 'info'),
                'Payload': json.dumps(event.get('payload', {})),
            })
    
    return filepath


def generate_business_health_report(targets: dict, events: list[dict]) -> str:
    """
    Generate multi-tenant health report showing alert statistics per business.
    
    Args:
        targets: Business registry from targets.json
        events: List of telemetry events
    
    Returns:
        HTML report string
    """
    # Compute stats per business
    business_stats = {name: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
                      for name in targets.keys()}
    business_stats["global"] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
    
    for event in events:
        business = event.get('business', 'global')
        if business not in business_stats:
            business_stats[business] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0, "total": 0}
        
        severity = event.get('severity', 'info').upper()
        if severity in business_stats[business]:
            business_stats[business][severity] += 1
        business_stats[business]["total"] += 1
    
    # Build table
    table_html = """
    <h2 class="section-title">Business Alert Summary</h2>
    <table>
      <thead>
        <tr>
          <th>Business / Target</th>
          <th>Network Range</th>
          <th>Critical</th>
          <th>High</th>
          <th>Medium</th>
          <th>Low</th>
          <th>Info</th>
          <th>Total Events</th>
        </tr>
      </thead>
      <tbody>"""
    
    for business, stats in sorted(business_stats.items()):
        if business == "global":
            network_range = "N/A"
            contacts = "N/A"
        else:
            network_range = targets.get(business, {}).get('network_range', 'N/A')
            contacts = ', '.join(targets.get(business, {}).get('contacts', []))
        
        table_html += f"""
        <tr>
          <td><strong>{html.escape(business)}</strong></td>
          <td><code>{html.escape(network_range)}</code></td>
          <td style="color: var(--critical);">{stats.get('CRITICAL', 0)}</td>
          <td style="color: var(--high);">{stats.get('HIGH', 0)}</td>
          <td style="color: var(--medium);">{stats.get('MEDIUM', 0)}</td>
          <td style="color: var(--low);">{stats.get('LOW', 0)}</td>
          <td>{stats.get('INFO', 0)}</td>
          <td><strong>{stats.get('total', 0)}</strong></td>
        </tr>"""
    
    table_html += "</tbody></table>"
    
    return HTML_TEMPLATE.format(
        title="SHADOW-TOOLZ MSSP Health Report",
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        content=table_html,
    )
