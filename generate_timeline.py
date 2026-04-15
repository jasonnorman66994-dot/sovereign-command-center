import csv
from pathlib import Path


def classify_phase(key_event, detection, response):
    text = f"{key_event} {detection} {response}".lower()
    detection_text = detection.lower()

    # Ordered high-to-low confidence mapping to MITRE-style tactic labels.
    tactic_rules = [
        ('Exfiltration', (
            'exfil', 'outbound transfer', 'data leakage', 'metadata exported',
            'model inversion', 'webhook'
        )),
        ('Impact', (
            'ransom', 'encryption', 'detonation', 'deletes application data',
            'overwrites root filesystem', 'fraudulent settlement', 'kill switch',
            'catastrophic volume', 'disables transaction integrity checks',
            'transaction integrity checks'
        )),
        ('Command and Control', (
            'c2', 'beacon', 'dns tunneling', 'reverse shell', 'relay'
        )),
        ('Persistence', (
            'persistence', 'cron', 'rogue federation trust', 'shadow vm clone',
            'rogue signing key', 'stealth vpn', 'root certificate'
        )),
        ('Privilege Escalation', (
            'escalates', 'cluster-admin', 'global admin', 'assumes',
            'privileged access', 'admin role', 'net_admin',
            'service principal hijack', 'rogue service principal created'
        )),
        ('Credential Access', (
            'stolen credentials', 'credential replay', 'token replay', 'oauth abuse',
            'secrets harvested', 'signing key exported', 'stolen disk key',
            'vm-disk-key', 'key extraction', 'secrets container accessed',
            'api token used', 'tokens harvested'
        )),
        ('Lateral Movement', (
            'lateral movement', 'pivots', 'session hijack', 'sidecar breakout',
            'cross-tenant', 'hybrid pivot'
        )),
        ('Defense Evasion', (
            'hide credential theft alerts', 'suppression rules', 'bypasses mfa',
            'impersonation', 'forged', 'without review', 'deletes 36 minutes of audit logs',
            'audit logs via privileged api call', 'silently disables'
        )),
        ('Discovery', (
            'reads tpm pcr', 'attestation report', 'schema data', 'extract system context',
            'reveal retrieval context'
        )),
        ('Initial Access', (
            'spam burst', 'malware attachment', 'business email compromise',
            'compromised', 'adversarial prompt', 'rogue container image',
            'unknown device fingerprint', 'vendor compromise',
            'serialized exploit payload', 'spear-phish', 'supply-chain poisoning',
            'poisoned hotfix'
        )),
    ]

    for tactic, keywords in tactic_rules:
        matches = sum(1 for keyword in keywords if keyword in text)
        if matches:
            confidence = 'High' if matches >= 2 else 'Medium'

            # Severity-aware boost: critical detections are high confidence
            # even when only one tactic keyword matches.
            if 'ueba critical' in detection_text:
                confidence = 'High'
            elif 'critical' in detection_text and confidence == 'Medium':
                confidence = 'High'

            return tactic, confidence

    fallback_confidence = 'Low'
    if 'ueba critical' in detection_text or 'critical' in detection_text:
        fallback_confidence = 'High'
    elif 'escalation' in detection_text:
        fallback_confidence = 'Medium'

    return 'Initial Access', fallback_confidence


def generate_timeline_md(csv_path, md_path):
    with open(csv_path, newline='', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile, delimiter=';')
        rows = list(reader)

    if not rows:
        raise ValueError('CSV file is empty and cannot be converted to markdown.')

    source_header = [cell.strip() for cell in rows[0]]
    source_expected_cols = len(source_header)
    has_phase = 'Phase' in source_header
    has_confidence = 'Confidence' in source_header

    if has_phase:
        header = source_header.copy()
        phase_idx = header.index('Phase')
    else:
        phase_idx = source_header.index('Key Event') + 1 if 'Key Event' in source_header else 2
        header = source_header.copy()
        header.insert(phase_idx, 'Phase')

    if has_confidence:
        confidence_idx = header.index('Confidence')
    else:
        confidence_idx = phase_idx + 1
        header.insert(confidence_idx, 'Confidence')

    key_event_idx = source_header.index('Key Event') if 'Key Event' in source_header else None
    detection_idx = source_header.index('Detection') if 'Detection' in source_header else None
    response_idx = source_header.index('Response') if 'Response' in source_header else None

    data = []

    for raw_row in rows[1:]:
        # Skip fully empty rows.
        if not any(cell.strip() for cell in raw_row):
            continue

        row = [cell.strip() for cell in raw_row]

        if len(row) < source_expected_cols:
            row.extend([''] * (source_expected_cols - len(row)))
        elif len(row) > source_expected_cols:
            row = row[:source_expected_cols - 1] + ['; '.join(row[source_expected_cols - 1:])]

        key_event = row[key_event_idx] if key_event_idx is not None else ''
        detection = row[detection_idx] if detection_idx is not None else ''
        response = row[response_idx] if response_idx is not None else ''
        tactic, confidence = classify_phase(key_event, detection, response)

        if not has_phase:
            row.insert(phase_idx, tactic)
        if not has_confidence:
            row.insert(confidence_idx, confidence)

        data.append(row)

    expected_cols = len(header)

    col_widths = [len(col) for col in header]
    for row in data:
        for idx, cell in enumerate(row):
            col_widths[idx] = max(col_widths[idx], len(cell))

    def format_row(row_values):
        return '| ' + ' | '.join(
            row_values[idx].ljust(col_widths[idx]) for idx in range(expected_cols)
        ) + ' |'
    
    legend = (
        '\n---\n\n'
        '## Confidence Scoring Legend\n\n'
        '| Confidence | Criteria |\n'
        '|------------|----------|\n'
        '| High       | ≥2 MITRE tactic keywords matched in event text, '
        'OR detection field contains `critical` / `UEBA critical` |\n'
        '| Medium     | 1 MITRE tactic keyword matched, '
        'OR detection field contains `escalation` |\n'
        '| Low        | No tactic keywords matched (fallback tactic assigned) |\n\n'
        '**Phase** labels follow MITRE ATT&CK tactic names. '
        'Classification is rule-based and injected at generation time — not stored in the source CSV.\n'
    )

    with open(md_path, 'w', encoding='utf-8') as mdfile:
        mdfile.write('# Multi-Scenario Attack Chain Timeline\n\n')
        mdfile.write(format_row(header) + '\n')
        mdfile.write('|-' + '-|-'.join('-' * width for width in col_widths) + '-|\n')
        for row in data:
            mdfile.write(format_row(row) + '\n')
        mdfile.write(legend)


if __name__ == "__main__":
    csv_path = Path('data/timeline_events.csv')
    md_path = Path('multi_scenario_chain_timeline.md')
    generate_timeline_md(csv_path, md_path)
    print(f"Timeline generated in {md_path}")
