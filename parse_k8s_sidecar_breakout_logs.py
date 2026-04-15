# Parser for Scenario 11: Kubernetes Sidecar Compromise + Container Breakout
import re
import sys

def parse_log_line(line):
    signals = []
    # Initial Compromise
    if re.search(r'exec into container=.*pod=.*user=.*source_ip=', line) and 'not initiated by Kubernetes API' in line:
        signals.append('Unauthorized exec into container')
    # Sidecar Tampering
    if 'unexpected binary executed' in line or 'file integrity diff detected' in line:
        signals.append('Sidecar integrity violation')
    # Privilege Escalation
    if 'CAPABILITY ADD' in line and 'SYS_ADMIN' in line:
        signals.append('SYS_ADMIN capability escalation')
    if 'container attempted to mount host filesystem' in line:
        signals.append('Host filesystem mount attempt')
    # Node-Level Breakout
    if 'cgroup violation' in line and 'kubelet-client-current.pem' in line:
        signals.append('Kubelet client cert access')
    # Cloud API Abuse
    if 'LIST SECRETS' in line or 'DOWNLOAD SECRET' in line:
        signals.append('Cloud API secret access')
    # Lateral Movement
    if 'GET /api/v1/pods' in line or 'GET /api/v1/secrets' in line:
        signals.append('Lateral movement')
    # UEBA
    if 'anomaly_score=' in line and 'container breakout' in line:
        signals.append('UEBA: breakout + secret access + lateral movement')
    return signals

def main():
    for line in sys.stdin:
        signals = parse_log_line(line.strip())
        if signals:
            print(f"{line.strip()} | Detected: {', '.join(signals)}")

if __name__ == "__main__":
    main()
