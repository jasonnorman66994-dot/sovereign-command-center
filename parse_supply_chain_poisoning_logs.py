# Parser for Scenario 12: Supply-Chain Poisoning (CI/CD Pipeline Compromise)
import re
import sys

def parse_log_line(line):
    signals = []
    # Source Control
    if 'COMMIT' in line and 'pipeline-templates' in line and 'build.yml' in line:
        signals.append('Unauthorized commit to pipeline template')
    if 'commit signed with unknown GPG key' in line:
        signals.append('Unknown GPG signature')
    # Malicious Build Step
    if 'added step="curl' in line or 'added step="wget' in line or 'added step="bash' in line:
        signals.append('Malicious build step')
    # Build Pipeline Execution
    if 'EXECUTING step="payload.sh"' in line and 'result="success"' in line:
        signals.append('Malicious build step')
    # Artifact Registry
    if 'image hash mismatch' in line:
        signals.append('Artifact hash mismatch')
    # Deployment
    if 'DEPLOY image=' in line and ('env="staging"' in line or 'env="production"' in line):
        signals.append('Poisoned artifact deployed')
    # Runtime Callback
    if 'OUTBOUND connection' in line and '185.199.220.14' in line:
        signals.append('Outbound callback to attacker')
    # Credential Harvesting
    if 'FILE READ' in line and '/etc/secrets/' in line:
        signals.append('Secret harvesting behavior')
    if 'unexpected secret access pattern' in line:
        signals.append('Secret harvesting behavior')
    return signals

def main():
    for line in sys.stdin:
        signals = parse_log_line(line.strip())
        if signals:
            print(f"{line.strip()} | Detected: {', '.join(signals)}")

if __name__ == "__main__":
    main()
