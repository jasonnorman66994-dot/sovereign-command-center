import re
import sys


def parse_log_line(line):
    signals = []

    if "federation" in line.lower() and "policy" in line.lower() and ("update" in line.lower() or "modified" in line.lower()):
        signals.append("Unauthorized federation trust modification")

    if "token_issued" in line.lower() and ("privileged" in line.lower() or "scope=admin" in line.lower()):
        signals.append("Abnormal token minting for privileged scopes")

    if "cross-tenant" in line.lower() or "tenant_context" in line.lower():
        signals.append("Cross-tenant pivot activity")

    if "app_consent" in line.lower() and ("elevated" in line.lower() or "high_privilege" in line.lower()):
        signals.append("Unauthorized privileged app consent")

    if "export" in line.lower() and ("sensitive" in line.lower() or "dataset" in line.lower()):
        signals.append("Sensitive data export spike")

    if "ueba" in line.lower() and "trust abuse" in line.lower():
        signals.append("UEBA trust-abuse correlation")

    return signals


def main():
    for raw in sys.stdin:
        line = raw.strip()
        found = parse_log_line(line)
        if found:
            print(f"{line} | Detected: {', '.join(found)}")


if __name__ == "__main__":
    main()
