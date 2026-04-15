#!/bin/bash
# Automated Email Security Incident Response Script
# Filters by log source, tool, and platform

# --- CONFIGURATION ---
MAIL_LOG="/var/log/maillog"   # Change as needed
DOMAIN="example.com"          # Change as needed
COMPROMISED_USER=""           # Set dynamically during investigation
SIEM_TOOL="Splunk"            # Options: Splunk, ELK, Sentinel
PLATFORM="Linux"              # Options: Linux, Windows

# --- 1. Detection ---
echo "[Detection]"
if [[ "$PLATFORM" == "Linux" ]]; then
    echo "Tailing mail log: $MAIL_LOG"
    tail -n 100 $MAIL_LOG | tee recent_mail.log
else
    echo "Use Windows Event Viewer or Exchange logs."
fi
# SIEM Alerts (manual step)
echo "Check $SIEM_TOOL dashboard for outbound mail spikes."

# --- 2. Investigation ---
echo "[Investigation]"
if [[ "$PLATFORM" == "Linux" ]]; then
    echo "Top sender accounts:"
    grep "from=<" $MAIL_LOG | awk '{print $7}' | sort | uniq -c | sort -nr | tee top_senders.log
else
    echo "Use PowerShell to parse Exchange logs."
fi
# SPF/DKIM/DMARC check
echo "SPF/DKIM/DMARC for $DOMAIN:"
dig +short TXT $DOMAIN | grep -E 'spf|dkim|dmarc' || echo "No SPF/DKIM/DMARC records found."

# --- 3. Containment ---
echo "[Containment]"
if [[ -n "$COMPROMISED_USER" ]]; then
    if [[ "$PLATFORM" == "Linux" ]]; then
        sudo usermod -L "$COMPROMISED_USER"
        echo "Account $COMPROMISED_USER locked."
    else
        echo "Use Active Directory to disable $COMPROMISED_USER."
    fi
else
    echo "Set COMPROMISED_USER variable to lock account."
fi
# Throttle outbound mail (manual step)
echo "Adjust Postfix/Exchange limits as needed."

# --- 4. Root Cause Analysis ---
echo "[Root Cause Analysis]"
if [[ "$PLATFORM" == "Linux" ]]; then
    echo "Testing open relay:"
    (echo "ehlo test"; sleep 1) | telnet localhost 25
else
    echo "Use telnet or PowerShell to test relay."
fi
# Malware scan (manual step)
echo "Run endpoint malware scan (Defender ATP, CrowdStrike, etc.)."

# --- 5. Remediation ---
echo "[Remediation]"
echo "Reset credentials and enable MFA for affected accounts."
if [[ "$PLATFORM" == "Linux" ]]; then
    sudo apt update && sudo apt upgrade -y
else
    echo "Use Windows Update to patch systems."
fi

# --- 6. Recovery & Monitoring ---
echo "[Recovery & Monitoring]"
echo "Check blacklists with MXToolbox or similar."
echo "Request delisting if needed."
echo "Monitor $SIEM_TOOL dashboard for future anomalies."

echo "--- Incident Response Script Complete ---"
