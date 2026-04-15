# Email Spam Incident Response Checklist

> **Last Updated:** April 14, 2026

## How to Use
1. Review each step in order during a spam incident.
2. Use the provided commands for rapid response.
3. Reference the 'See Also' table for related playbooks and scripts.
4. Print or share this checklist as needed for your team.

This checklist provides a structured, actionable guide for administrators responding to a spam outbreak.

---

## 1. Detection
- Monitor mail server logs for unusual spikes.
- Review SIEM alerts for outbound anomalies.
- Confirm alert thresholds (e.g., >500 emails/hour).

**Commands:**
- `tail -f /var/log/maillog`

---

## 2. Investigation
- Identify source account or IP.
- Review sample emails for phishing or malware.
- Check SPF/DKIM/DMARC authentication.

**Commands:**
- `grep "from=" /var/log/maillog | sort | uniq -c | sort -nr`
- `dig +short TXT example.com`

---

## 3. Containment
- Disable compromised accounts.
- Throttle outbound mail temporarily.
- Quarantine suspicious messages.

**Commands:**
- `sudo usermod -L compromised_user`

---

## 4. Root Cause Analysis
- Check for open relay vulnerabilities.
- Scan affected devices for malware.
- Review authentication logs for unauthorized access.

**Commands:**
- `telnet mail.example.com 25`

---

## 5. Remediation
- Reset all affected credentials.
- Enforce multi-factor authentication (MFA).
- Patch mail server and related systems.

**Commands:**
- `sudo apt update && sudo apt upgrade`

---

## 6. Recovery & Monitoring
- Check domain/IP reputation using MXToolbox.
- Request delisting from major providers.
- Implement continuous monitoring and stricter thresholds.

**Tools:**
- SIEM dashboards (Splunk, Sentinel)
- Email gateways (Proofpoint, Mimecast)

---

## ✅ Key Takeaways
- Rapid detection and containment prevent escalation.
- Authentication protocols (SPF, DKIM, DMARC) are critical.
- Continuous monitoring ensures long-term protection.

---

This checklist can be printed or integrated into your incident response documentation for quick reference during email security events.

---

## See Also
| 📄 Resource | Description |
|---|---|
| [🛡️ Unified Email Threat Response Playbook](unified_email_threat_response_playbook.md) | Unified workflow for spam, phishing, malware, and unauthorized access. |
| [🐧 Linux Incident Response Script](email_incident_response.sh) | Automated Bash script for Linux-based email incident response. |
| [🪟 Windows Incident Response Script](email_incident_response.ps1) | Automated PowerShell script for Windows/Exchange environments. |
| [📬 Extracted Email Addresses](extracted_emails.md) | All unique email addresses and their context, extracted from the workspace. |
| [📚 Documentation Index](EMAIL_SECURITY_DOCS_INDEX.md) | Central index for all email security documentation and automation. |
