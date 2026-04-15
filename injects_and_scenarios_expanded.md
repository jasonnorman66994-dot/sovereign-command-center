# Additional Injects & Scenario Expansion

## Inject 6: Vendor Email Compromise
- Invoice fraud from lookalike domain
- Poisoned PDF attachment
- Supply-chain impersonation

## Inject 7: Insider Misuse
- Mass file downloads from HR system
- Privilege escalation event
- Suspicious access to payroll data

## Inject 8: Impossible Travel + Token Replay
- Session from NY, then Singapore within 2 minutes
- Same token fingerprint used

## Inject 9: Credential Stuffing Attack
- Multiple failed logins from diverse IPs
- Sudden success for privileged account

## Inject 10: Phishing with MFA Bypass
- Phishing email with fake MFA prompt
- Session hijack after token theft

---

# Example Log Snippets for Each Inject

## Vendor Compromise
Apr 14 09:01:10 mailserver postfix/submission[2222]: from=<billing@vend0r-payments.com> to=<ap@company.com> subject="Invoice Q2" attachment="invoice.pdf"
Apr 14 09:01:12 mailserver postfix/submission[2222]: attachment anomaly: PDF contains macro

## Insider Misuse
Apr 14 11:32:10 fileserver[5555]: DOWNLOAD user=hr_analyst@example.com file="payroll_2026.xlsx"
Apr 14 11:32:12 fileserver[5555]: PRIV_ESC user=hr_analyst@example.com new_role="HR_Admin"

## Impossible Travel
Apr 14 14:01:10 idp[4411]: LOGIN SUCCESS user=exec@example.com location="NY" token=TK-123
Apr 14 14:03:05 idp[4411]: LOGIN SUCCESS user=exec@example.com location="Singapore" token=TK-123

## Credential Stuffing
Apr 14 15:10:10 mailserver imapd[7777]: LOGIN FAILED user=admin@example.com host=201.10.10.1
Apr 14 15:10:12 mailserver imapd[7777]: LOGIN FAILED user=admin@example.com host=201.10.10.2
Apr 14 15:10:15 mailserver imapd[7777]: LOGIN SUCCESS user=admin@example.com host=201.10.10.3

## Phishing with MFA Bypass
Apr 14 16:20:10 mailserver postfix/submission[2222]: from=<it-support@company-help.com> to=<user@example.com> subject="MFA Required"
Apr 14 16:20:12 mailserver postfix/submission[2222]: body anomaly: fake MFA link detected
Apr 14 16:20:15 idp[4411]: SESSION HIJACK user=user@example.com token=TK-999

---

# Add these to your SOC-Day timeline and training suite for deeper coverage.
