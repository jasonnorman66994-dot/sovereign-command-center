# Scenario 4 - Business Email Compromise (BEC) Attempt

## Overview

An external actor uses a compromised executive mailbox to launch a financial fraud attempt. The attack combines abnormal login context, message tampering, and mailbox-rule persistence to evade normal user notice and drive urgent wire-transfer behavior.

## Input Evidence Bundle

### 1. Login + Session Telemetry

```text
Apr 14 06:02:11 mailserver imapd[7777]: LOGIN SUCCESS user=ceo@example.com host=45.199.12.88
Apr 14 06:02:12 mailserver imapd[7777]: SESSION START user=ceo@example.com host=45.199.12.88
Apr 14 06:02:13 mailserver imapd[7777]: WARNING: OAuth token used from new device fingerprint: DF-9981-AZ
```

### 2. Email Behavior Anomalies

```text
Apr 14 06:05:44 mailserver postfix/submission[2222]: from=<ceo@example.com> to=<finance_lead@example.com> subject="Need a quick favor"
Apr 14 06:05:45 mailserver postfix/submission[2222]: header anomaly: reply-to changed to external address <ceo-secure@consultantmail.com>
Apr 14 06:05:46 mailserver postfix/submission[2222]: body anomaly: financial request keywords detected ("urgent", "wire", "confidential")
```

### 3. Mailbox Rule Creation

```text
Apr 14 06:06:10 mailboxd[3333]: RULE CREATED user=ceo@example.com action=move_to_folder pattern="invoice" folder="Archive"
Apr 14 06:06:11 mailboxd[3333]: RULE CREATED user=ceo@example.com action=delete pattern="security"
```

## Key Detection Signals

- Detect successful login from unusual IP
- Detect new device fingerprint for user
- Detect OAuth token use from new device
- Detect reply-to header change to external domain
- Detect financial urgency keywords in body
- Detect mailbox rules that hide or delete security or finance messages

## Expected Classification

Business Email Compromise (BEC) - Active Account Takeover

## SOC Actions

- Disable CEO account
- Revoke OAuth tokens
- Terminate active sessions
- Block suspicious IP
- Review sent items for fraud
- Check mailbox rules
- Validate MFA status
- Notify finance team
- Add indicators to SIEM

## Grafana Dashboard Panel Suggestions

- Panel: "Unusual Login Locations"
- Panel: "New Device Fingerprints"
- Panel: "Reply-To Header Changes"
- Panel: "Financial Keyword Alerts"
- Panel: "Mailbox Rule Changes"

## Example SQL for Dashboard (SQLite)

```sql
-- Unusual logins
SELECT user, host, COUNT(*) as logins FROM login_events WHERE host NOT LIKE '192.168.%' GROUP BY user, host;
-- New device fingerprints
SELECT user, fingerprint, MIN(time) as first_seen FROM device_fingerprints GROUP BY user, fingerprint HAVING COUNT(*) = 1;
-- Reply-to header changes
SELECT * FROM mail_activity WHERE reply_to NOT LIKE '%@example.com';
-- Financial keyword alerts
SELECT * FROM mail_activity WHERE body LIKE '%urgent%' OR body LIKE '%wire%' OR body LIKE '%confidential%';
-- Mailbox rule changes
SELECT * FROM mailbox_rules WHERE action IN ('move_to_folder', 'delete') AND (pattern LIKE '%invoice%' OR pattern LIKE '%security%');
```

## Training Drill: BEC Detection Walkthrough

1. Review `login_events` and `device_fingerprints` tables for anomalies.
2. Check `mail_activity` for reply-to, header, and body anomalies.
3. Inspect `mailbox_rules` for suspicious changes.
4. Use dashboard panels to visualize and correlate signals.
5. Practice SOC response steps as listed above.

## Timeline

| Time  | Event |
|-------|-------|
| 06:02 | Suspicious login succeeds from unusual host and new device fingerprint |
| 06:05 | Fraud-style email sent with modified reply-to and urgency language |
| 06:06 | Mailbox rules created to hide invoice and security-related mail |

## Analyst Guidance

Treat this scenario as active account takeover with fraud intent. Prioritize session revocation, message-trace review, mailbox-rule rollback, and finance-team validation of all recent payment requests.
