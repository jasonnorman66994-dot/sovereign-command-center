# Scenario 6 - Vendor Email Compromise (Invoice Fraud Supply-Chain Attack)

## Input Evidence Bundle

### 1. Vendor Email Logs

```text
Apr 14 10:12:44 mailserver postfix/smtpd[2211]: from=<billing@trustedvendor.com> to=<ap_team@example.com> subject="Updated Invoice #4471"
Apr 14 10:12:45 mailserver postfix/smtpd[2211]: header anomaly: SPF=pass, DKIM=pass, DMARC=pass
Apr 14 10:12:46 mailserver postfix/smtpd[2211]: attachment: invoice_4471.pdf
```

### 2. Content Inspection

```text
Apr 14 10:12:47 contentfilter[5512]: anomaly: banking details changed from previous invoices
Apr 14 10:12:48 contentfilter[5512]: anomaly: payment urgency language detected ("immediately", "overdue", "avoid service disruption")
```

### 3. Vendor Mailbox Telemetry

```text
Apr 14 09:55:10 intel_feed: vendor=trustedvendor.com indicator=mailbox_rule_forwarding target=fraudster@protonmail.com
Apr 14 09:55:11 intel_feed: vendor=trustedvendor.com indicator=login_from_country=UnknownRegion-5
```

### 4. Internal User Behavior

```text
Apr 14 10:13:02 user_action: ap_team@example.com opened invoice_4471.pdf
Apr 14 10:13:05 user_action: ap_team@example.com replied "Received. Processing now."
```

## Detection Logic (for SOC Automation)

- Detect mailbox forwarding rules from the vendor
- Detect vendor login from an unusual region
- Detect changed banking details in invoice content
- Detect urgency language in the email body
- Detect AP team engagement with the invoice

## Expected Classification

Vendor Email Compromise -> Invoice Fraud Attempt

## SOC Actions

- Alert AP team to stop payment
- Quarantine the invoice email
- Notify finance leadership
- Block further emails from the vendor until verified
- Contact the vendor security team
- Review AP team replies
- Add indicators to SIEM

## Example SQL for Dashboard/Detection

```sql
-- Vendor mailbox forwarding rules
SELECT * FROM intel_feed WHERE indicator = 'mailbox_rule_forwarding';
-- Vendor login from unusual region
SELECT * FROM intel_feed WHERE indicator LIKE 'login_from_country=%' AND indicator NOT LIKE '%US%' AND indicator NOT LIKE '%UK%';
-- Changed banking details
SELECT * FROM contentfilter WHERE anomaly LIKE '%banking details changed%';
-- Urgency language
SELECT * FROM contentfilter WHERE anomaly LIKE '%urgency language%';
-- AP team engagement
SELECT * FROM user_action WHERE user = 'ap_team@example.com' AND action LIKE '%opened%' OR action LIKE '%replied%';
```

## Training Drill: Vendor Compromise Walkthrough

1. Review `intel_feed` and `contentfilter` for vendor anomalies.
2. Check `user_action` for AP engagement.
3. Use dashboard panels to correlate signals.
4. Practice SOC response steps as listed above.
