# SIEM Rule Templates: Scenario 5 — OAuth Abuse

## Splunk (SPL)
```
index=security sourcetype=oauth_consents publisher="Unverified" OR scopes="*Mail.ReadWrite*" OR scopes="*Files.ReadWrite*"
| stats count by user, app, scopes, publisher
```

```
index=security sourcetype=token_activity ip!="192.168.*"
| stats count by user, app, ip, action
```

```
index=security sourcetype=mailbox_rules action="forward"
| stats count by user, pattern, action, to
```

## Microsoft Sentinel (KQL)
```
OAuthConsents
| where Publisher == "Unverified" or Scopes has_any ("Mail.ReadWrite", "Files.ReadWrite")
| summarize count() by User, App, Scopes, Publisher
```

```
TokenActivity
| where IP !startswith "192.168."
| summarize count() by User, App, IP, Action
```

```
MailboxRules
| where Action == "forward"
| summarize count() by User, Pattern, Action, To
```

## QRadar (AQL)
```
SELECT user, app, scopes, publisher FROM oauth_consents WHERE publisher = 'Unverified' OR scopes LIKE '%Mail.ReadWrite%' OR scopes LIKE '%Files.ReadWrite%';
```

```
SELECT user, app, ip, action FROM token_activity WHERE ip NOT LIKE '192.168.%';
```

```
SELECT user, pattern, action, to FROM mailbox_rules WHERE action = 'forward';
```

---

Use these templates to create detection rules for OAuth abuse and mailbox forwarding in your SIEM.
