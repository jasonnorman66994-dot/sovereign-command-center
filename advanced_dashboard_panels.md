# Additional Dashboard Panels for Advanced SOC Monitoring

## Panels to Add
- Unverified OAuth App Consents (Scenario 5)
- High-Risk OAuth Scopes Granted
- Foreign IP Token Usage
- Mailbox Forwarding Rule Creations
- Vendor Email Compromise (invoice fraud, poisoned PDF, domain lookalike)
- Insider Misuse (mass downloads, privilege escalation)
- Impossible Travel & Token Replay
- End-of-Day Severity Matrix

## Example SQL for Panels (SQLite)
```sql
-- Unverified OAuth app consents
SELECT user, app, scopes, time FROM oauth_consents WHERE publisher = 'Unverified';
-- High-risk scopes
SELECT user, app, scopes FROM oauth_consents WHERE scopes LIKE '%Mail.ReadWrite%' OR scopes LIKE '%Files.ReadWrite%';
-- Foreign IP token usage
SELECT user, app, ip, action, time FROM token_activity WHERE ip NOT LIKE '192.168.%';
-- Mailbox forwarding rules
SELECT user, pattern, action, "to", time FROM mailbox_rules WHERE action = 'forward';
-- Vendor compromise
SELECT * FROM mail_activity WHERE sender LIKE '%@vendor%' AND (subject LIKE '%invoice%' OR body LIKE '%pdf%');
-- Insider misuse
SELECT user, action, resource, time FROM file_access WHERE action = 'download' AND resource LIKE '%HR%';
-- Impossible travel
SELECT user, session_id, location, time FROM session_activity WHERE session_id IN (SELECT session_id FROM session_activity GROUP BY session_id HAVING COUNT(DISTINCT location) > 1 AND MAX(time) - MIN(time) < 600);
-- Severity matrix
SELECT scenario, COUNT(*) as incidents, MAX(risk_level) as max_risk FROM incidents GROUP BY scenario;
```

## Panel Types
- Table, Bar, Heatmap, and Matrix panels for each scenario.
- Timeline panel for injects and escalation tracking.

---

Add these queries/panels to your Grafana dashboard for full SOC coverage and training.
