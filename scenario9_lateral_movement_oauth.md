# Scenario 9 - Lateral Movement via Compromised OAuth App

## Overview

An attacker abuses a compromised OAuth application to escalate permissions, impersonate multiple users, and extract sensitive data across services. Persistence is achieved through long-lived refresh token issuance.

## Input Evidence Bundle

### 1. OAuth App Modification

```text
Apr 14 16:12:10 idp[4411]: APP PERMISSION CHANGE app="AnalyticsSync" scopes_added="Directory.ReadWrite.All"
Apr 14 16:12:11 idp[4411]: WARNING: Permission escalation requested by non-admin user=intern_mike@example.com
```

### 2. Token Activity Across Multiple Users

```text
Apr 14 16:14:55 graphapi[8821]: ACCESS TOKEN USED app="AnalyticsSync" user=hr_manager@example.com action="read_directory" ip=185.199.220.14
Apr 14 16:14:56 graphapi[8821]: ACCESS TOKEN USED app="AnalyticsSync" user=finance_lead@example.com action="read_mail" ip=185.199.220.14
Apr 14 16:14:57 graphapi[8821]: ACCESS TOKEN USED app="AnalyticsSync" user=dev_lead@example.com action="list_repos" ip=185.199.220.14
```

### 3. Lateral Movement Behavior

```text
Apr 14 16:15:20 graphapi[8821]: API CALL app="AnalyticsSync" action="download_repo" repo="payments-service" size=2.1GB
Apr 14 16:15:21 graphapi[8821]: API CALL app="AnalyticsSync" action="export_mailbox" user=finance_lead@example.com size=480MB
```

### 4. Persistence Mechanism

```text
Apr 14 16:16:10 idp[4411]: REFRESH TOKEN ISSUED app="AnalyticsSync" lifetime="90 days" user=hr_manager@example.com
```

### 5. UEBA Output

```text
Apr 14 16:16:30 ueba[9911]: anomaly_score=9.8 entity="AnalyticsSync" reason="permission escalation + multi-user impersonation + large data exports"
```

## Key Detection Signals

- Detect OAuth app permission escalation
- Detect non-admin permission change
- Detect app impersonating multiple users
- Detect large repo or mailbox exports
- Detect a single attacker IP
- Detect long-lived refresh tokens
- Detect high UEBA anomaly scores

## Expected Classification

Lateral Movement via Compromised OAuth App

## SOC Actions

- Disable the OAuth app
- Revoke all tokens issued to the app
- Block the attacker IP
- Audit app permission history
- Investigate the initial compromise
- Rotate accessed secrets

## Example SQL for Dashboard/Detection

```sql
-- App permission escalation
SELECT * FROM idp WHERE event LIKE '%APP PERMISSION CHANGE%' AND scopes_added LIKE '%Directory.ReadWrite.All%';
-- Non-admin permission change
SELECT * FROM idp WHERE event LIKE '%Permission escalation%' AND user NOT IN (SELECT admin_users FROM directory);
-- App impersonating multiple users
SELECT app, COUNT(DISTINCT user) as users FROM graphapi WHERE app='AnalyticsSync' GROUP BY app HAVING users > 1;
-- Large repo/mailbox exports
SELECT * FROM graphapi WHERE action IN ('download_repo', 'export_mailbox') AND size > 100;
-- Single attacker IP
SELECT ip, COUNT(*) as events FROM graphapi WHERE app='AnalyticsSync' GROUP BY ip HAVING events > 2;
-- Long-lived refresh token
SELECT * FROM idp WHERE event LIKE '%REFRESH TOKEN ISSUED%' AND lifetime > 30;
-- High UEBA anomaly
SELECT * FROM ueba WHERE anomaly_score > 9.0;
```

## Training Drill

1. Review `idp`, `graphapi`, and `ueba` logs for app escalation and lateral movement.
2. Use dashboard panels to visualize.
3. Practice SOC response steps as above.

## Timeline

| Time  | Event |
|-------|-------|
| 16:12 | OAuth app gains elevated directory-write permission via suspicious change |
| 16:14 | Access tokens are used across multiple user contexts from one attacker IP |
| 16:15 | High-volume repository and mailbox exports begin |
| 16:16 | Long-lived refresh token is issued and UEBA score spikes |

## Analyst Guidance

Treat this as app-identity compromise with cross-tenant blast-radius potential. Focus on app disablement, token revocation, and retrospective audit of all operations executed under app grants.
