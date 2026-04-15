# Scenario 7 - Impossible Travel and Token Replay

## Overview

An attacker reuses a valid token in a second geography within minutes of a legitimate login, producing impossible-travel and token-replay indicators. This pattern strongly suggests credential or session theft.

## Input Evidence Bundle

### 1. Identity Provider Logs

```text
Apr 14 14:01:10 idp[4411]: LOGIN SUCCESS user=exec@example.com location="NY" token=TK-123
Apr 14 14:03:05 idp[4411]: LOGIN SUCCESS user=exec@example.com location="Singapore" token=TK-123
```

### 2. Session Analysis

```text
Apr 14 14:03:10 session_analyzer[9001]: anomaly: impossible travel detected for user=exec@example.com token=TK-123
Apr 14 14:03:12 session_analyzer[9001]: anomaly: token replay suspected
```

## Key Detection Signals

- Detect logins for the same user and token from distant locations within a short time window
- Detect `session_analyzer` anomalies for impossible travel or token replay

## Expected Classification

Impossible Travel and Token Replay Attack

## SOC Actions

- Invalidate all sessions for the affected user
- Force password reset and MFA re-enrollment
- Investigate for credential theft or session hijack
- Add indicators to SIEM
- Notify the user and leadership

## Example SQL for Dashboard/Detection

```sql
-- Impossible travel
SELECT user, token, MIN(location) as first_loc, MAX(location) as second_loc, MAX(time)-MIN(time) as delta FROM idp_logs WHERE user='exec@example.com' AND token='TK-123' GROUP BY user, token HAVING delta < 600 AND first_loc != second_loc;
-- Token replay
SELECT * FROM session_analyzer WHERE anomaly LIKE '%token replay%';
```

## Training Drill

1. Review `idp_logs` and `session_analyzer` for anomalies.
2. Use dashboard panels to visualize.
3. Practice SOC response steps as above.

## Timeline

| Time  | Event |
|-------|-------|
| 14:01 | User login succeeds in New York with token `TK-123` |
| 14:03 | Same token appears from Singapore, triggering impossible-travel condition |
| 14:03 | Session analyzer flags likely token replay |

## Analyst Guidance

Treat same-token multi-region access inside a short window as high confidence compromise. Execute immediate session invalidation and identity hardening before deeper root-cause investigation.
