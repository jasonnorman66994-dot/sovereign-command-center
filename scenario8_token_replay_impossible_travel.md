# Scenario 8 - Impossible Travel and Token Replay Attack

## Input Evidence Bundle

### 1. Legitimate User Session

```text
Apr 14 08:01:12 authz[5511]: LOGIN SUCCESS user=dev_lead@example.com ip=104.28.55.12 location="New York, USA" device="MacOS-Chrome" token_id="TKN-8841"
Apr 14 08:01:13 authz[5511]: SESSION START user=dev_lead@example.com token_id="TKN-8841"
```

### 2. Suspicious Second Session (Impossible Travel)

```text
Apr 14 08:03:44 authz[5511]: LOGIN SUCCESS user=dev_lead@example.com ip=203.55.19.88 location="Sydney, Australia" device="Linux-Firefox" token_id="TKN-8841"
Apr 14 08:03:45 authz[5511]: WARNING: Token replay detected for token_id="TKN-8841"
```

### 3. Session Behavior

```text
Apr 14 08:04:10 graphapi[8821]: API CALL user=dev_lead@example.com token_id="TKN-8841" action="download_repo" repo="core-platform" size=1.2GB
Apr 14 08:04:11 graphapi[8821]: API CALL user=dev_lead@example.com token_id="TKN-8841" action="list_secrets" project="payments-service"
```

### 4. UEBA Output

```text
Apr 14 08:04:30 ueba[9911]: anomaly_score=9.9 user=dev_lead@example.com reason="impossible travel + token replay + sensitive repo access"
```

## Detection Logic (for SOC Automation)

- Detect the same token used from distant locations within minutes
- Detect token replay warnings
- Detect device fingerprint mismatch
- Detect sensitive repo access and secrets enumeration
- Detect high UEBA anomaly scores

## Expected Classification

Token Replay and Impossible Travel

## SOC Actions

- Revoke all sessions for the user
- Invalidate `token_id` `TKN-8841`
- Force MFA re-enrollment
- Block the suspicious IP in Sydney
- Review repo download logs
- Rotate secrets accessed by the attacker

## Example SQL for Dashboard/Detection

```sql
-- Same token from two locations
SELECT user, token_id, COUNT(DISTINCT location) as locs, MAX(time)-MIN(time) as delta FROM authz WHERE token_id='TKN-8841' GROUP BY user, token_id HAVING locs > 1 AND delta < 600;
-- Token replay warning
SELECT * FROM authz WHERE event LIKE '%Token replay detected%';
-- Sensitive repo access
SELECT * FROM graphapi WHERE action='download_repo' OR action='list_secrets';
-- High UEBA anomaly
SELECT * FROM ueba WHERE anomaly_score > 9.0;
```

## Training Drill

1. Review `authz`, `graphapi`, and `ueba` logs for impossible travel and token replay.
2. Use dashboard panels to visualize.
3. Practice SOC response steps as above.
