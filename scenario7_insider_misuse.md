# Scenario 7 - Insider Misuse: Privilege Creep and Data Exfiltration

## Input Evidence Bundle

### 1. Privilege Escalation Events

```text
Apr 14 13:22:10 idp[4411]: ROLE CHANGE user=analyst_john@example.com old_role="Support Analyst" new_role="Data Engineer"
Apr 14 13:22:11 idp[4411]: WARNING: Role change not approved by manager
```

### 2. Access to Sensitive Files

```text
Apr 14 13:25:44 fileserver[7712]: FILE ACCESS user=analyst_john@example.com path="/finance/payroll/2024/Q1_salaries.xlsx" action=read
Apr 14 13:25:45 fileserver[7712]: FILE ACCESS user=analyst_john@example.com path="/finance/vendor_contracts/master_list.pdf" action=read
```

### 3. Data Aggregation Behavior

```text
Apr 14 13:26:10 fileserver[7712]: ZIP CREATED user=analyst_john@example.com path="/home/john/export_bundle.zip" contents=42 files
```

### 4. Exfiltration Attempt

```text
Apr 14 13:27:55 proxy[8821]: UPLOAD user=analyst_john@example.com dest="https://personal-dropbox.com/upload" size=184MB
Apr 14 13:27:56 proxy[8821]: CATEGORY=Personal Storage flagged=High-Risk
```

### 5. Behavioral Baseline Deviation

```text
Apr 14 13:28:10 ueba[9911]: anomaly_score=9.7 user=analyst_john@example.com reason="Accessing finance data; privilege escalation; large upload"
```

## Detection Logic (for SOC Automation)

- Detect unauthorized role changes
- Detect access to sensitive finance files
- Detect ZIP file creation for aggregation
- Detect large uploads to personal cloud
- Detect high UEBA anomaly scores

## Expected Classification

Insider Misuse - Privilege Creep and Data Exfiltration

## SOC Actions

- Disable the user account
- Block outbound uploads
- Notify HR and security leadership
- Review role change logs
- Analyze ZIP contents
- Revert unauthorized privileges

## Example SQL for Dashboard/Detection

```sql
-- Unauthorized role changes
SELECT * FROM idp WHERE event LIKE '%ROLE CHANGE%' AND new_role NOT IN (SELECT approved_roles FROM hr_approvals);
-- Sensitive file access
SELECT * FROM fileserver WHERE path LIKE '/finance/%' AND action='read';
-- ZIP file creation
SELECT * FROM fileserver WHERE event LIKE '%ZIP CREATED%';
-- Large uploads to personal cloud
SELECT * FROM proxy WHERE dest LIKE '%dropbox%' AND size > 100000000;
-- High UEBA anomaly
SELECT * FROM ueba WHERE anomaly_score > 9.0;
```

## Training Drill

1. Review `idp`, `fileserver`, `proxy`, and `ueba` logs for privilege creep and exfiltration.
2. Use dashboard panels to visualize.
3. Practice SOC response steps as above.
