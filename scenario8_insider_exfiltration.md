# Scenario 8 - Insider Data Exfiltration

## Overview

An insider account accesses sensitive datasets and attempts external transfer, with supporting DLP and HR-system corroboration. Detection confidence increases through file, transfer, and behavior telemetry correlation.

## Input Evidence Bundle

### 1. File Server Logs

```text
Apr 14 17:10:10 fileserver[5555]: DOWNLOAD user=it_admin@example.com file="customer_db_backup.sql"
Apr 14 17:10:12 fileserver[5555]: DOWNLOAD user=it_admin@example.com file="employee_records.xlsx"
Apr 14 17:10:15 fileserver[5555]: UPLOAD user=it_admin@example.com file="customer_db_backup.sql" dest="external_sftp://10.10.10.10"
```

### 2. DLP (Data Loss Prevention) Alerts

```text
Apr 14 17:10:20 dlp[7777]: ALERT: Large file transfer detected user=it_admin@example.com file="customer_db_backup.sql"
```

### 3. HR System Logs

```text
Apr 14 17:10:30 hr_system[8888]: ACCESS user=it_admin@example.com resource="employee_records"
```

## Key Detection Signals

- Detect mass downloads of sensitive files
- Detect uploads to external destinations
- Correlate DLP alerts with file server activity
- Detect access to HR data by non-HR users

## Expected Classification

Insider Data Exfiltration

## SOC Actions

- Disable the user account
- Block external transfers
- Notify HR and leadership
- Review all recent file access by the user
- Add indicators to SIEM

## Example SQL for Dashboard/Detection

```sql
-- Mass downloads
SELECT user, COUNT(*) as downloads FROM fileserver WHERE action='DOWNLOAD' AND time > datetime('now', '-1 hour') GROUP BY user HAVING downloads > 10;
-- Uploads to external
SELECT * FROM fileserver WHERE action='UPLOAD' AND dest LIKE 'external_sftp%';
-- DLP alerts
SELECT * FROM dlp WHERE alert LIKE '%Large file transfer%';
-- HR access by non-HR
SELECT * FROM hr_system WHERE user NOT LIKE '%hr%' AND resource LIKE '%employee_records%';
```

## Training Drill

1. Review `fileserver`, `dlp`, and `hr_system` logs for exfiltration patterns.
2. Use dashboard panels to visualize.
3. Practice SOC response steps as above.

## Timeline

| Time  | Event |
|-------|-------|
| 17:10 | Sensitive backup and HR-related files are downloaded |
| 17:10 | External SFTP upload of database backup is initiated |
| 17:10 | DLP flags large transfer from insider account |
| 17:10 | HR resource access confirms broader sensitive-data touchpoint |

## Analyst Guidance

Treat this as potential high-impact insider theft. Preserve transfer evidence, isolate account activity, and coordinate HR/security response while validating full data exposure scope.
