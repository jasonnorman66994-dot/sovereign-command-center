# Grafana/Kibana/Excel Dashboard Template Instructions

## 1. Excel/Google Sheets
- Import mail_activity.csv and login_attempts.csv (from analyze_mail_log.py) or login_events.csv (from parse_windows_event_logs.ps1).
- Create:
  - Line/Bar Chart: Emails sent per sender per hour (mail_activity.csv)
  - Pie Chart: Top senders or attachments
  - Line/Bar Chart: Failed vs. successful logins per user/IP (login_attempts.csv or login_events.csv)
  - Heatmap: Activity by hour and sender

## 2. Grafana
- Data source: CSV plugin or import into a database (e.g., SQLite, MySQL, PostgreSQL)
- Example panels:
  - Time series: Emails sent per sender per hour
  - Table: Top senders, top attachments
  - Bar chart: Failed logins per user/IP
  - Heatmap: Login attempts by hour
- Use Grafana's panel editor to select fields and visualize trends.

## 3. Kibana
- Data source: Import CSVs into Elasticsearch (use Logstash or Kibana's CSV upload)
- Example visualizations:
  - Vertical bar: Emails per sender per hour
  - Pie: Top attachments
  - Line: Failed logins over time
  - Data table: Suspicious login attempts (filter by status)
- Build dashboards to monitor spikes, anomalies, and trends.

---

## Example: Excel Pivot Table for Login Events
1. Insert Pivot Table from login_events.csv
2. Rows: User, IP
3. Columns: Status (SUCCESS/FAILED)
4. Values: Count of events
5. Filter: TimeCreated (for time window)

---

## Example: Grafana Query (if using SQL DB)
```sql
SELECT Hour, Sender, SUM(Count) as TotalEmails
FROM mail_activity
GROUP BY Hour, Sender
ORDER BY Hour, TotalEmails DESC;
```

---

## Example: Kibana Query (KQL)
```
status : "FAILED" AND user : "finance_team@example.com"
```

---

Use these templates to quickly build dashboards for SOC monitoring, threat hunting, and incident response.
