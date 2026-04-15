# Grafana Data Source Setup for CSV/SQL

## 1. Using CSV Plugin (Recommended for Quick Start)
- Install the "CSV" data source plugin in Grafana (Grafana.com > Plugins > CSV).
- Place your CSV files (mail_activity.csv, login_attempts.csv, login_events.csv) in a directory accessible by the Grafana server.
- In Grafana:
  1. Go to Configuration > Data Sources > Add data source > CSV.
  2. Set the path to your CSV files.
  3. Configure field mapping (timestamp, user, sender, status, etc.).
  4. Test the data source.

## 2. Using SQL Database (For Automation/Scaling)
- Import your CSVs into a database (e.g., SQLite, MySQL, PostgreSQL).
- Example (SQLite):
  ```sh
  sqlite3 email_security.db
  .mode csv
  .import mail_activity.csv mail_activity
  .import login_attempts.csv login_attempts
  .import login_events.csv login_events
  ```
- In Grafana:
  1. Add a new data source (e.g., SQLite, MySQL, PostgreSQL).
  2. Point to your database.
  3. Use SQL queries in dashboard panels.

## 3. Automation Script: Import CSVs to SQLite
- See import_csv_to_sqlite.ps1 for a PowerShell script to automate CSV import.

---

# Further Automation
- Schedule the import script to run after new logs are parsed.
- Use Grafana's auto-refresh to update dashboards every 5 minutes.
- For advanced automation, integrate log parsing scripts to output directly to the database.

---

# Security Note
- Restrict access to sensitive CSVs and databases.
- Use least-privilege for Grafana data source credentials.
