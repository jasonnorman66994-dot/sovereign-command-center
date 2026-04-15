# Grafana Dashboard Auto-Refresh Setup

## 1. Set Auto-Refresh Interval
- In your Grafana dashboard, click the refresh icon (top right) or open dashboard settings.
- Set the auto-refresh interval to 1m, 5m, or custom (e.g., 30s) as needed.
- Example: Select "5m" for 5-minute refresh.

## 2. Panel-Level Refresh (Optional)
- For panels with heavy queries, set a longer refresh interval in panel settings.

## 3. Data Source Sync
- Ensure your log parsing/automation scripts update the underlying CSV/DB at least as often as the dashboard refresh.

---

# Automation Tip
- Use Windows Task Scheduler, cron, or a background service to run log parsing and import scripts on a schedule matching your dashboard refresh.

---

# Example: Task Scheduler (Windows)
- Create a task to run import_csv_to_sqlite.ps1 every 5 minutes.

# Example: Cron (Linux)
*/5 * * * * /usr/bin/python3 /path/to/parse_mail_log.py

---

With auto-refresh and scheduled parsing, your dashboards will always show near real-time data.
