#!/usr/bin/env bash
set -u

LOGFILE="${LOGFILE:-/var/log/cve43887-heartbeat.log}"
REPORT_DIR="${REPORT_DIR:-/var/reports/cve43887}"

log() {
  printf "%s %s\n" "$(date "+%Y-%m-%d %H:%M:%S")" "$1" >> "$LOGFILE" 2>/dev/null || true
}

# Ensure log path is writable; fallback to /tmp if needed.
LOG_DIR="$(dirname "$LOGFILE")"
if ! mkdir -p "$LOG_DIR" 2>/dev/null || ! touch "$LOGFILE" 2>/dev/null; then
  LOGFILE="/tmp/cve43887-heartbeat.log"
  mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null || true
  touch "$LOGFILE" 2>/dev/null || true
fi

log "=== Heartbeat Check Run ==="

# 1) Cron service (support cron and crond)
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet cron || systemctl is-active --quiet crond; then
    log "[PASS] cron service running"
  else
    log "[FAIL] cron service not running"
  fi
else
  log "[WARN] systemctl unavailable; cron check skipped"
fi

# 2) Report directory writable
if [ -d "$REPORT_DIR" ] && [ -w "$REPORT_DIR" ]; then
  log "[PASS] ${REPORT_DIR} writable"
else
  log "[FAIL] report directory missing or not writable: ${REPORT_DIR}"
fi

# 3) Core logs presence
for path in /var/log/cve-43887-check.log /var/log/cve-43887-api.log /var/log/cve-43887-reporting.log; do
  if [ -f "$path" ]; then
    log "[PASS] ${path} exists"
  else
    log "[FAIL] ${path} missing"
  fi
done

log "=== Heartbeat Check Complete ==="
exit 0
