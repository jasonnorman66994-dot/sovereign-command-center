#!/usr/bin/env bash
set -u

LOG_DIR="${LOG_DIR:-/var/log}"
REPORT_DIR="${REPORT_DIR:-/var/reports}"
DASHBOARD_FILE="${DASHBOARD_FILE:-${REPORT_DIR}/cve43887-dashboard-summary.txt}"
HEARTBEAT_LOG="${HEARTBEAT_LOG:-${LOG_DIR}/cve43887-heartbeat.log}"
HEALTH_PREFIX="${HEALTH_PREFIX:-cve43887-healthcheck}"

mkdir -p "$(dirname "$DASHBOARD_FILE")" 2>/dev/null || true

timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
start_date="$(date -d '6 days ago' '+%Y-%m-%d' 2>/dev/null || date -v-6d '+%Y-%m-%d' 2>/dev/null || date '+%Y-%m-%d')"

latest_health_log=""
if ls "${LOG_DIR}/${HEALTH_PREFIX}"-*.log >/dev/null 2>&1; then
  latest_health_log="$(ls -1t "${LOG_DIR}/${HEALTH_PREFIX}"-*.log 2>/dev/null | head -n1)"
fi

{
  echo "=== CVE-43887 Weekly Dashboard Summary ==="
  echo "Generated: ${timestamp}"
  echo ""

  echo ">>> Heartbeat Checks (last 7 days)"
  if [ -f "$HEARTBEAT_LOG" ]; then
    awk -v start="$start_date" '$1 >= start {print}' "$HEARTBEAT_LOG"
  else
    echo "Heartbeat log not found: $HEARTBEAT_LOG"
  fi
  echo ""

  echo ">>> Full Health Check (last run)"
  if [ -n "$latest_health_log" ] && [ -f "$latest_health_log" ]; then
    echo "Source: $latest_health_log"
    tail -n 80 "$latest_health_log"
  else
    echo "No health-check monthly log found under ${LOG_DIR}/${HEALTH_PREFIX}-*.log"
  fi
  echo ""

  echo ">>> Summary Counts"

  heartbeat_pass=0
  heartbeat_fail=0
  health_pass=0
  health_fail=0

  if [ -f "$HEARTBEAT_LOG" ]; then
    heartbeat_pass="$(awk -v start="$start_date" '$1 >= start && /\[PASS\]/ {c++} END {print c+0}' "$HEARTBEAT_LOG")"
    heartbeat_fail="$(awk -v start="$start_date" '$1 >= start && /\[FAIL\]/ {c++} END {print c+0}' "$HEARTBEAT_LOG")"
  fi

  if [ -n "$latest_health_log" ] && [ -f "$latest_health_log" ]; then
    health_pass="$(grep -c '\[PASS\]' "$latest_health_log" 2>/dev/null || echo 0)"
    health_fail="$(grep -c '\[FAIL\]' "$latest_health_log" 2>/dev/null || echo 0)"
  fi

  echo "Heartbeat checks passed (last 7 days): ${heartbeat_pass}"
  echo "Heartbeat checks failed (last 7 days): ${heartbeat_fail}"
  echo "Health checks passed (latest monthly log): ${health_pass}"
  echo "Health checks failed (latest monthly log): ${health_fail}"
  echo ""

  echo "=== End of Dashboard Summary ==="
} > "$DASHBOARD_FILE"

echo "Dashboard summary written to: $DASHBOARD_FILE"
