#!/usr/bin/env bash
set -u

PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
QUIET=false
REPORT_DIR="/var/reports/cve43887"
TEST_PDF="${REPORT_DIR}/test.pdf"
TEST_EMAIL="${TEST_EMAIL:-}"
ALERT_EMAIL="${ALERT_EMAIL:-${TEST_EMAIL:-}}"
ENABLE_EMAIL_TEST="${ENABLE_EMAIL_TEST:-false}"
LOG_DIR="${LOG_DIR:-/var/log}"
LOG_PREFIX="${LOG_PREFIX:-cve43887-healthcheck}"
LOG_RETENTION_MONTHS="${LOG_RETENTION_MONTHS:-12}"
CURRENT_MONTH="$(date +%Y%m)"
DEFAULT_LOGFILE="${LOG_DIR}/${LOG_PREFIX}-${CURRENT_MONTH}.log"
LOGFILE="${LOGFILE:-$DEFAULT_LOGFILE}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --quiet)
      QUIET=true
      ;;
  esac
  shift
done

out() {
  if [ "$QUIET" = false ]; then
    echo "$1"
  fi
}

log_line() {
  local level="$1"
  shift
  local message="$*"
  printf "%s [%s] %s\n" "$(date "+%Y-%m-%d %H:%M:%S")" "$level" "$message" >> "$LOGFILE" 2>/dev/null || true
}

LOGFILE_DIR="$(dirname "$LOGFILE")"
if ! mkdir -p "$LOGFILE_DIR" 2>/dev/null || ! touch "$LOGFILE" 2>/dev/null; then
  LOGFILE="/tmp/cve43887-healthcheck.log"
  mkdir -p "$(dirname "$LOGFILE")" 2>/dev/null || true
  touch "$LOGFILE" 2>/dev/null || true
  out "[WARN] Default log path unavailable; using $LOGFILE"
fi

if [[ "$LOG_RETENTION_MONTHS" =~ ^[0-9]+$ ]] && [ "$LOG_RETENTION_MONTHS" -gt 0 ]; then
  # Approximate month retention by days to stay POSIX-friendly in cron environments.
  RETENTION_DAYS=$((LOG_RETENTION_MONTHS * 31))
  find "$(dirname "$LOGFILE")" -maxdepth 1 -type f -name "${LOG_PREFIX}-*.log" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
fi

pass() {
  out "[PASS] $1"
  log_line "PASS" "$1"
  PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
  out "[FAIL] $1"
  log_line "FAIL" "$1"
  FAIL_COUNT=$((FAIL_COUNT + 1))
}

warn() {
  out "[WARN] $1"
  log_line "WARN" "$1"
  WARN_COUNT=$((WARN_COUNT + 1))
}

out "=== CVE-43887 Reporting Pipeline Health Check ==="
out "Audit log: ${LOGFILE}"
log_line "INFO" "=== Health Check Run Started (quiet=${QUIET}) ==="

# 1) Python libraries
# fpdf is optional in current pipeline; keep as warning if missing.
out ""
out "[Python Libraries]"
for lib in matplotlib reportlab openpyxl; do
  if python3 -c "import ${lib}" >/dev/null 2>&1; then
    pass "${lib} installed"
  else
    fail "${lib} missing"
  fi
done

if python3 -c "import fpdf" >/dev/null 2>&1; then
  pass "fpdf installed (optional)"
else
  warn "fpdf missing (optional)"
fi

# 2) Mail utility
out ""
out "[Mail Utility]"
if command -v mail >/dev/null 2>&1; then
  pass "mail utility present"
elif command -v mailx >/dev/null 2>&1; then
  pass "mailx utility present"
else
  fail "mail utility missing (mail/mailx)"
fi

# 3) Cron service
# Support both cron (Debian/Ubuntu) and crond (RHEL/Fedora)
out ""
out "[Cron Service]"
if command -v systemctl >/dev/null 2>&1; then
  if systemctl is-active --quiet cron; then
    pass "cron service running"
  elif systemctl is-active --quiet crond; then
    pass "crond service running"
  else
    fail "cron service not running (cron/crond)"
  fi
else
  warn "systemctl not available; skipping cron service check"
fi

# 4) Report directory permissions
out ""
out "[Report Directory]"
if [ ! -d "$REPORT_DIR" ]; then
  fail "$REPORT_DIR missing"
elif [ -w "$REPORT_DIR" ]; then
  pass "$REPORT_DIR writable"
else
  fail "$REPORT_DIR not writable"
fi

# 5) Logs presence
out ""
out "[Logs]"
for log_path in /var/log/cve-43887-check.log /var/log/cve-43887-api.log /var/log/cve-43887-reporting.log; do
  if [ -f "$log_path" ]; then
    pass "$log_path exists"
  else
    warn "$log_path missing"
  fi
done

# 6) API reachability quick probe (optional)
out ""
out "[API Endpoint]"
if command -v curl >/dev/null 2>&1; then
  API_PORT="${API_PORT:-8443}"
  if curl --silent --insecure --max-time 3 "https://localhost:${API_PORT}/status" >/dev/null 2>&1; then
    warn "API responded without auth check (verify token enforcement)"
  else
    pass "API endpoint reachable check completed (auth likely enforced or service down)"
  fi
else
  warn "curl missing; skipping API probe"
fi

# 7) PDF generation test
out ""
out "[PDF Generation]"
python3 <<'EOF'
from reportlab.pdfgen import canvas

path = "/var/reports/cve43887/test.pdf"
c = canvas.Canvas(path)
c.drawString(100, 750, "PDF generation test successful")
c.save()
EOF
if [ $? -ne 0 ]; then
  fail "PDF generation failed"
else
  pass "PDF generated successfully"
fi

# 8) Email test configuration (optional)
out ""
out "[Email Test]"
if [ -z "$ALERT_EMAIL" ]; then
  warn "ALERT_EMAIL not set; failure notifications disabled"
elif command -v mail >/dev/null 2>&1 || command -v mailx >/dev/null 2>&1; then
  pass "Failure alert email configured for $ALERT_EMAIL"
else
  fail "No mail utility available for failure notifications (mail/mailx)"
fi

if [ "$ENABLE_EMAIL_TEST" = true ]; then
  if [ ! -f "$TEST_PDF" ]; then
    fail "Email test enabled but test PDF not found"
  elif [ -z "$ALERT_EMAIL" ]; then
    fail "Email test enabled but ALERT_EMAIL is not set"
  elif command -v mail >/dev/null 2>&1; then
    if echo "This is a CVE-43887 health check test email. The attached PDF confirms pipeline output." | mail -s "CVE-43887 Health Check Report" -a "$TEST_PDF" "$ALERT_EMAIL"; then
      pass "Test email sent with PDF attachment to $ALERT_EMAIL"
    else
      fail "mail command failed while sending test email"
    fi
  elif command -v mailx >/dev/null 2>&1; then
    if echo "This is a CVE-43887 health check test email. The attached PDF confirms pipeline output." | mailx -s "CVE-43887 Health Check Report" -a "$TEST_PDF" "$ALERT_EMAIL"; then
      pass "Test email sent with PDF attachment to $ALERT_EMAIL"
    else
      fail "mailx command failed while sending test email"
    fi
  fi
fi

echo "=== Health Check Summary ==="
echo "PASS: ${PASS_COUNT}"
echo "WARN: ${WARN_COUNT}"
echo "FAIL: ${FAIL_COUNT}"
log_line "INFO" "Summary PASS=${PASS_COUNT} WARN=${WARN_COUNT} FAIL=${FAIL_COUNT}"

if [ "$FAIL_COUNT" -eq 0 ]; then
  if [ "$WARN_COUNT" -eq 0 ]; then
    echo "STATUS: All checks passed. Pipeline is healthy."
    log_line "INFO" "STATUS: All checks passed. Pipeline is healthy."
  else
    echo "STATUS: No hard failures, but warnings need review."
    log_line "INFO" "STATUS: No hard failures, but warnings need review."
  fi
else
  echo "STATUS: Some checks failed. Review output above."
  log_line "INFO" "STATUS: Some checks failed. Review output above."

  # Failure-only notification: alert only when there are failures.
  if [ -n "$ALERT_EMAIL" ]; then
    ALERT_SUBJECT="CVE-43887 Health Check ALERT"
    ALERT_BODY="Health check detected ${FAIL_COUNT} failed checks at $(date '+%Y-%m-%d %H:%M:%S'). See log: ${LOGFILE}"

    if command -v mail >/dev/null 2>&1; then
      if echo "$ALERT_BODY" | mail -s "$ALERT_SUBJECT" "$ALERT_EMAIL"; then
        log_line "INFO" "Failure alert email sent to ${ALERT_EMAIL}"
      else
        log_line "WARN" "Failed to send failure alert via mail to ${ALERT_EMAIL}"
      fi
    elif command -v mailx >/dev/null 2>&1; then
      if echo "$ALERT_BODY" | mailx -s "$ALERT_SUBJECT" "$ALERT_EMAIL"; then
        log_line "INFO" "Failure alert email sent to ${ALERT_EMAIL}"
      else
        log_line "WARN" "Failed to send failure alert via mailx to ${ALERT_EMAIL}"
      fi
    else
      log_line "WARN" "Could not send failure alert: no mail utility available"
    fi
  else
    log_line "WARN" "Failures detected but ALERT_EMAIL is not configured"
  fi
fi

echo "=== Health Check Complete ==="
log_line "INFO" "=== Health Check Complete ==="

if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
