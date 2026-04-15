#!/usr/bin/env bash
set -euo pipefail

EXPORT_DIR="${EXPORT_DIR:-/var/reports/cve43887}"
EXPORT_EMAIL="${EXPORT_EMAIL:-}"
SHARED_DIR="${SHARED_DIR:-}"
API_PORT="${API_PORT:-8443}"
API_TOKEN_ADMIN="${API_TOKEN_ADMIN:-}"
CHECK_LOG_DIR="${CHECK_LOG_DIR:-/var/log}"
CHECK_LOG_CURRENT="${CHECK_LOG_CURRENT:-$CHECK_LOG_DIR/cve-43887-check.log}"
CHECK_LOG_ARCHIVE_GLOB="${CHECK_LOG_ARCHIVE_GLOB:-$CHECK_LOG_DIR/cve-43887-check-*.log}"
API_AUDIT_LOG="${API_AUDIT_LOG:-$CHECK_LOG_DIR/cve-43887-api.log}"
MONTHLY_SUMMARY=false
EXPORT_BASENAME="audit-$(date +%Y%m%d).zip"
SUMMARY_BASENAME="summary-$(date +%Y%m).txt"
CHART_BASENAME="alerts-trend-$(date +%Y%m).png"
REPORT_AUDIT_LOG="${REPORT_AUDIT_LOG:-/var/log/cve-43887-reporting.log}"
REPORT_AUDIT_TAIL=""

SCRIPT_NAME="$(basename "$0")"

log_report_event() {
  local event="$1"
  local status="$2"
  local details="${3:-none}"
  local ts
  ts="$(date -Iseconds)"
  printf '%s | script=%s | event=%s | status=%s | details=%s\n' "$ts" "$SCRIPT_NAME" "$event" "$status" "$details" >> "$REPORT_AUDIT_LOG" 2>/dev/null || true
}

trap 'log_report_event "run" "failed" "line=${LINENO}"' ERR

while [ "$#" -gt 0 ]; do
  case "$1" in
    --monthly-summary)
      MONTHLY_SUMMARY=true
      shift
      ;;
    --report-audit-tail)
      REPORT_AUDIT_TAIL="${2:-50}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [ -n "$REPORT_AUDIT_TAIL" ]; then
  if ! [[ "$REPORT_AUDIT_TAIL" =~ ^[0-9]+$ ]]; then
    echo "Invalid --report-audit-tail value: $REPORT_AUDIT_TAIL" >&2
    exit 1
  fi

  if [ -f "$REPORT_AUDIT_LOG" ]; then
    tail -n "$REPORT_AUDIT_TAIL" "$REPORT_AUDIT_LOG"
  else
    echo "No reporting audit log found at $REPORT_AUDIT_LOG"
  fi
  log_report_event "audit_tail" "success" "lines=${REPORT_AUDIT_TAIL}"
  exit 0
fi

current_month_prefix() {
  date +%Y%m
}

collect_monthly_check_logs() {
  local month_prefix
  month_prefix="$(current_month_prefix)"

  for path in $CHECK_LOG_ARCHIVE_GLOB; do
    [ -f "$path" ] || continue
    case "$path" in
      *"$month_prefix"*.log)
        printf '%s\n' "$path"
        ;;
    esac
  done

  if [ -f "$CHECK_LOG_CURRENT" ]; then
    printf '%s\n' "$CHECK_LOG_CURRENT"
  fi
}

count_pattern_in_files() {
  local pattern="$1"
  shift
  if [ "$#" -eq 0 ]; then
    printf '0\n'
    return
  fi

  grep -h -c -- "$pattern" "$@" 2>/dev/null | awk '{sum += $1} END {print sum + 0}'
}

count_api_audit_pattern() {
  local pattern="$1"
  local month_prefix
  month_prefix="$(date +%Y-%m)"

  if [ ! -f "$API_AUDIT_LOG" ]; then
    printf '0\n'
    return
  fi

  grep -c -- "^$month_prefix.*$pattern" "$API_AUDIT_LOG" 2>/dev/null || true
}

build_monthly_summary() {
  local summary_path="$1"
  local -a monthly_logs=()
  local email_alerts
  local kernel_events
  local api_calls
  local read_calls
  local admin_calls
  local unauthorized_calls

  while IFS= read -r path; do
    [ -n "$path" ] && monthly_logs+=("$path")
  done < <(collect_monthly_check_logs)

  email_alerts="$(count_pattern_in_files "Email alert sent:" "${monthly_logs[@]}")"
  kernel_events="$(count_pattern_in_files "Safe likely:\|Vulnerable range:\|Unknown range:" "${monthly_logs[@]}")"
  api_calls="$(count_api_audit_pattern 'role=')"
  read_calls="$(count_api_audit_pattern 'role=read')"
  admin_calls="$(count_api_audit_pattern 'role=admin')"
  unauthorized_calls="$(count_api_audit_pattern 'role=unauthorized')"

  {
    echo "=== Monthly CVE-2024-43887 Summary Report ==="
    echo "Date: $(date)"
    echo
    echo "Email Alerts Sent: $email_alerts"
    echo "Kernel Status Events Logged: $kernel_events"
    echo "API Accesses Logged: $api_calls"
    echo "Access Breakdown: Read=$read_calls, Admin=$admin_calls, Unauthorized=$unauthorized_calls"
    echo
    echo "Summary generated automatically by the CVE-2024-43887 monitoring pipeline."
  } > "$summary_path"
}

  build_monthly_chart() {
    local chart_path="$1"
    local -a monthly_logs=()

    while IFS= read -r path; do
    [ -n "$path" ] && monthly_logs+=("$path")
    done < <(collect_monthly_check_logs)

    if [ "${#monthly_logs[@]}" -eq 0 ]; then
    return 1
    fi

    CHART_OUTPUT="$chart_path" python3 - "${monthly_logs[@]}" <<'EOF'
  import collections
  import datetime
  import os
  import sys

  try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
  except ImportError:
    sys.exit(2)


  output_path = os.environ["CHART_OUTPUT"]
  log_paths = sys.argv[1:]
  alert_weeks = collections.Counter()
  kernel_weeks = collections.Counter()

  for log_path in log_paths:
    try:
      with open(log_path, "r", encoding="utf-8") as handle:
        for line in handle:
          timestamp = line.split(" | ", 1)[0].strip()
          try:
            dt = datetime.datetime.fromisoformat(timestamp)
          except ValueError:
            continue
          iso_year, iso_week, _ = dt.isocalendar()
          week_key = f"{iso_year}-W{iso_week:02d}"

          if "Email alert sent:" in line:
            alert_weeks[week_key] += 1

          if any(marker in line for marker in ("Safe likely:", "Vulnerable range:", "Unknown range:")):
            kernel_weeks[week_key] += 1
    except FileNotFoundError:
      continue

  labels = sorted(set(alert_weeks.keys()) | set(kernel_weeks.keys()))[-10:]
  alert_values = [alert_weeks[label] for label in labels]
  kernel_values = [kernel_weeks[label] for label in labels]

  if not labels:
    labels = ["No Data"]
    alert_values = [0]
    kernel_values = [0]

  plt.figure(figsize=(9, 4.5))
  plt.plot(labels, alert_values, marker="o", linewidth=2.2, color="#dc2626", label="Email Alerts")
  plt.plot(labels, kernel_values, marker="s", linewidth=2.2, color="#2563eb", label="Kernel Events")
  plt.title("CVE-2024-43887 Monthly Trend Analysis")
  plt.xlabel("Week")
  plt.ylabel("Count")
  plt.xticks(rotation=35, ha="right")
  plt.grid(True, linestyle="--", alpha=0.4)
  plt.legend()
  plt.tight_layout()

  plt.savefig(output_path, dpi=150)
  EOF
  }

if [ -z "$API_TOKEN_ADMIN" ]; then
  echo "API_TOKEN_ADMIN must be set for weekly exports." >&2
  log_report_event "validation" "failed" "API_TOKEN_ADMIN missing"
  exit 1
fi

mkdir -p "$EXPORT_DIR"
log_report_event "run" "started" "mode=$( [ "$MONTHLY_SUMMARY" = true ] && printf monthly || printf weekly )"

OUTPUT_PATH="$EXPORT_DIR/$EXPORT_BASENAME"
curl --fail --silent --show-error --insecure \
  -H "Authorization: Bearer $API_TOKEN_ADMIN" \
  "https://localhost:${API_PORT}/download/audit.zip" \
  -o "$OUTPUT_PATH"
log_report_event "zip_export" "success" "path=${OUTPUT_PATH}"

SUMMARY_PATH="$EXPORT_DIR/$SUMMARY_BASENAME"
CHART_PATH="$EXPORT_DIR/$CHART_BASENAME"
if [ "$MONTHLY_SUMMARY" = true ]; then
  build_monthly_summary "$SUMMARY_PATH"
  log_report_event "summary_generation" "success" "path=${SUMMARY_PATH}"
  if ! build_monthly_chart "$CHART_PATH"; then
    echo "Monthly trend chart could not be generated (matplotlib may be unavailable or no logs were found)." >> "$SUMMARY_PATH"
    rm -f "$CHART_PATH"
    log_report_event "chart_generation" "failed" "matplotlib unavailable or insufficient data"
  else
    log_report_event "chart_generation" "success" "path=${CHART_PATH}"
  fi
fi

if [ -n "$SHARED_DIR" ]; then
  mkdir -p "$SHARED_DIR"
  cp "$OUTPUT_PATH" "$SHARED_DIR/$EXPORT_BASENAME"
  log_report_event "shared_copy" "success" "path=$SHARED_DIR/$EXPORT_BASENAME"
  if [ "$MONTHLY_SUMMARY" = true ]; then
    cp "$SUMMARY_PATH" "$SHARED_DIR/$SUMMARY_BASENAME"
    log_report_event "shared_copy" "success" "path=$SHARED_DIR/$SUMMARY_BASENAME"
    if [ -f "$CHART_PATH" ]; then
      cp "$CHART_PATH" "$SHARED_DIR/$CHART_BASENAME"
      log_report_event "shared_copy" "success" "path=$SHARED_DIR/$CHART_BASENAME"
    fi
  fi
fi

if [ -n "$EXPORT_EMAIL" ]; then
  if command -v mail >/dev/null 2>&1; then
    if [ "$MONTHLY_SUMMARY" = true ]; then
      if [ -f "$CHART_PATH" ]; then
        if echo "Attached: monthly audit export, executive summary, and trend chart." | mail -s "Monthly CVE-2024-43887 Report" -a "$OUTPUT_PATH" -a "$SUMMARY_PATH" -a "$CHART_PATH" "$EXPORT_EMAIL"; then
          log_report_event "email_delivery" "success" "target=${EXPORT_EMAIL}"
        else
          log_report_event "email_delivery" "failed" "target=${EXPORT_EMAIL}"
        fi
      else
        if echo "Attached: monthly audit export and executive summary." | mail -s "Monthly CVE-2024-43887 Report" -a "$OUTPUT_PATH" -a "$SUMMARY_PATH" "$EXPORT_EMAIL"; then
          log_report_event "email_delivery" "success" "target=${EXPORT_EMAIL}"
        else
          log_report_event "email_delivery" "failed" "target=${EXPORT_EMAIL}"
        fi
      fi
    else
      if echo "Weekly CVE-2024-43887 audit export attached." | mail -s "Weekly Audit Export" -a "$OUTPUT_PATH" "$EXPORT_EMAIL"; then
        log_report_event "email_delivery" "success" "target=${EXPORT_EMAIL}"
      else
        log_report_event "email_delivery" "failed" "target=${EXPORT_EMAIL}"
      fi
    fi
  elif command -v mailx >/dev/null 2>&1; then
    if [ "$MONTHLY_SUMMARY" = true ]; then
      if [ -f "$CHART_PATH" ]; then
        if echo "Attached: monthly audit export, executive summary, and trend chart." | mailx -s "Monthly CVE-2024-43887 Report" -a "$OUTPUT_PATH" -a "$SUMMARY_PATH" -a "$CHART_PATH" "$EXPORT_EMAIL"; then
          log_report_event "email_delivery" "success" "target=${EXPORT_EMAIL}"
        else
          log_report_event "email_delivery" "failed" "target=${EXPORT_EMAIL}"
        fi
      else
        if echo "Attached: monthly audit export and executive summary." | mailx -s "Monthly CVE-2024-43887 Report" -a "$OUTPUT_PATH" -a "$SUMMARY_PATH" "$EXPORT_EMAIL"; then
          log_report_event "email_delivery" "success" "target=${EXPORT_EMAIL}"
        else
          log_report_event "email_delivery" "failed" "target=${EXPORT_EMAIL}"
        fi
      fi
    else
      if echo "Weekly CVE-2024-43887 audit export attached." | mailx -s "Weekly Audit Export" -a "$OUTPUT_PATH" "$EXPORT_EMAIL"; then
        log_report_event "email_delivery" "success" "target=${EXPORT_EMAIL}"
      else
        log_report_event "email_delivery" "failed" "target=${EXPORT_EMAIL}"
      fi
    fi
  else
    echo "No mail client found; export retained at $OUTPUT_PATH" >&2
    log_report_event "email_delivery" "skipped" "mail client unavailable"
  fi
fi

echo "Export created at $OUTPUT_PATH"
if [ "$MONTHLY_SUMMARY" = true ]; then
  echo "Monthly summary created at $SUMMARY_PATH"
  if [ -f "$CHART_PATH" ]; then
    echo "Monthly trend chart created at $CHART_PATH"
  fi
fi
log_report_event "run" "completed" "mode=$( [ "$MONTHLY_SUMMARY" = true ] && printf monthly || printf weekly )"