#!/usr/bin/env bash
set -euo pipefail

EXPORT_DIR="${EXPORT_DIR:-/var/reports/cve43887}"
ARCHIVE_DIR="${ARCHIVE_DIR:-$EXPORT_DIR/archive}"
LEADERSHIP_EMAIL="${LEADERSHIP_EMAIL:-}"
CHECK_LOG_DIR="${CHECK_LOG_DIR:-/var/log}"
CHECK_LOG_CURRENT="${CHECK_LOG_CURRENT:-$CHECK_LOG_DIR/cve-43887-check.log}"
CHECK_LOG_ARCHIVE_GLOB="${CHECK_LOG_ARCHIVE_GLOB:-$CHECK_LOG_DIR/cve-43887-check-*.log}"
API_AUDIT_LOG="${API_AUDIT_LOG:-$CHECK_LOG_DIR/cve-43887-api.log}"
RETENTION_DAYS="${LOG_RETENTION_DAYS:-90}"
REPORT_LOGO_PATH="${REPORT_LOGO_PATH:-/etc/cve43887/logo.png}"
REPORT_PREPARED_BY="${REPORT_PREPARED_BY:-CVE-2024-43887 Monitoring Pipeline}"
PRIORITIES_HISTORY_CSV="${PRIORITIES_HISTORY_CSV:-$EXPORT_DIR/priorities-history.csv}"
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

quarter_id() {
  python3 - <<'EOF'
import datetime
today = datetime.date.today()
quarter = ((today.month - 1) // 3) + 1
print(f"{today.year}Q{quarter}")
EOF
}

quarter_month_prefixes() {
  python3 - <<'EOF'
import datetime
today = datetime.date.today()
quarter = ((today.month - 1) // 3) + 1
start_month = (quarter - 1) * 3 + 1
for month in range(start_month, start_month + 3):
    print(f"{today.year}{month:02d}")
EOF
}

collect_quarterly_check_logs() {
  local -a prefixes=()
  local path

  while IFS= read -r prefix; do
    [ -n "$prefix" ] && prefixes+=("$prefix")
  done < <(quarter_month_prefixes)

  for path in $CHECK_LOG_ARCHIVE_GLOB; do
    [ -f "$path" ] || continue
    for prefix in "${prefixes[@]}"; do
      case "$path" in
        *"$prefix"*.log)
          printf '%s\n' "$path"
          break
          ;;
      esac
    done
  done

  if [ -f "$CHECK_LOG_CURRENT" ]; then
    printf '%s\n' "$CHECK_LOG_CURRENT"
  fi
}

collect_all_check_logs() {
    local path

    for path in $CHECK_LOG_ARCHIVE_GLOB; do
        [ -f "$path" ] || continue
        printf '%s\n' "$path"
    done

    if [ -f "$CHECK_LOG_CURRENT" ]; then
        printf '%s\n' "$CHECK_LOG_CURRENT"
    fi
}

REPORT_ID="$(quarter_id)"
PDF_PATH="$EXPORT_DIR/quarterly-report-${REPORT_ID}.pdf"
mapfile -t ALL_CHECK_LOGS < <(collect_all_check_logs)

mkdir -p "$EXPORT_DIR"
mkdir -p "$ARCHIVE_DIR"

log_report_event "run" "started" "report_id=${REPORT_ID}"

python3 - "$PDF_PATH" "$API_AUDIT_LOG" "$RETENTION_DAYS" "$REPORT_LOGO_PATH" "$REPORT_PREPARED_BY" "$PRIORITIES_HISTORY_CSV" "${ALL_CHECK_LOGS[@]}" <<'EOF'
import collections
import csv
import datetime
import os
import sys

pdf_path = sys.argv[1]
api_audit_log = sys.argv[2]
retention_days = sys.argv[3]
logo_path = sys.argv[4]
prepared_by = sys.argv[5]
priorities_history_csv = sys.argv[6]
check_logs = [path for path in sys.argv[7:] if path]

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
except ImportError as exc:
    raise SystemExit(f"matplotlib is required for quarterly reports: {exc}")

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Image, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except ImportError as exc:
    raise SystemExit(f"reportlab is required for quarterly reports: {exc}")


today = datetime.date.today()
quarter = ((today.month - 1) // 3) + 1
report_id = f"{today.year}Q{quarter}"
temp_chart = os.path.join(os.path.dirname(pdf_path), f"quarterly-trends-{report_id}.png")
temp_risk_chart = os.path.join(os.path.dirname(pdf_path), f"quarterly-risk-{report_id}.png")

email_alerts = 0
kernel_events = 0
api_calls = 0
read_calls = 0
admin_calls = 0
unauthorized_calls = 0

alert_weeks = collections.Counter()
kernel_weeks = collections.Counter()
api_weeks = collections.Counter()
unauthorized_events = []


def html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def normalize_index(value: int, max_reference: int, invert: bool = False) -> float:
    if max_reference <= 0:
        return 0.0

    normalized = min((value / max_reference) * 10.0, 10.0)
    if invert:
        return max(0.0, 10.0 - normalized)
    return normalized


def compute_risk_rating(email_alert_count: int, kernel_event_count: int, unauthorized_count: int):
    alerts_index = normalize_index(email_alert_count, 50)
    update_index = normalize_index(kernel_event_count, 20, invert=True)
    unauthorized_index = normalize_index(unauthorized_count, 10)

    risk_score = (0.5 * alerts_index) + (0.3 * update_index) + (0.2 * unauthorized_index)

    if risk_score < 4:
        return (
            "Low",
            colors.HexColor("#15803d"),
            f"Weighted score {risk_score:.1f}/10. Current telemetry indicates low alert pressure, healthy kernel activity, and minimal unauthorized access.",
            risk_score,
            alerts_index,
            update_index,
            unauthorized_index,
        )
    if risk_score < 7:
        return (
            "Medium",
            colors.HexColor("#d97706"),
            f"Weighted score {risk_score:.1f}/10. Moderate operational risk driven by alert activity, uneven kernel cadence, or isolated unauthorized attempts.",
            risk_score,
            alerts_index,
            update_index,
            unauthorized_index,
        )
    return (
        "High",
        colors.HexColor("#b91c1c"),
        f"Weighted score {risk_score:.1f}/10. Elevated risk due to sustained alert volume, limited kernel activity, or repeated unauthorized API access.",
        risk_score,
        alerts_index,
        update_index,
        unauthorized_index,
    )


def forecast_next_risk(scores):
    if not scores:
        return 0.0, "Low", "No historical points available."

    if len(scores) == 1:
        return scores[0], "Low", "Single data point available; forecast confidence is limited."

    slope = (scores[-1] - scores[0]) / (len(scores) - 1)
    forecast = max(0.0, min(10.0, scores[-1] + slope))
    deltas = [abs(scores[i] - scores[i - 1]) for i in range(1, len(scores))]
    volatility = sum(deltas) / len(deltas) if deltas else 0.0

    if len(scores) >= 4 and volatility <= 1.0:
        confidence = "High"
    elif len(scores) >= 3 and volatility <= 2.0:
        confidence = "Medium"
    else:
        confidence = "Low"

    direction = "stable"
    if slope > 0.15:
        direction = "upward"
    elif slope < -0.15:
        direction = "downward"

    message = f"Forecast indicates a {direction} risk trajectory based on recent quarter scores."
    return forecast, confidence, message


def build_recommendations(alerts_index: float, update_index: float, unauthorized_index: float):
    recommendations = []

    if alerts_index > 7:
        recommendations.append((3,
            "Investigate frequent alerts; patch vulnerable services promptly and review whether alert thresholds need tuning."
        ))
    if update_index > 5:
        recommendations.append((2,
            "Increase kernel patch cadence and automate update verification so systems do not drift behind the expected remediation window."
        ))
    if unauthorized_index > 5:
        recommendations.append((1,
            "Review API access controls, rotate exposed tokens, and enforce stricter RBAC policies around privileged endpoints."
        ))

    if not recommendations:
        recommendations.append((0,
            "System posture is stable; maintain the current monitoring, patching cadence, and API access review process."
        ))

    recommendations.sort(key=lambda item: item[0], reverse=True)
    return [text for _, text in recommendations]


def top_three_priorities(recommendations):
    priorities = list(recommendations[:3])
    while len(priorities) < 3:
        priorities.append("Maintain current posture and continue quarterly review of monitoring and update controls.")
    return priorities


def quarter_key(date_value: datetime.date) -> str:
    q = ((date_value.month - 1) // 3) + 1
    return f"{date_value.year}Q{q}"


def quarter_sort_value(key: str):
    return int(key[:4]), int(key[-1])


def quarter_label(key: str) -> str:
    return f"Q{key[-1]} {key[:4]}"


def previous_quarter_key(key: str) -> str:
    year = int(key[:4])
    quarter_value = int(key[-1])
    if quarter_value == 1:
        return f"{year - 1}Q4"
    return f"{year}Q{quarter_value - 1}"


def ensure_priorities_history_header(path: str) -> None:
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["quarter", "year", "priority", "status"])


def load_quarter_priorities(path: str, quarter_key_value: str):
    if not os.path.exists(path):
        return []

    expected_year = quarter_key_value[:4]
    expected_quarter = f"Q{quarter_key_value[-1]}"
    records = []
    with open(path, "r", newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_quarter = (row.get("quarter") or "").strip().upper()
            row_year = (row.get("year") or "").strip()
            if row_quarter == expected_quarter and row_year == expected_year:
                records.append(
                    {
                        "priority": (row.get("priority") or "").strip(),
                        "status": (row.get("status") or "Pending").strip() or "Pending",
                    }
                )
    return records


def append_current_priorities(path: str, quarter_key_value: str, priorities):
    existing = load_quarter_priorities(path, quarter_key_value)
    existing_priorities = {record["priority"] for record in existing if record["priority"]}
    pending_rows = []
    for priority in priorities:
        if priority not in existing_priorities:
            pending_rows.append(priority)

    if not pending_rows:
        return

    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        for priority in pending_rows:
            writer.writerow([f"Q{quarter_key_value[-1]}", quarter_key_value[:4], priority, "Pending"])


quarterly_metrics = collections.defaultdict(lambda: {"alerts": 0, "kernel": 0, "unauthorized": 0})


def quarter_start_date(date_value: datetime.date) -> datetime.date:
    start_month = (quarter - 1) * 3 + 1
    return datetime.date(date_value.year, start_month, 1)


quarter_start = quarter_start_date(today)

for log_path in check_logs:
    if not os.path.exists(log_path):
        continue
    with open(log_path, "r", encoding="utf-8") as handle:
        for line in handle:
            timestamp = line.split(" | ", 1)[0].strip()
            try:
                dt = datetime.datetime.fromisoformat(timestamp)
            except ValueError:
                continue
            if dt.date() < quarter_start:
                continue
            week_key = f"{dt.isocalendar().year}-W{dt.isocalendar().week:02d}"
            qkey = quarter_key(dt.date())

            if "Email alert sent:" in line:
                email_alerts += 1
                alert_weeks[week_key] += 1
                quarterly_metrics[qkey]["alerts"] += 1

            if any(marker in line for marker in ("Safe likely:", "Vulnerable range:", "Unknown range:")):
                kernel_events += 1
                kernel_weeks[week_key] += 1
                quarterly_metrics[qkey]["kernel"] += 1

if os.path.exists(api_audit_log):
    with open(api_audit_log, "r", encoding="utf-8") as handle:
        for line in handle:
            timestamp = line.split(" | ", 1)[0].strip()
            try:
                dt = datetime.datetime.fromisoformat(timestamp)
            except ValueError:
                continue
            if dt.date() < quarter_start:
                continue

            api_calls += 1
            week_key = f"{dt.isocalendar().year}-W{dt.isocalendar().week:02d}"
            qkey = quarter_key(dt.date())
            api_weeks[week_key] += 1

            if "role=read" in line:
                read_calls += 1
            elif "role=admin" in line:
                admin_calls += 1
            elif "role=unauthorized" in line:
                unauthorized_calls += 1
                unauthorized_events.append(line.strip())
                quarterly_metrics[qkey]["unauthorized"] += 1

weeks = sorted(set(alert_weeks) | set(kernel_weeks) | set(api_weeks))[-12:]
if not weeks:
    weeks = ["No Data"]

alert_values = [alert_weeks.get(week, 0) for week in weeks]
kernel_values = [kernel_weeks.get(week, 0) for week in weeks]
api_values = [api_weeks.get(week, 0) for week in weeks]

plt.figure(figsize=(10, 5.5))
plt.plot(weeks, alert_values, marker="o", linewidth=2.2, color="#b91c1c", label="Email Alerts")
plt.plot(weeks, kernel_values, marker="s", linewidth=2.2, color="#1d4ed8", label="Kernel Events")
plt.plot(weeks, api_values, marker="^", linewidth=2.2, color="#0f766e", label="API Activity")
plt.title("Quarterly Monitoring Trend Analysis")
plt.xlabel("Week")
plt.ylabel("Count")
plt.xticks(rotation=35, ha="right")
plt.grid(True, linestyle="--", alpha=0.35)
plt.legend()
plt.tight_layout()
plt.savefig(temp_chart, dpi=150)
plt.close()

quarter_keys = sorted(quarterly_metrics.keys(), key=quarter_sort_value)[-6:]
if not quarter_keys:
    quarter_keys = [report_id]
    quarterly_metrics[report_id]

risk_labels = []
risk_scores = []
for key in quarter_keys:
    quarter_risk = compute_risk_rating(
        quarterly_metrics[key]["alerts"],
        quarterly_metrics[key]["kernel"],
        quarterly_metrics[key]["unauthorized"],
    )
    risk_labels.append(quarter_label(key))
    risk_scores.append(round(quarter_risk[3], 2))

forecast_score, forecast_confidence, forecast_message = forecast_next_risk(risk_scores)
forecast_rating = "Low" if forecast_score < 4 else ("Medium" if forecast_score < 7 else "High")

plt.figure(figsize=(8.8, 4.2))
plt.plot(risk_labels, risk_scores, marker="o", linewidth=2.4, color="#7c3aed")
plt.axhline(4, color="#d97706", linestyle="--", linewidth=1.2)
plt.axhline(7, color="#b91c1c", linestyle="--", linewidth=1.2)
plt.ylim(0, 10)
plt.title("Quarter-over-Quarter Risk Score")
plt.xlabel("Quarter")
plt.ylabel("Risk Score")
plt.grid(True, linestyle="--", alpha=0.35)
plt.tight_layout()
plt.savefig(temp_risk_chart, dpi=150)
plt.close()

highlights = []
if unauthorized_calls:
    highlights.append(f"Unauthorized API attempts recorded: {unauthorized_calls}")
if alert_values and max(alert_values) > 0:
    peak_index = max(range(len(alert_values)), key=alert_values.__getitem__)
    highlights.append(f"Peak alert volume occurred in {weeks[peak_index]} with {alert_values[peak_index]} email alerts")
if kernel_values and max(kernel_values) > 0:
    peak_index = max(range(len(kernel_values)), key=kernel_values.__getitem__)
    highlights.append(f"Most kernel status activity occurred in {weeks[peak_index]} with {kernel_values[peak_index]} events")
if not highlights:
    highlights.append("No notable spikes detected during this quarter.")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], alignment=1, fontSize=24, leading=30, textColor=colors.HexColor("#0f172a")))
styles.add(ParagraphStyle(name="CoverMeta", parent=styles["Heading2"], alignment=1, textColor=colors.HexColor("#334155"), spaceAfter=10))
styles.add(ParagraphStyle(name="CoverBody", parent=styles["Normal"], alignment=1, textColor=colors.HexColor("#475569"), leading=15))
doc = SimpleDocTemplate(pdf_path, pagesize=letter, topMargin=0.6 * inch, bottomMargin=0.6 * inch)
story = []

risk_label, risk_color, risk_message, risk_score, alerts_index, update_index, unauthorized_index = compute_risk_rating(email_alerts, kernel_events, unauthorized_calls)
recommendations = build_recommendations(alerts_index, update_index, unauthorized_index)
priorities = top_three_priorities(recommendations)

ensure_priorities_history_header(priorities_history_csv)
prior_quarter = previous_quarter_key(report_id)
prior_quarter_records = load_quarter_priorities(priorities_history_csv, prior_quarter)
append_current_priorities(priorities_history_csv, report_id, priorities)

story.append(Spacer(1, 0.45 * inch))
if os.path.exists(logo_path):
    story.append(Image(logo_path, width=2.1 * inch, height=2.1 * inch, hAlign="CENTER"))
    story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph("Quarterly CVE-2024-43887 Security Report", styles["CoverTitle"]))
story.append(Spacer(1, 0.15 * inch))
story.append(Paragraph(f"{report_id} | Generated on {today.isoformat()}", styles["CoverMeta"]))
story.append(Spacer(1, 0.2 * inch))

risk_table = Table(
    [[f"Risk Level: {risk_label} ({risk_score:.1f}/10)"]],
    colWidths=[5.7 * inch],
)
risk_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, -1), risk_color),
    ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
    ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, -1), 18),
    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ("TOPPADDING", (0, 0), (-1, -1), 14),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 14),
    ("BOX", (0, 0), (-1, -1), 0, colors.white),
]))
story.append(risk_table)
story.append(Spacer(1, 0.22 * inch))
story.append(Paragraph(risk_message, styles["CoverBody"]))
story.append(Spacer(1, 0.1 * inch))
story.append(Paragraph(
    f"Score composition: Alerts Index {alerts_index:.1f}/10, Update Index {update_index:.1f}/10, Unauthorized Index {unauthorized_index:.1f}/10.",
    styles["CoverBody"],
))
story.append(Spacer(1, 0.22 * inch))
priority_box = Table(
    [["Top 3 Security Priorities This Quarter"], *[[f"{index}. {priority}"] for index, priority in enumerate(priorities, start=1)]],
    colWidths=[5.7 * inch],
)
priority_box.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), risk_color),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("FONTSIZE", (0, 0), (-1, 0), 13),
    ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#f8fafc")),
    ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#0f172a")),
    ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
    ("LEFTPADDING", (0, 0), (-1, -1), 12),
    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ("TOPPADDING", (0, 0), (-1, -1), 9),
    ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
]))
story.append(priority_box)
story.append(Spacer(1, 0.22 * inch))
story.append(Paragraph(f"Prepared by: {html_escape(prepared_by)}", styles["CoverBody"]))
story.append(PageBreak())

story.append(Paragraph("Progress Tracker", styles["Heading1"]))
if prior_quarter_records:
        progress_rows = [["Priority", "Status"]]
        completed = 0
        for record in prior_quarter_records:
            status_value = record["status"]
            normalized = status_value.lower()
            icon = "✔" if normalized == "completed" else "✖"
            if normalized == "completed":
                completed += 1
            progress_rows.append([record["priority"], f"{icon} {status_value}"])

        progress_table = Table(progress_rows, colWidths=[4.7 * inch, 1.4 * inch])
        progress_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#ede9fe")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#5b21b6")),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]))
        story.append(Paragraph(f"Progress from {quarter_label(prior_quarter)} to {quarter_label(report_id)}", styles["Normal"]))
        story.append(Spacer(1, 0.1 * inch))
        story.append(progress_table)
        story.append(Spacer(1, 0.12 * inch))
        total = len(prior_quarter_records)
        story.append(Paragraph(
            f"Summary: {completed} of {total} priorities were completed. {total - completed} remain pending.",
            styles["Normal"],
        ))
else:
        story.append(Paragraph(
            f"No tracked priorities were found for {quarter_label(prior_quarter)}. Priorities for {quarter_label(report_id)} were seeded as Pending in priorities history.",
            styles["Normal"],
        ))

story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph(f"CVE-2024-43887 Quarterly Executive Report ({report_id})", styles["Title"]))
story.append(Paragraph(f"Generated on {today.isoformat()}", styles["Normal"]))
story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph("Executive Summary", styles["Heading1"]))
summary_table = Table(
    [
        ["Metric", "Value"],
        ["Email Alerts Sent", str(email_alerts)],
        ["Kernel Status Events", str(kernel_events)],
        ["API Accesses Logged", str(api_calls)],
        ["Read Role Requests", str(read_calls)],
        ["Admin Role Requests", str(admin_calls)],
        ["Unauthorized Attempts", str(unauthorized_calls)],
        ["Weighted Risk Score", f"{risk_score:.1f}/10 ({risk_label})"],
        ["Retention Policy", f"{retention_days} days"],
    ],
    colWidths=[2.8 * inch, 2.4 * inch],
)
summary_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dbeafe")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
    ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
]))
story.append(summary_table)
story.append(Spacer(1, 0.25 * inch))

story.append(Paragraph("Trend Analysis", styles["Heading1"]))
story.append(Image(temp_chart, width=6.8 * inch, height=3.7 * inch))
story.append(Spacer(1, 0.2 * inch))
story.append(Paragraph("Risk Trendline", styles["Heading1"]))
story.append(Image(temp_risk_chart, width=6.5 * inch, height=3.1 * inch))
story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph("Forecast", styles["Heading1"]))
story.append(Paragraph(
    f"Predicted next-quarter risk score: {forecast_score:.1f}/10 ({forecast_rating}). Confidence: {forecast_confidence}.",
    styles["Normal"],
))
story.append(Paragraph(forecast_message, styles["Normal"]))
story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph("Recommendations", styles["Heading1"]))
for recommendation in recommendations:
    story.append(Paragraph(f"• {html_escape(recommendation)}", styles["Normal"]))
story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph("Highlights", styles["Heading1"]))
for highlight in highlights:
    story.append(Paragraph(f"• {highlight}", styles["Normal"]))
story.append(Spacer(1, 0.2 * inch))

story.append(Paragraph("Detailed Appendix", styles["Heading1"]))
appendix_table = Table(
    [
        ["Category", "Count"],
        ["API Read Requests", str(read_calls)],
        ["API Admin Requests", str(admin_calls)],
        ["API Unauthorized Requests", str(unauthorized_calls)],
        ["Quarter Weeks Tracked", str(len(weeks) if weeks != ["No Data"] else 0)],
    ],
    colWidths=[3.3 * inch, 1.9 * inch],
)
appendix_table.setStyle(TableStyle([
    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dcfce7")),
    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#166534")),
    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
]))
story.append(appendix_table)

if unauthorized_events:
    story.append(Spacer(1, 0.2 * inch))
    story.append(Paragraph("Recent Unauthorized Attempts", styles["Heading2"]))
    for event in unauthorized_events[-5:]:
        story.append(Paragraph(html_escape(event), styles["Code"]))

doc.build(story)
os.remove(temp_chart)
os.remove(temp_risk_chart)
EOF

log_report_event "pdf_generation" "success" "path=${PDF_PATH}"

if [ -n "$LEADERSHIP_EMAIL" ]; then
  if command -v mail >/dev/null 2>&1; then
        if echo "Attached: quarterly executive PDF report." | mail -s "Quarterly CVE-2024-43887 Executive Report" -a "$PDF_PATH" "$LEADERSHIP_EMAIL"; then
            log_report_event "email_delivery" "success" "target=${LEADERSHIP_EMAIL}"
        else
            log_report_event "email_delivery" "failed" "target=${LEADERSHIP_EMAIL}"
        fi
  elif command -v mailx >/dev/null 2>&1; then
        if echo "Attached: quarterly executive PDF report." | mailx -s "Quarterly CVE-2024-43887 Executive Report" -a "$PDF_PATH" "$LEADERSHIP_EMAIL"; then
            log_report_event "email_delivery" "success" "target=${LEADERSHIP_EMAIL}"
        else
            log_report_event "email_delivery" "failed" "target=${LEADERSHIP_EMAIL}"
        fi
  else
    echo "No mail client found; PDF retained at $PDF_PATH" >&2
        log_report_event "email_delivery" "skipped" "mail client unavailable"
  fi
fi

cp "$PDF_PATH" "$ARCHIVE_DIR/$(basename "$PDF_PATH")"
log_report_event "archive_copy" "success" "path=$ARCHIVE_DIR/$(basename "$PDF_PATH")"
echo "Quarterly PDF created at $PDF_PATH"
log_report_event "run" "completed" "report_id=${REPORT_ID}"