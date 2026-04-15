<#
.SYNOPSIS
CVE-43887 HTML + PDF Dashboard Generator with Digital Signature & Email
Generates weekly dashboard as HTML, converts to PDF, optionally signs it,
and emails both to leadership via Gmail SMTP.

.DESCRIPTION
1. Aggregates heartbeat, health-check, and Sentinel baseline data.
2. Renders a self-contained HTML report with Chart.js sparklines.
3. Converts HTML to PDF via wkhtmltopdf (or Python fallback).
4. Applies PKCS#12 digital signature via openssl + qpdf (if configured).
5. Emails the signed PDF + HTML to leadership.

.PARAMETER AlertEmail
Email recipient for the dashboard report.

.PARAMETER CertPath
Path to PKCS#12 (.p12 / .pfx) certificate for PDF signing.

.PARAMETER CertPassword
SecureString password for the certificate keystore (prompted securely if omitted).

.PARAMETER SkipEmail
Generate report only — do not send email.

.PARAMETER SkipSign
Skip digital signature even if certificate is available.

.EXAMPLE
.\cve43887_dashboard_html.ps1
$pwd = Read-Host -AsSecureString -Prompt "Cert password"
.\cve43887_dashboard_html.ps1 -CertPath C:\Certs\cve43887.p12 -CertPassword $pwd
.\cve43887_dashboard_html.ps1 -SkipEmail -SkipSign
#>

param(
    [string]$AlertEmail = "jasonnorman66994@gmail.com",
    [string]$CertPath = "",
    [SecureString]$CertPassword = (New-Object SecureString),
    [switch]$SkipEmail,
    [switch]$SkipSign
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
$logDir = "C:\Logs\cve43887"
$sentinelDir = "C:\Logs\sentinel"
$reportDir = "C:\Reports\cve43887"
$gmailCredFile = Join-Path $logDir 'gmail_cred.xml'
$timestamp = Get-Date -Format "yyyy-MM-dd"
$htmlFile = Join-Path $reportDir "cve43887-dashboard-$timestamp.html"
$pdfFile = Join-Path $reportDir "cve43887-dashboard-$timestamp.pdf"
$signedPdfFile = Join-Path $reportDir "cve43887-dashboard-$timestamp-signed.pdf"

$null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $sentinelDir -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction SilentlyContinue

Write-Host "[*] CVE-43887 HTML Dashboard Generator" -ForegroundColor Cyan
Write-Host "    Output: $htmlFile"
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Gather Data
# ---------------------------------------------------------------------------
Write-Host "[1/5] Gathering data..." -ForegroundColor Yellow

# Health check summary from latest monthly log
$latestHealthLog = Get-ChildItem (Join-Path $logDir "cve43887-healthcheck-*.log") -ErrorAction SilentlyContinue |
Sort-Object LastWriteTime -Descending | Select-Object -First 1

$hcPass = 0; $hcFail = 0; $hcWarn = 0; $hcDate = "N/A"
if ($latestHealthLog) {
    $hcContent = Get-Content $latestHealthLog.FullName -ErrorAction SilentlyContinue
    $hcPass = @($hcContent | Where-Object { $_ -match '\[PASS\]' }).Count
    $hcFail = @($hcContent | Where-Object { $_ -match '\[FAIL\]' }).Count
    $hcWarn = @($hcContent | Where-Object { $_ -match '\[WARN\]' }).Count
    $hcDate = $latestHealthLog.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
}

# Heartbeat log entries (last 7 days)
$heartbeatLog = Join-Path $logDir "cve43887-heartbeat.log"
$hbEntries = @()
$hbPassCount = 0; $hbFailCount = 0
if (Test-Path $heartbeatLog) {
    $sevenDaysAgo = (Get-Date).AddDays(-7)
    $hbEntries = @(Get-Content $heartbeatLog -ErrorAction SilentlyContinue | Where-Object {
            $lineDate = ($_ -split ' ')[0]
            if ($lineDate -match '^\d{4}-\d{2}-\d{2}$') {
                [datetime]::ParseExact($lineDate, 'yyyy-MM-dd', $null) -ge $sevenDaysAgo
            }
            else { $false }
        })
    $hbPassCount = @($hbEntries | Where-Object { $_ -match '\[PASS\]' }).Count
    $hbFailCount = @($hbEntries | Where-Object { $_ -match '\[FAIL\]' }).Count
}

# Sentinel baseline data
$baselineFile = Join-Path $sentinelDir "baseline_samples.json"
$anomalyFile = Join-Path $sentinelDir "anomalies.json"
$threatFile = Join-Path $sentinelDir "threat_events.json"

$sparkLabels = @(); $sparkActual = @(); $baselineMean = 0
$sampleCount = 0; $anomalyCount = 0; $threatEventCount = 0

if (Test-Path $baselineFile) {
    $samples = Get-Content $baselineFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    $sampleCount = $samples.Count
    $recent = $samples | Select-Object -Last 24
    $sparkLabels = $recent | ForEach-Object {
        $ts = if ($_.timestamp -is [datetime]) { $_.timestamp.ToString('HH:mm') } else { ($_.timestamp -split 'T')[1].Substring(0, 5) }
        $ts
    }
    $sparkActual = $recent | ForEach-Object { $_.process_count }
    if ($sparkActual.Count -gt 0) {
        $baselineMean = [math]::Round(($sparkActual | Measure-Object -Average).Average, 1)
    }
}

if (Test-Path $anomalyFile) {
    $anomalies = Get-Content $anomalyFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    $anomalyCount = $anomalies.Count
}

$threatEvents = @()
if (Test-Path $threatFile) {
    $threatEvents = Get-Content $threatFile -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
    $threatEventCount = $threatEvents.Count
}

# Overall status
$overallStatus = "HEALTHY"
$statusColor = "#22c55e"
if ($hcFail -gt 0 -or $hbFailCount -gt 0) {
    $overallStatus = "DEGRADED"
    $statusColor = "#ef4444"
}
elseif ($hcWarn -gt 0 -or $anomalyCount -gt 0) {
    $overallStatus = "WARNING"
    $statusColor = "#eab308"
}

# ---------------------------------------------------------------------------
# 2. Generate HTML
# ---------------------------------------------------------------------------
Write-Host "[2/5] Generating HTML report..." -ForegroundColor Yellow

$labelsJson = ($sparkLabels | ForEach-Object { "`"$_`"" }) -join ','
$actualJson = ($sparkActual | ForEach-Object { $_ }) -join ','
$baselineArr = ($sparkActual | ForEach-Object { $baselineMean }) -join ','

# Build anomaly + threat table rows
$eventRows = ""

# Helper: format timestamp safely whether DateTime or string
function Format-TS($val) {
    if (-not $val) { return "--" }
    if ($val -is [datetime]) { return $val.ToString('yyyy-MM-dd HH:mm:ss') }
    $s = [string]$val
    if ($s.Length -gt 19) { return $s.Substring(0, 19) }
    return $s
}

if ($anomalies) {
    foreach ($a in ($anomalies | Select-Object -Last 15)) {
        $ts = Format-TS $a.timestamp
        $met = if ($a.metric) { $a.metric } else { "--" }
        $obs = if ($a.PSObject.Properties['observed']) { $a.observed } else { "--" }
        $zsc = if ($a.PSObject.Properties['zscore']) { "{0:+0.0}" -f $a.zscore } else { "--" }
        $sev = if ($a.severity) { $a.severity } else { "INFO" }
        $sevClass = "sev-$($sev.ToLower())"
        $eventRows += "<tr><td>$ts</td><td><span class=`"badge badge-anomaly`">ANOMALY</span></td><td>$met`: observed=$obs z=$zsc</td><td class=`"$sevClass`">$sev</td></tr>`n"
    }
}
if ($threatEvents) {
    foreach ($t in ($threatEvents | Select-Object -Last 10)) {
        $ts = Format-TS $t.timestamp
        $ind = if ($t.indicator) { $t.indicator } else { "--" }
        $cat = if ($t.category) { $t.category } else { "--" }
        $badge = if ($t.badge) { $t.badge } else { "Threat Match" }
        $conf = if ($t.PSObject.Properties['confidence']) { $t.confidence } else { 0 }
        $sev = if ($conf -ge 70) { "HIGH" } else { "MEDIUM" }
        $sevClass = "sev-$($sev.ToLower())"
        $eventRows += "<tr><td>$ts</td><td><span class=`"badge badge-threat`">$badge</span></td><td>$ind ($cat)</td><td class=`"$sevClass`">$sev</td></tr>`n"
    }
}
if (-not $eventRows) {
    $eventRows = '<tr><td colspan="4" style="color:#94a3b8;">No events in the reporting period</td></tr>'
}

$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CVE-43887 Weekly Dashboard — $timestamp</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
  :root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#e2e8f0;--muted:#94a3b8;--accent:#6366f1;--green:#22c55e;--red:#ef4444;--amber:#eab308;--orange:#f97316}
  *{margin:0;padding:0;box-sizing:border-box}
  body{font-family:'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1000px;margin:0 auto}
  h1{color:var(--accent);font-size:1.5rem;margin-bottom:.15rem}
  .subtitle{color:var(--muted);font-size:.82rem;margin-bottom:1.5rem}
  .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:1.5rem}
  .card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1.2rem}
  .card h2{font-size:.95rem;color:var(--accent);margin-bottom:.6rem}
  .stat{display:flex;justify-content:space-between;padding:.3rem 0;border-bottom:1px solid var(--border);font-size:.85rem}
  .stat:last-child{border:none}
  .stat .label{color:var(--muted)}
  .badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.72rem;font-weight:600}
  .badge-anomaly{background:rgba(234,179,8,.15);color:var(--amber)}
  .badge-threat{background:rgba(239,68,68,.15);color:var(--red)}
  .badge-zscore{background:rgba(249,115,22,.15);color:var(--orange)}
  .chart-wrap{position:relative;height:220px;margin-bottom:1.5rem}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;padding:.45rem;color:var(--muted);border-bottom:2px solid var(--border)}
  td{padding:.45rem;border-bottom:1px solid var(--border)}
  .sev-critical{color:var(--red);font-weight:700}
  .sev-high{color:var(--orange);font-weight:600}
  .sev-medium{color:var(--amber)}
  .sev-low{color:var(--green)}
  .sev-info{color:var(--muted)}
  .status-pill{display:inline-block;padding:4px 14px;border-radius:20px;font-weight:700;font-size:.9rem}
  .footer{text-align:center;color:var(--muted);font-size:.72rem;margin-top:2rem;border-top:1px solid var(--border);padding-top:1rem}
  @media print{body{background:#fff;color:#111}.card{border-color:#ccc;background:#fafafa}:root{--text:#111;--muted:#555;--accent:#4338ca;--border:#ccc}}
</style>
</head>
<body>

<h1>CVE-43887 Weekly Dashboard</h1>
<p class="subtitle">Generated: $timestamp &nbsp;|&nbsp; Sovereign Pulse Engine &nbsp;|&nbsp; Status: <span class="status-pill" style="background:${statusColor}22;color:$statusColor">$overallStatus</span></p>

<div class="grid">
  <div class="card">
    <h2>Health Check</h2>
    <div class="stat"><span class="label">Last Run</span><span>$hcDate</span></div>
    <div class="stat"><span class="label">Pass</span><span style="color:var(--green)">$hcPass</span></div>
    <div class="stat"><span class="label">Warn</span><span style="color:var(--amber)">$hcWarn</span></div>
    <div class="stat"><span class="label">Fail</span><span style="color:var(--red)">$hcFail</span></div>
  </div>
  <div class="card">
    <h2>Heartbeat (7d)</h2>
    <div class="stat"><span class="label">Total Entries</span><span>$($hbEntries.Count)</span></div>
    <div class="stat"><span class="label">Pass</span><span style="color:var(--green)">$hbPassCount</span></div>
    <div class="stat"><span class="label">Fail</span><span style="color:var(--red)">$hbFailCount</span></div>
  </div>
  <div class="card">
    <h2>Sentinel Baseline</h2>
    <div class="stat"><span class="label">Samples</span><span>$sampleCount</span></div>
    <div class="stat"><span class="label">Anomalies</span><span style="color:var(--amber)">$anomalyCount</span></div>
    <div class="stat"><span class="label">Threat Events</span><span style="color:var(--red)">$threatEventCount</span></div>
  </div>
</div>

<div class="card" style="margin-bottom:1.5rem">
  <h2>Sovereign Pulse — Process Count (Baseline vs Actual)</h2>
  <div class="chart-wrap"><canvas id="spark"></canvas></div>
</div>

<div class="card">
  <h2>Flagged Events</h2>
  <table>
    <thead><tr><th>Time</th><th>Badge</th><th>Detail</th><th>Severity</th></tr></thead>
    <tbody>$eventRows</tbody>
  </table>
</div>

<div class="footer">
  Shadow Toolkit v2.0.0 &mdash; Sovereign Pulse Operational Layer &mdash; CVE-43887 Compliance Dashboard<br>
  This report is auto-generated. Digital signature status: <span id="sigStatus">Pending</span>
</div>

<script>
new Chart(document.getElementById('spark').getContext('2d'), {
  type:'line',
  data:{
    labels:[$labelsJson],
    datasets:[
      {label:'Actual',data:[$actualJson],borderColor:'#6366f1',backgroundColor:'rgba(99,102,241,.1)',fill:true,tension:.3,pointRadius:2},
      {label:'Baseline (avg)',data:[$baselineArr],borderColor:'#22c55e',borderDash:[6,3],pointRadius:0,fill:false}
    ]
  },
  options:{
    responsive:true, maintainAspectRatio:false,
    plugins:{legend:{labels:{color:'#94a3b8',font:{size:11}}}},
    scales:{
      x:{ticks:{color:'#94a3b8',font:{size:10}},grid:{color:'#1e293b'}},
      y:{ticks:{color:'#94a3b8'},grid:{color:'#1e293b'}}
    }
  }
});
</script>
</body>
</html>
"@

$htmlContent | Out-File -FilePath $htmlFile -Encoding UTF8 -Force
Write-Host "    HTML: $htmlFile" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 3. Convert to PDF
# ---------------------------------------------------------------------------
Write-Host "[3/5] Converting to PDF..." -ForegroundColor Yellow

$pdfGenerated = $false

# Try wkhtmltopdf first
$wkhtmltopdf = Get-Command wkhtmltopdf -ErrorAction SilentlyContinue
if ($wkhtmltopdf) {
    & wkhtmltopdf --quiet --enable-javascript --javascript-delay 2000 `
        --page-size A4 --margin-top 10mm --margin-bottom 10mm `
        $htmlFile $pdfFile 2>$null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $pdfFile)) {
        $pdfGenerated = $true
        Write-Host "    PDF (wkhtmltopdf): $pdfFile" -ForegroundColor Green
    }
}

# Fallback: Python reportlab
if (-not $pdfGenerated) {
    Write-Host "    wkhtmltopdf not found, trying Python reportlab fallback..." -ForegroundColor DarkYellow
    $pyPdf = @"
import sys
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as cvs
from reportlab.lib.colors import HexColor

path = sys.argv[1]
c = cvs.Canvas(path, pagesize=A4)
w, h = A4

c.setFillColor(HexColor('#6366f1'))
c.setFont('Helvetica-Bold', 18)
c.drawString(50, h - 60, 'CVE-43887 Weekly Dashboard')
c.setFillColor(HexColor('#333333'))
c.setFont('Helvetica', 10)
c.drawString(50, h - 80, 'Generated: $timestamp | Sovereign Pulse Engine | Status: $overallStatus')

y = h - 130
sections = [
    ('Health Check', [('Pass', '$hcPass'), ('Warn', '$hcWarn'), ('Fail', '$hcFail'), ('Last Run', '$hcDate')]),
    ('Heartbeat (7d)', [('Entries', '$($hbEntries.Count)'), ('Pass', '$hbPassCount'), ('Fail', '$hbFailCount')]),
    ('Sentinel Baseline', [('Samples', '$sampleCount'), ('Anomalies', '$anomalyCount'), ('Threat Events', '$threatEventCount')]),
]
for title, items in sections:
    c.setFont('Helvetica-Bold', 12)
    c.setFillColor(HexColor('#6366f1'))
    c.drawString(50, y, title)
    y -= 18
    c.setFont('Helvetica', 10)
    c.setFillColor(HexColor('#333333'))
    for label, val in items:
        c.drawString(70, y, f'{label}: {val}')
        y -= 15
    y -= 10

c.setFont('Helvetica', 8)
c.setFillColor(HexColor('#999999'))
c.drawString(50, 40, 'Shadow Toolkit v2.0.0 - Sovereign Pulse - Auto-generated report')
c.save()
"@
    $tempPy = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.py'
    $pyPdf | Out-File -FilePath $tempPy -Encoding UTF8
    & python $tempPy $pdfFile 2>$null
    if ($LASTEXITCODE -eq 0 -and (Test-Path $pdfFile)) {
        $pdfGenerated = $true
        Write-Host "    PDF (reportlab): $pdfFile" -ForegroundColor Green
    }
    else {
        Write-Host "    [WARN] PDF generation failed" -ForegroundColor Red
    }
    Remove-Item $tempPy -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# 4. Digital Signature
# ---------------------------------------------------------------------------
Write-Host "[4/5] Digital signature..." -ForegroundColor Yellow

$signedFile = $pdfFile  # default to unsigned
$signatureApplied = $false

if ($SkipSign) {
    Write-Host "    Skipped (--SkipSign)" -ForegroundColor DarkYellow
}
elseif (-not $pdfGenerated) {
    Write-Host "    Skipped (no PDF to sign)" -ForegroundColor DarkYellow
}
elseif (-not $CertPath) {
    Write-Host "    No certificate provided (-CertPath). Skipping signature." -ForegroundColor DarkYellow
    Write-Host "    To sign, run with: -CertPath C:\path\to\cert.p12 -CertPassword '...'" -ForegroundColor DarkGray
}
elseif (-not (Test-Path $CertPath)) {
    Write-Host "    [WARN] Certificate not found: $CertPath" -ForegroundColor Red
}
else {
    # Prompt for password if not provided
    if ($CertPassword.Length -eq 0) {
        $CertPassword = Read-Host "Enter certificate password" -AsSecureString
    }

    # Decrypt only at point of use, clear immediately after
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($CertPassword)
    $PlainCertPassword = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)

    try {

        # Method 1: Try qpdf (if available)
        $qpdf = Get-Command qpdf -ErrorAction SilentlyContinue
        if ($qpdf) {
            & qpdf --sign $CertPath --password=$PlainCertPassword `
                --reason="Weekly Dashboard Integrity" `
                --location="Los Angeles, USA" `
                $pdfFile $signedPdfFile 2>$null
            if ($LASTEXITCODE -eq 0 -and (Test-Path $signedPdfFile)) {
                $signedFile = $signedPdfFile
                $signatureApplied = $true
                Write-Host "    Signed (qpdf): $signedPdfFile" -ForegroundColor Green
            }
        }

        # Method 2: Try jSignPdf (Java)
        if (-not $signatureApplied) {
            $jSignPdf = Get-Command java -ErrorAction SilentlyContinue
            $jSignJar = Join-Path $PSScriptRoot "tools\jSignPdf.jar"
            if ($jSignPdf -and (Test-Path $jSignJar)) {
                & java -jar $jSignJar `
                    --keystore $CertPath --storepass $PlainCertPassword `
                    --reason "Weekly Dashboard Integrity" `
                    --location "Los Angeles, USA" `
                    $pdfFile 2>$null
                $jSignedFile = $pdfFile -replace '\.pdf$', '_signed.pdf'
                if (Test-Path $jSignedFile) {
                    $signedFile = $jSignedFile
                    $signatureApplied = $true
                    Write-Host "    Signed (jSignPdf): $jSignedFile" -ForegroundColor Green
                }
            }
        }

        # Method 3: Python pyhanko (pip install pyhanko)
        if (-not $signatureApplied) {
            $pySign = @"
import sys, os
try:
    from pyhanko.sign import signers
    from pyhanko.sign.fields import SigFieldSpec
    from pyhanko import stamp
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter

    cert_path = sys.argv[1]
    cert_pass = sys.argv[2]
    pdf_in    = sys.argv[3]
    pdf_out   = sys.argv[4]

    signer = signers.SimpleSigner.load_pkcs12(
        cert_path, passphrase=cert_pass.encode()
    )
    with open(pdf_in, 'rb') as inf:
        w = IncrementalPdfFileWriter(inf)
        out = signers.sign_pdf(
            w, signers.PdfSignatureMetadata(
                field_name='Signature',
                reason='Weekly Dashboard Integrity',
                location='Los Angeles, USA',
            ),
            signer=signer,
        )
        with open(pdf_out, 'wb') as outf:
            outf.write(out.getbuffer())
    print('OK')
except ImportError:
    print('MISSING_PYHANKO')
    sys.exit(2)
except Exception as e:
    print(f'ERROR:{e}')
    sys.exit(1)
"@
            $tempPy = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.py'
            $pySign | Out-File -FilePath $tempPy -Encoding UTF8
            $result = & python $tempPy $CertPath $PlainCertPassword $pdfFile $signedPdfFile 2>&1
            $exitCode = $LASTEXITCODE
            Remove-Item $tempPy -ErrorAction SilentlyContinue

            if ($exitCode -eq 0 -and (Test-Path $signedPdfFile)) {
                $signedFile = $signedPdfFile
                $signatureApplied = $true
                Write-Host "    Signed (pyhanko): $signedPdfFile" -ForegroundColor Green
            }
            elseif ($result -match 'MISSING_PYHANKO') {
                Write-Host "    pyhanko not installed. Install with: pip install pyhanko" -ForegroundColor DarkYellow
            }
            else {
                Write-Host "    [WARN] Signature failed: $result" -ForegroundColor Red
            }
        }

        if (-not $signatureApplied) {
            Write-Host "    No signing tool available. Install one of: qpdf, jSignPdf, pyhanko" -ForegroundColor DarkYellow
        }

    }
    finally {
        # Zero out the plaintext password from memory
        $PlainCertPassword = $null
        [System.GC]::Collect()
    }
}

# ---------------------------------------------------------------------------
# 5. Email Report
# ---------------------------------------------------------------------------
Write-Host "[5/5] Email delivery..." -ForegroundColor Yellow

if ($SkipEmail) {
    Write-Host "    Skipped (--SkipEmail)" -ForegroundColor DarkYellow
}
elseif (-not (Test-Path $gmailCredFile)) {
    Write-Host "    [WARN] Gmail credentials not found: $gmailCredFile" -ForegroundColor Red
    Write-Host "    Store credentials with:" -ForegroundColor DarkGray
    Write-Host '    Get-Credential | Export-Clixml -Path "C:\Logs\cve43887\gmail_cred.xml"' -ForegroundColor DarkGray
}
else {
    $cred = Import-Clixml -Path $gmailCredFile
    $user = $cred.UserName
    $pass = $cred.GetNetworkCredential().Password

    # Build attachment list
    $attachments = @($htmlFile)
    if ($pdfGenerated) { $attachments += $signedFile }

    $sigNote = if ($signatureApplied) { "Digitally signed PDF attached." } else { "Unsigned PDF attached (no certificate configured)." }
    $emailBody = @"
CVE-43887 Weekly Dashboard Report — $timestamp

Status: $overallStatus

Health Check: $hcPass PASS / $hcWarn WARN / $hcFail FAIL
Heartbeat (7d): $hbPassCount PASS / $hbFailCount FAIL
Sentinel: $sampleCount samples, $anomalyCount anomalies, $threatEventCount threat events

$sigNote

This report is auto-generated by the Sovereign Pulse engine.
"@

    $pyEmail = @"
import smtplib, sys, os
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

user, pwd, to_addr = sys.argv[1], sys.argv[2], sys.argv[3]
subject = sys.argv[4]
body = sys.argv[5]
attachments = sys.argv[6:]

msg = MIMEMultipart()
msg['Subject'] = subject
msg['From'] = user
msg['To'] = to_addr
msg.attach(MIMEText(body, 'plain'))

for fpath in attachments:
    if os.path.isfile(fpath):
        with open(fpath, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f'attachment; filename="{os.path.basename(fpath)}"')
        msg.attach(part)

with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
    s.login(user, pwd)
    s.send_message(msg)
print('OK')
"@
    $tempPy = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.py'
    $pyEmail | Out-File -FilePath $tempPy -Encoding UTF8

    $subject = "CVE-43887 Dashboard [$overallStatus] — $timestamp"
    $emailArgs = @($tempPy, $user, $pass, $AlertEmail, $subject, $emailBody) + $attachments

    try {
        $result = & python @emailArgs 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Host "    Email sent to $AlertEmail ($($attachments.Count) attachments)" -ForegroundColor Green
        }
        else {
            Write-Host "    [WARN] Email failed: $result" -ForegroundColor Red
        }
    }
    catch {
        Write-Host "    [WARN] Email error: $($_.Exception.Message)" -ForegroundColor Red
    }
    Remove-Item $tempPy -ErrorAction SilentlyContinue
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "=== Dashboard Generation Complete ===" -ForegroundColor Cyan
Write-Host "  HTML:      $htmlFile"
if ($pdfGenerated) {
    Write-Host "  PDF:       $signedFile"
    if ($signatureApplied) {
        Write-Host "  Signature: APPLIED" -ForegroundColor Green
    }
    else {
        Write-Host "  Signature: NOT APPLIED" -ForegroundColor DarkYellow
    }
}
Write-Host "  Status:    $overallStatus"
Write-Host ""

exit 0
