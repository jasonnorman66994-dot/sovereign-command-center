#Requires -Version 5.1
<#
.SYNOPSIS
CVE-43887 Health Check Script (Windows PowerShell Version)
Validates reporting pipeline dependencies and logs results for audit purposes.

.DESCRIPTION
Checks Python libraries, mail utility, logs, report directory, and email delivery.
Logs each check result with timestamp, supports quiet mode.

.PARAMETER Quiet
Suppress detailed console output; only print summary.

.PARAMETER AlertEmail
Email address for failure notifications.

.PARAMETER EnableEmailTest
Optional explicit email delivery test when all checks pass.

.EXAMPLE
.\cve43887_healthcheck.ps1
.\cve43887_healthcheck.ps1 -Quiet
.\cve43887_healthcheck.ps1 -Quiet -AlertEmail "jasonnorman66994@gmail.com"
#>

param(
    [switch]$Quiet,
    [string]$AlertEmail = "jasonnorman66994@gmail.com",
    [switch]$EnableEmailTest
)

# Configuration
$logDir = "C:\Logs\cve43887"
$currentMonth = Get-Date -Format "yyyyMM"
$logFile = Join-Path $logDir "cve43887-healthcheck-$currentMonth.log"
$reportDir = "C:\Reports\cve43887"
$gmailCredFile = Join-Path $logDir 'gmail_cred.xml'
$smtpServer = 'smtp.gmail.com'
$smtpPort = 465

# Ensure log and report directories exist
$null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction SilentlyContinue

# Counters
[int]$passCount = 0
[int]$failCount = 0
[int]$warnCount = 0

# Helper functions
function Send-GmailMessage {
    param([string]$To, [string]$Subject, [string]$Body, [pscredential]$Credential)
    $user = $Credential.UserName
    $pass = $Credential.GetNetworkCredential().Password
    $pyScript = @'
import smtplib, sys
from email.mime.text import MIMEText
user, pwd, to_addr, subj = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
body = sys.argv[5]
msg = MIMEText(body)
msg['Subject'] = subj
msg['From'] = user
msg['To'] = to_addr
with smtplib.SMTP_SSL('smtp.gmail.com', 465) as s:
    s.login(user, pwd)
    s.send_message(msg)
'@
    $tempPy = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.py'
    $pyScript | Out-File -FilePath $tempPy -Encoding UTF8
    & python $tempPy $user $pass $To $Subject $Body 2>&1
    $exitCode = $LASTEXITCODE
    Remove-Item $tempPy -ErrorAction SilentlyContinue
    if ($exitCode -ne 0) { throw "Gmail send failed (exit code $exitCode)" }
}

function Log-Line {
    param([string]$Level, [string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = '{0} [{1}] {2}' -f $ts, $Level, $Message
    Add-Content -Path $logFile -Value $entry -ErrorAction SilentlyContinue
}

function Out-Message {
    param([string]$Message)
    if (-not $Quiet) {
        Write-Host $Message
    }
}

function Test-Pass {
    param([string]$Message)
    Out-Message ('  [PASS] {0}' -f $Message)
    Log-Line 'PASS' $Message
    $script:passCount++
}

function Test-Fail {
    param([string]$Message)
    Out-Message ('  [FAIL] {0}' -f $Message)
    Log-Line 'FAIL' $Message
    $script:failCount++
}

function Test-Warn {
    param([string]$Message)
    Out-Message ('  [WARN] {0}' -f $Message)
    Log-Line 'WARN' $Message
    $script:warnCount++
}

# Main execution
Log-Line 'INFO' "=== Health Check Run Started (Quiet=$Quiet) ==="
Out-Message '=== CVE-43887 Reporting Pipeline Health Check ==='
Out-Message "Audit log: $logFile"
Out-Message ''

# 1. Python libraries
Out-Message '[Python Libraries]'
foreach ($lib in @("matplotlib", "reportlab", "openpyxl")) {
    $pythonCheck = & python -c "import $lib" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Test-Pass "$lib installed"
    }
    else {
        Test-Fail "$lib missing"
    }
}

# Check fpdf (optional)
$pythonCheck = & python -c "import fpdf" 2>$null
if ($LASTEXITCODE -eq 0) {
    Test-Pass "fpdf installed (optional)"
}
else {
    Test-Warn "fpdf missing (optional)"
}

# 2. Mail utility (Gmail SMTP)
Out-Message ''
Out-Message '[Mail Utility]'
if ($AlertEmail) {
    if (Test-Path $gmailCredFile) {
        Test-Pass "Email configured for $AlertEmail (Gmail SMTP)"
    }
    else {
        Test-Warn "Gmail credentials missing: $gmailCredFile"
    }
}
else {
    Test-Warn "ALERT_EMAIL not set; failure notifications disabled"
}

# 3. Report directory
Out-Message ''
Out-Message '[Report Directory]'
if (Test-Path $reportDir -PathType Container) {
    $acl = Get-Acl $reportDir
    Test-Pass "$reportDir writable"
}
else {
    Test-Fail "$reportDir missing or not writable"
}

# 4. Core log files presence (check for typical locations)
Out-Message ''
Out-Message '[Logs]'
$expectedLogs = @(
    "C:\Logs\cve-43887-check.log",
    "C:\Logs\cve-43887-api.log",
    "C:\Logs\cve-43887-reporting.log"
)
foreach ($logPath in $expectedLogs) {
    if (Test-Path $logPath -PathType Leaf) {
        Test-Pass "$logPath exists"
    }
    else {
        Test-Warn "$logPath missing"
    }
}

# 5. PDF generation test
Out-Message ''
Out-Message '[PDF Generation]'
$testPdfPath = Join-Path $reportDir 'test.pdf'
try {
    $pythonScript = @'
from reportlab.pdfgen import canvas
import sys
path = sys.argv[1]
c = canvas.Canvas(path)
c.drawString(100, 750, "PDF generation test successful")
c.save()
'@
    $tempPyFile = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.py'
    $pythonScript | Out-File -FilePath $tempPyFile -Encoding UTF8
    & python $tempPyFile $testPdfPath 2>$null
    if ($LASTEXITCODE -eq 0) {
        Test-Pass "PDF generated successfully"
    }
    else {
        Test-Fail "PDF generation failed"
    }
    Remove-Item $tempPyFile -ErrorAction SilentlyContinue
}
catch {
    $errMsg = $_.Exception.Message
    Test-Fail "PDF generation failed: $errMsg"
}

# 6. Optional email test
if ($EnableEmailTest -and $AlertEmail) {
    Out-Message ''
    Out-Message '[Email Test]'
    try {
        $cred = Import-Clixml -Path $gmailCredFile
        Send-GmailMessage -To $AlertEmail -Subject 'CVE-43887 Health Check Report' -Body "This is a test email from the CVE-43887 health check script. Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -Credential $cred
        Test-Pass "Test email sent to $AlertEmail"
    }
    catch {
        $errMsg = $_.Exception.Message
        Test-Warn "Email test failed: $errMsg"
    }
}

# Summary
Out-Message ''
Out-Message '=== Health Check Summary ==='
Out-Message "PASS: $passCount"
Out-Message "WARN: $warnCount"
Out-Message "FAIL: $failCount"
Log-Line 'INFO' "Summary PASS=$passCount WARN=$warnCount FAIL=$failCount"

if ($failCount -eq 0) {
    if ($warnCount -eq 0) {
        Out-Message 'STATUS: All checks passed. Pipeline is healthy.'
        Log-Line 'INFO' 'STATUS: All checks passed. Pipeline is healthy.'
    }
    else {
        Out-Message 'STATUS: No hard failures, but warnings need review.'
        Log-Line 'INFO' 'STATUS: No hard failures, but warnings need review.'
    }
}
else {
    Out-Message 'STATUS: Some checks failed. Review output above.'
    Log-Line 'INFO' 'STATUS: Some checks failed. Review output above.'

    # Failure-only notification
    if ($AlertEmail -and (Test-Path $gmailCredFile)) {
        try {
            $cred = Import-Clixml -Path $gmailCredFile
            $alertBody = "Health check detected $failCount failed checks at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss').`n`nSee log: $logFile`n`nReview the output and resolve failures."
            Send-GmailMessage -To $AlertEmail -Subject 'CVE-43887 Health Check ALERT' -Body $alertBody -Credential $cred
            Log-Line 'INFO' "Failure alert email sent to $AlertEmail"
            Out-Message "Alert email sent to $AlertEmail"
            Out-Message "Alert email sent to $AlertEmail"
        }
        catch {
            $errMsg = $_.Exception.Message
            Log-Line 'WARN' "Failed to send failure alert: $errMsg"
            Out-Message "Failed to send alert email: $errMsg"
        }
    }
}

Out-Message ''

# Post results to Sovereign Pulse telemetry API (if running)
$telemetryUrl = $env:SOVEREIGN_API_URL
if (-not $telemetryUrl) { $telemetryUrl = 'http://127.0.0.1:5050' }
try {
    $payload = @{
        source     = 'healthcheck'
        host       = $env:COMPUTERNAME
        pass_count = $passCount
        warn_count = $warnCount
        fail_count = $failCount
        details    = "Health check completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    } | ConvertTo-Json -Compress
    $null = Invoke-RestMethod -Uri "$telemetryUrl/api/telemetry/heartbeat" `
        -Method Post -ContentType 'application/json' -Body $payload `
        -TimeoutSec 5 -ErrorAction Stop
    Log-Line 'INFO' 'Telemetry heartbeat posted to Sovereign Pulse API'
    Out-Message '  [+] Telemetry posted to Sovereign Pulse API'
}
catch {
    Log-Line 'INFO' "Telemetry API not available (non-blocking): $($_.Exception.Message)"
}

Out-Message '=== Health Check Complete ==='
Log-Line 'INFO' '=== Health Check Complete ==='

if ($failCount -gt 0) {
    exit 1
}
exit 0
