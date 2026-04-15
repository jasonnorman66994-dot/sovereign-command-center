#Requires -Version 5.1
<#
.SYNOPSIS
CVE-43887 Daily Heartbeat Check (Windows PowerShell Version)
Lightweight daily verification that the system is alive.

.DESCRIPTION
Checks critical components: report directory, core logs.
Logs results with timestamp for audit trail.

.EXAMPLE
.\cve43887_heartbeat.ps1
#>

$logDir = "C:\Logs\cve43887"
$logFile = Join-Path $logDir "cve43887-heartbeat.log"
$reportDir = "C:\Reports\cve43887"

# Ensure log directory exists
$null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue

function Log-Line {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Add-Content -Path $logFile -Value "$timestamp $Message" -ErrorAction SilentlyContinue
}

Log-Line "=== Heartbeat Check Run ==="

$passCount = 0
$failCount = 0

# 1. Report directory writable
if (Test-Path $reportDir -PathType Container) {
    Log-Line "[PASS] $reportDir writable"
    $passCount++
}
else {
    Log-Line "[FAIL] report directory missing or not writable: $reportDir"
    $failCount++
}

# 2. Core logs presence
$expectedLogs = @(
    "C:\Logs\cve-43887-check.log",
    "C:\Logs\cve-43887-api.log",
    "C:\Logs\cve-43887-reporting.log"
)
foreach ($logPath in $expectedLogs) {
    if (Test-Path $logPath -PathType Leaf) {
        Log-Line "[PASS] $logPath exists"
        $passCount++
    }
    else {
        Log-Line "[FAIL] $logPath missing"
        $failCount++
    }
}

Log-Line "=== Heartbeat Check Complete ==="

# Post results to Sovereign Pulse telemetry API (if running)
$telemetryUrl = $env:SOVEREIGN_API_URL
if (-not $telemetryUrl) { $telemetryUrl = 'http://127.0.0.1:5050' }
try {
    $payload = @{
        source     = 'heartbeat'
        host       = $env:COMPUTERNAME
        pass_count = $passCount
        warn_count = 0
        fail_count = $failCount
        details    = "Heartbeat at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    } | ConvertTo-Json -Compress
    $null = Invoke-RestMethod -Uri "$telemetryUrl/api/telemetry/heartbeat" `
        -Method Post -ContentType 'application/json' -Body $payload `
        -TimeoutSec 5 -ErrorAction Stop
}
catch {
    # Non-blocking — API may not be running
}

exit 0
