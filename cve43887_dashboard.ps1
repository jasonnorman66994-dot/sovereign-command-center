#Requires -Version 5.1
<#
.SYNOPSIS
CVE-43887 Weekly Dashboard Summary (Windows PowerShell Version)
Aggregates heartbeat and health-check logs into consolidated report for leadership.

.DESCRIPTION
Pulls last 7 days of heartbeat logs and latest health-check log.
Generates summary counts and writes to dashboard file.

.EXAMPLE
.\cve43887_dashboard.ps1
#>

$logDir = "C:\Logs\cve43887"
$reportDir = "C:\Reports\cve43887"
$dashboardFile = Join-Path $reportDir "cve43887-dashboard-summary.txt"
$heartbeatLog = Join-Path $logDir "cve43887-heartbeat.log"

# Ensure directories exist
$null = New-Item -ItemType Directory -Path $logDir -Force -ErrorAction SilentlyContinue
$null = New-Item -ItemType Directory -Path $reportDir -Force -ErrorAction SilentlyContinue

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$sevenDaysAgo = (Get-Date).AddDays(-7).Date

# Build dashboard report
$report = @(
    "=== CVE-43887 Weekly Dashboard Summary ==="
    "Generated: $timestamp"
    ""
    ">>> Heartbeat Checks (last 7 days)"
)

if (Test-Path $heartbeatLog -PathType Leaf) {
    $heartbeatEntries = @(Get-Content $heartbeatLog | Where-Object {
            $lineDate = $_ -split ' ' | Select-Object -First 1
            if ($lineDate -match '^\d{4}-\d{2}-\d{2}$') {
                [datetime]::ParseExact($lineDate, 'yyyy-MM-dd', $null) -ge $sevenDaysAgo
            }
            else {
                $false
            }
        })
    $report += $heartbeatEntries
}
else {
    $report += "Heartbeat log not found: $heartbeatLog"
}

$report += ""
$report += ">>> Full Health Check (last run)"

# Find the latest monthly health-check log
$latestHealthLog = Get-ChildItem (Join-Path $logDir "cve43887-healthcheck-*.log") -ErrorAction SilentlyContinue | 
Sort-Object LastWriteTime -Descending | 
Select-Object -First 1

if ($latestHealthLog) {
    $report += "Source: $($latestHealthLog.FullName)"
    $healthContent = Get-Content $latestHealthLog -Tail 80 -ErrorAction SilentlyContinue
    $report += $healthContent
}
else {
    $report += "No health-check monthly log found"
}

$report += ""
$report += ">>> Summary Counts"

$heartbeatPass = @(Get-Content $heartbeatLog -ErrorAction SilentlyContinue | 
    Where-Object { $_ -match '\[PASS\]' }).Count
$heartbeatFail = @(Get-Content $heartbeatLog -ErrorAction SilentlyContinue | 
    Where-Object { $_ -match '\[FAIL\]' }).Count

$healthPass = 0
$healthFail = 0
if ($latestHealthLog) {
    $healthPass = @(Get-Content $latestHealthLog.FullName -ErrorAction SilentlyContinue | 
        Where-Object { $_ -match '\[PASS\]' }).Count
    $healthFail = @(Get-Content $latestHealthLog.FullName -ErrorAction SilentlyContinue | 
        Where-Object { $_ -match '\[FAIL\]' }).Count
}

$report += "Heartbeat checks passed (last 7 days): $heartbeatPass"
$report += "Heartbeat checks failed (last 7 days): $heartbeatFail"
$report += "Health checks passed (latest monthly log): $healthPass"
$report += "Health checks failed (latest monthly log): $healthFail"
$report += ""
$report += "=== End of Dashboard Summary ==="

# Write dashboard file
$report | Out-File -FilePath $dashboardFile -Encoding UTF8 -Force -ErrorAction SilentlyContinue

Write-Host "Dashboard summary written to: $dashboardFile"
exit 0
