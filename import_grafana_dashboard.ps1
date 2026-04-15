# Grafana Dashboard Auto-Import Script
# This PowerShell script uses the Grafana HTTP API to import the dashboard JSON.
# Prerequisites: Grafana server running, API key with 'Editor' or 'Admin' rights.
# Usage: Update $grafanaUrl and $apiKey as needed.

param(
    [string]$DashboardJsonPath = "grafana_email_security_dashboard.json",
    [string]$GrafanaUrl = "http://localhost:3000",
    [string]$ApiKey = "YOUR_GRAFANA_API_KEY"
)

if (!(Test-Path $DashboardJsonPath)) {
    Write-Error "Dashboard JSON file not found: $DashboardJsonPath"
    exit 1
}

$dashboardContent = Get-Content $DashboardJsonPath -Raw | ConvertFrom-Json

$body = @{ dashboard = $dashboardContent.dashboard; overwrite = $true } | ConvertTo-Json -Depth 10

$headers = @{ "Authorization" = "Bearer $ApiKey"; "Content-Type" = "application/json" }

$response = Invoke-RestMethod -Uri "$GrafanaUrl/api/dashboards/db" -Method Post -Headers $headers -Body $body

if ($response.status -eq "success") {
    Write-Host "Dashboard imported successfully!"
    Write-Host "URL: $($GrafanaUrl)$($response.slug)"
} else {
    Write-Error "Failed to import dashboard. Response: $($response | ConvertTo-Json)"
}
