# Automated Windows Event Log Parser for Email Security Incidents
# Extracts failed/successful logins and email-related events for dashboarding

# Requires: Run as Administrator, PowerShell 5+
# Output: login_events.csv (for Excel, Grafana, Kibana, etc.)

$LogName = "Security"  # Or "Application" if SMTP/IMAP logs are there
$StartTime = (Get-Date).AddDays(-1)  # Last 24 hours
$OutputCsv = "login_events.csv"

# Filter for failed/successful logins (Event ID 4625 = failed, 4624 = success)
$events = Get-WinEvent -FilterHashtable @{LogName=$LogName; StartTime=$StartTime; Id=4624,4625} | ForEach-Object {
    $xml = [xml]$_.ToXml()
    $props = $xml.Event.EventData.Data | ForEach-Object { $_.Name, $_.'#text' } | ForEach-Object -Begin {@{}} -Process {
        param($dict, $item)
        if ($dict.Count % 2 -eq 0) { $dict[$item] = $null } else { $dict[$($dict.Keys[-1])] = $item }
        $dict
    }
    [PSCustomObject]@{
        TimeCreated = $_.TimeCreated
        User = $props['TargetUserName']
        IP = $props['IpAddress']
        Status = if ($_.Id -eq 4624) { 'SUCCESS' } else { 'FAILED' }
        LogonType = $props['LogonType']
        Workstation = $props['WorkstationName']
    }
}

$events | Export-Csv -NoTypeInformation -Path $OutputCsv
Write-Host "Exported login events to $OutputCsv"

# For SMTP/IMAP/POP3 logs in Application log, adjust $LogName and Event IDs accordingly.
# Import login_events.csv into Excel, Grafana, or Kibana for visualization.
