# Email Security Incident Response Script (PowerShell)
# Filters by log source, tool, and platform (Windows)

# --- CONFIGURATION ---
$MailLog = "C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\MessageTracking\MSGTRK*.log" # Adjust as needed
$Domain = "example.com" # Change as needed
$CompromisedUser = "" # Set dynamically during investigation
$SIEMTool = "Sentinel" # Options: Sentinel, Splunk, ELK
$Platform = "Windows"

# --- 1. Detection ---
Write-Host "[Detection]"
Write-Host "Tailing mail logs: $MailLog"
Get-Content -Path $MailLog -Tail 100 -Wait | Tee-Object -FilePath recent_mail.log
Write-Host "Check $SIEMTool dashboard for outbound mail spikes."

# --- 2. Investigation ---
Write-Host "[Investigation]"
Write-Host "Top sender accounts:"
Get-Content $MailLog | Select-String "from=<" | ForEach-Object {
    if ($_ -match 'from=<([^>]+)>') { $matches[1] }
} | Group-Object | Sort-Object Count -Descending | Format-Table Count, Name | Tee-Object -FilePath top_senders.log

# SPF/DKIM/DMARC check
Write-Host "SPF/DKIM/DMARC for $Domain:"
Resolve-DnsName -Type TXT $Domain | Where-Object { $_.Strings -match 'spf|dkim|dmarc' } | Select-Object -ExpandProperty Strings

# --- 3. Containment ---
Write-Host "[Containment]"
if ($CompromisedUser) {
    Disable-ADAccount -Identity $CompromisedUser
    Write-Host "Account $CompromisedUser disabled."
} else {
    Write-Host "Set CompromisedUser variable to lock account."
}
Write-Host "Adjust Exchange send limits as needed."

# --- 4. Root Cause Analysis ---
Write-Host "[Root Cause Analysis]"
Write-Host "Testing open relay:"
try {
    $tcp = New-Object System.Net.Sockets.TcpClient('localhost',25)
    if ($tcp.Connected) { Write-Host "Port 25 open." }
    $tcp.Close()
} catch { Write-Host "Port 25 not open or blocked." }
Write-Host "Run endpoint malware scan (Defender ATP, CrowdStrike, etc.)."

# --- 5. Remediation ---
Write-Host "[Remediation]"
Write-Host "Reset credentials and enable MFA for affected accounts."
Write-Host "Use Windows Update to patch systems."

# --- 6. Recovery & Monitoring ---
Write-Host "[Recovery & Monitoring]"
Write-Host "Check blacklists with MXToolbox or similar."
Write-Host "Request delisting if needed."
Write-Host "Monitor $SIEMTool dashboard for future anomalies."

Write-Host "--- Incident Response Script Complete ---"

# --- 7. Unauthorized Access Detection & Response ---
Write-Host "[Unauthorized Access Detection]"
Write-Host "Example IMAP/SMTP log snippet:"
Write-Host "Apr 14 04:15:20 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=203.0.113.45"
Write-Host "Apr 14 04:15:21 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=198.51.100.23"
Write-Host "Apr 14 04:15:22 mailserver imapd[8888]: LOGIN FAILED user=finance_team@example.com host=192.0.2.10"
Write-Host "Apr 14 04:15:25 mailserver imapd[8888]: LOGIN SUCCESS user=finance_team@example.com host=203.0.113.45"
Write-Host "Apr 14 04:15:26 mailserver imapd[8888]: SESSION START user=finance_team@example.com host=203.0.113.45"

# Red flags to spot
Write-Host "Red Flags:"
Write-Host "- Multiple failed logins from different IPs in seconds (brute-force or credential stuffing)"
Write-Host "- Suspicious IP addresses (not normal user behavior)"
Write-Host "- Sudden success after failures (attacker guessed or used stolen credentials)"
Write-Host "- Session start from unusual location (unauthorized access)"

# What Admins Do
Write-Host "Admin Response Steps:"
Write-Host "1. Detection: Spot failed login spikes in logs."
Write-Host "2. Investigation: Confirm IPs are not from the employee’s usual location."
Write-Host "3. Containment: Disable the account and terminate active sessions."
Write-Host "4. Root Cause: Identify if credentials were stolen or brute-forced."
Write-Host "5. Remediation: Reset password, enforce MFA, block suspicious IPs."
Write-Host "6. Recovery: Monitor for repeat attempts and update access policies."
