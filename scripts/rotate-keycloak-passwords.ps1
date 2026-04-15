param(
    [Parameter(Mandatory = $true)][string]$CurrentAdminPassword,
    [Parameter(Mandatory = $true)][string]$NewAdminPassword,
    [Parameter(Mandatory = $true)][string]$NewOperatorPassword,
    [string]$Server = "http://localhost:8080",
    [string]$Realm = "shadow-realm",
    [string]$AdminUser = "admin",
    [string]$OperatorUser = "operator"
)

$ErrorActionPreference = "Stop"
$kcBin = "$env:USERPROFILE\tools\keycloak-dist\keycloak-26.6.0\bin"
$env:JAVA_HOME = "$env:USERPROFILE\tools\jdk\jdk-17.0.18+8"
$env:Path = "$env:JAVA_HOME\bin;$env:Path"

function Invoke-KcAdm {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)

    $output = & "$kcBin\kcadm.bat" @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $outputStr = ($output | Out-String).Trim()
    if ($exitCode -ne 0 -or $outputStr -match 'Session has expired|Invalid user credentials|The syntax of the command is incorrect|Expected parameter for option|^Usage: kcadm\.bat|Try ''kcadm\.bat') {
        throw "kcadm failed (exit=$exitCode): $($Arguments -join ' ')`n$outputStr"
    }

    return $output
}

if ($NewAdminPassword -match '^<.*>$' -or $NewOperatorPassword -match '^<.*>$') {
    throw "Replace placeholder values (for example '<new-admin-pw>') with real passwords before running this script."
}

# Authenticate with current admin credentials
Invoke-KcAdm config credentials --server $Server --realm master --user $AdminUser --password $CurrentAdminPassword | Out-Null

# Rotate operator password
Invoke-KcAdm set-password -r $Realm --username $OperatorUser --new-password $NewOperatorPassword | Out-Null
Write-Host "OPERATOR_ROTATED"

# Rotate admin password (do this last — auth context becomes invalid after)
Invoke-KcAdm set-password -r master --username $AdminUser --new-password $NewAdminPassword | Out-Null
Write-Host "ADMIN_ROTATED"

Write-Host "ROTATE_OK"
Write-Host "NewAdminPassword=$NewAdminPassword"
Write-Host "NewOperatorPassword=$NewOperatorPassword"
