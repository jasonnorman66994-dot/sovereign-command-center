param(
    [string]$Server = "http://localhost:8080",
    [string]$Realm = "shadow-realm",
    [string]$ClientId = "shadow-toolz-dashboard",
    [string]$AdminUser = "admin",
    [Parameter(Mandatory = $true)][SecureString]$AdminPassword,
    [string]$OperatorUser = "operator",
    [string]$OperatorPassword = "Operator123!"
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

$adminPasswordPlain = [System.Net.NetworkCredential]::new("", $AdminPassword).Password
try {
    Invoke-KcAdm config credentials --server $Server --realm master --user $AdminUser --password $adminPasswordPlain | Out-Null

    # Ensure realm exists
    try {
        Invoke-KcAdm get "realms/$Realm" | Out-Null
    }
    catch {
        Invoke-KcAdm create realms -s "realm=$Realm" -s enabled=true | Out-Null
    }

    # Ensure dashboard client exists
    $client = ((Invoke-KcAdm get clients -r $Realm -q "clientId=$ClientId" | Out-String) | ConvertFrom-Json | Select-Object -First 1)
    if (-not $client) {
        $tmpClient = Join-Path $env:TEMP "shadow-client.json"
        @"
{
  "clientId": "$ClientId",
  "publicClient": true,
  "standardFlowEnabled": true,
  "directAccessGrantsEnabled": true,
  "redirectUris": ["http://localhost:8055/*", "http://localhost:8055/"],
  "webOrigins": ["http://localhost:8055", "http://127.0.0.1:8055"]
}
"@ | Set-Content -Path $tmpClient -Encoding ascii
        Invoke-KcAdm create clients -r $Realm -f $tmpClient | Out-Null
        $client = ((Invoke-KcAdm get clients -r $Realm -q "clientId=$ClientId" | Out-String) | ConvertFrom-Json | Select-Object -First 1)
    }

    if (-not $client -or -not $client.id) {
        throw "Unable to resolve client id for '$ClientId' in realm '$Realm'."
    }
    $clientId = $client.id

    # Ensure audience mapper exists
    $mappers = ((Invoke-KcAdm get clients/$clientId/protocol-mappers/models -r $Realm | Out-String) | ConvertFrom-Json)
    if (-not ($mappers | Where-Object { $_.name -eq "aud-shadow-toolz" })) {
        $tmpAud = Join-Path $env:TEMP "mapper-aud.json"
        @"
{
  "name": "aud-shadow-toolz",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-audience-mapper",
  "config": {
    "included.client.audience": "shadow-toolz",
    "id.token.claim": "false",
    "access.token.claim": "true"
  }
}
"@ | Set-Content -Path $tmpAud -Encoding ascii
        Invoke-KcAdm create clients/$clientId/protocol-mappers/models -r $Realm -f $tmpAud | Out-Null
    }

    # Ensure role-based security_clearance mapper exists
    $mappers = ((Invoke-KcAdm get clients/$clientId/protocol-mappers/models -r $Realm | Out-String) | ConvertFrom-Json)
    if (-not ($mappers | Where-Object { $_.name -eq "security_clearance_from_role" })) {
        $tmpClearance = Join-Path $env:TEMP "mapper-clearance-role.json"
        @"
{
  "name": "security_clearance_from_role",
  "protocol": "openid-connect",
  "protocolMapper": "oidc-usermodel-realm-role-mapper",
  "config": {
    "claim.name": "security_clearance",
    "jsonType.label": "int",
    "multivalued": "false",
    "id.token.claim": "true",
    "access.token.claim": "true",
    "userinfo.token.claim": "true"
  }
}
"@ | Set-Content -Path $tmpClearance -Encoding ascii
        Invoke-KcAdm create clients/$clientId/protocol-mappers/models -r $Realm -f $tmpClearance | Out-Null
    }

    # Ensure role "3" exists
    $roles = ((Invoke-KcAdm get roles -r $Realm | Out-String) | ConvertFrom-Json)
    if (-not ($roles | Where-Object { $_.name -eq "3" })) {
        Invoke-KcAdm create roles -r $Realm -s name=3 | Out-Null
    }

    # Ensure operator user exists
    $user = ((Invoke-KcAdm get users -r $Realm -q "username=$OperatorUser" | Out-String) | ConvertFrom-Json | Select-Object -First 1)
    if (-not $user) {
        Invoke-KcAdm create users -r $Realm -s "username=$OperatorUser" -s enabled=true | Out-Null
        $user = ((Invoke-KcAdm get users -r $Realm -q "username=$OperatorUser" | Out-String) | ConvertFrom-Json | Select-Object -First 1)
    }

    if (-not $user -or -not $user.id) {
        throw "Unable to resolve user id for '$OperatorUser' in realm '$Realm'."
    }

    # Set user profile + password + role
    Invoke-KcAdm update users/$($user.id) -r $Realm -s firstName=SOC -s lastName=Operator -s email=operator@shadow.local -s emailVerified=true -s enabled=true -s requiredActions=[] | Out-Null
    Invoke-KcAdm set-password -r $Realm --username $OperatorUser --new-password $OperatorPassword | Out-Null
    Invoke-KcAdm add-roles -r $Realm --uusername $OperatorUser --rolename 3 | Out-Null

    Write-Host "RESEED_OK"
    Write-Host "Realm=$Realm"
    Write-Host "Client=$ClientId"
    Write-Host "OperatorUser=$OperatorUser"
}
finally {
    $adminPasswordPlain = $null
}
