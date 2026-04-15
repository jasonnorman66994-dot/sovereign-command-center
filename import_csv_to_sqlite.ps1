# PowerShell: Import CSVs to SQLite for Grafana
# Requires: PowerShell 5+, System.Data.SQLite (install via NuGet if needed)

param(
    [string]$DatabasePath = "email_security.db",
    [string[]]$CsvFiles = @("mail_activity.csv", "login_attempts.csv", "login_events.csv")
)

# Ensure SQLite assembly is loaded
if (-not ([System.AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq "System.Data.SQLite" })) {
    try {
        Add-Type -Path (Join-Path $PSScriptRoot "System.Data.SQLite.dll")
    } catch {
        Write-Error "System.Data.SQLite.dll not found. Download from https://system.data.sqlite.org/index.html/doc/trunk/www/downloads.wiki and place in script directory."
        exit 1
    }
}

function Import-CsvToSqliteTable {
    param(
        [string]$CsvPath,
        [string]$TableName,
        [string]$DbPath
    )
    $csv = Import-Csv $CsvPath
    if ($csv.Count -eq 0) { return }
    $columns = $csv[0].PSObject.Properties.Name
    $colDefs = ($columns | ForEach-Object { "[$_] TEXT" }) -join ", "
    $createTable = "CREATE TABLE IF NOT EXISTS [$TableName] ($colDefs);"
    $conn = New-Object System.Data.SQLite.SQLiteConnection ("Data Source=$DbPath")
    $conn.Open()
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = $createTable
    $cmd.ExecuteNonQuery() | Out-Null
    foreach ($row in $csv) {
        $vals = ($columns | ForEach-Object { $row.$_ -replace '"', '""' })
        $valStr = ($vals | ForEach-Object { '"' + $_ + '"' }) -join ", "
        $insert = "INSERT INTO [$TableName] VALUES ($valStr);"
        $cmd.CommandText = $insert
        $cmd.ExecuteNonQuery() | Out-Null
    }
    $conn.Close()
}

foreach ($csvFile in $CsvFiles) {
    $table = [System.IO.Path]::GetFileNameWithoutExtension($csvFile)
    if (Test-Path $csvFile) {
        Import-CsvToSqliteTable -CsvPath $csvFile -TableName $table -DbPath $DatabasePath
        Write-Host "Imported $csvFile to table $table."
    } else {
        Write-Warning "$csvFile not found. Skipping."
    }
}
Write-Host "All CSVs imported to $DatabasePath."
