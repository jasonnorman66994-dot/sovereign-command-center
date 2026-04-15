param(
    [ValidateSet('Quick', 'Full')]
    [string]$Mode = 'Quick'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $repoRoot

$pythonExe = Join-Path $repoRoot '.venv\Scripts\python.exe'
if (-not (Test-Path $pythonExe)) {
    throw "Python virtual environment not found at $pythonExe"
}

Write-Host "Running smoke check in $Mode mode"

$quickMarkdownTargets = @('scenario*.md', 'multi_scenario_chain_timeline.md')
$quickMarkdownTargetsCli2 = @('scenario*.md', 'multi_scenario_chain_timeline.md')
$fullMarkdownTargetsCli2 = @(
    '**/*.md',
    '!**/node_modules/**',
    '!**/build/**',
    '!**/.venv/**',
    '!**/.zhanlu/**',
    '!**/sovereign-hud/build/**',
    '!advanced_dashboard_panels.md',
    '!campaign_launcher_manifest.md',
    '!chain_kpis.md',
    '!custom_reporting_template.md',
    '!dashboard_auto_refresh.md',
    '!dashboard_templates.md',
    '!drilldown_report.md',
    '!EMAIL_SECURITY_DOCS_INDEX.md',
    '!email_spam_incident_response_checklist.md',
    '!email_threat_evaluation_rubric.md',
    '!end_of_day_executive_summary_template.md',
    '!executive_summary.md',
    '!extracted_emails.md',
    '!grafana_data_source_setup.md',
    '!injects_and_scenarios_expanded.md',
    '!mission_control_deck.md',
    '!mission_control_presentation.md',
    '!mission_control_report.md',
    '!red_team_deliverable_package.md',
    '!multi_scenario_analytics_dashboard.md',
    '!siem_automation_guide.md',
    '!siem_rule_templates_oauth_abuse.md',
    '!sim_insider_exfiltration_summary.md',
    '!TODO.md',
    '!unified_email_threat_response_playbook.md'
)
$fullMarkdownExcludePattern = @(
    '\\.venv\\',
    '\\node_modules\\',
    '\\build\\',
    '\\.zhanlu\\',
    '\\sovereign-hud\\build\\',
    'advanced_dashboard_panels\.md$',
    'campaign_launcher_manifest\.md$',
    'chain_kpis\.md$',
    'custom_reporting_template\.md$',
    'dashboard_auto_refresh\.md$',
    'dashboard_templates\.md$',
    'drilldown_report\.md$',
    'EMAIL_SECURITY_DOCS_INDEX\.md$',
    'email_spam_incident_response_checklist\.md$',
    'email_threat_evaluation_rubric\.md$',
    'end_of_day_executive_summary_template\.md$',
    'executive_summary\.md$',
    'extracted_emails\.md$',
    'grafana_data_source_setup\.md$',
    'injects_and_scenarios_expanded\.md$',
    'mission_control_deck\.md$',
    'mission_control_presentation\.md$',
    'mission_control_report\.md$',
    'red_team_deliverable_package\.md$'
)

Write-Host '[1/3] Regenerating timeline markdown...'
& $pythonExe 'generate_timeline.py'
if ($LASTEXITCODE -ne 0) {
    throw 'Timeline generation failed.'
}

$markdownlint = Get-Command 'markdownlint' -ErrorAction SilentlyContinue
$markdownlintCli2 = Get-Command 'markdownlint-cli2' -ErrorAction SilentlyContinue

if ($markdownlintCli2) {
    Write-Host '[2/3] Running markdownlint-cli2...'
    if ($Mode -eq 'Full') {
        & $markdownlintCli2.Source '--no-globs' @fullMarkdownTargetsCli2
    }
    else {
        & $markdownlintCli2.Source '--no-globs' @quickMarkdownTargetsCli2
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'markdownlint-cli2 reported issues.'
    }
}
elseif ($markdownlint) {
    Write-Host '[2/3] Running markdownlint...'
    if ($Mode -eq 'Full') {
        $fullMarkdownFiles = Get-ChildItem -Path $repoRoot -Recurse -File -Filter '*.md' |
        Where-Object {
            $filePath = $_.FullName
            ($fullMarkdownExcludePattern | Where-Object { $filePath -match $_ }).Count -eq 0
        } |
        Select-Object -ExpandProperty FullName

        & $markdownlint.Source @fullMarkdownFiles
    }
    else {
        & $markdownlint.Source @quickMarkdownTargets
    }
    if ($LASTEXITCODE -ne 0) {
        throw 'markdownlint reported issues.'
    }
}
else {
    Write-Host '[2/3] Markdown lint skipped: markdownlint is not installed.'
}

Write-Host '[3/3] Validating Python syntax...'
$pythonFiles = Get-ChildItem -Path $repoRoot -Recurse -File -Filter '*.py' |
Where-Object {
    $_.FullName -notmatch '\\.venv\\' -and
    $_.FullName -notmatch '\\node_modules\\' -and
    $_.FullName -notmatch '\\build\\' -and
    $_.FullName -notmatch '\\shadow_toolkit\.egg-info\\'
}

$failedSyntaxChecks = @()
foreach ($pythonFile in $pythonFiles) {
    & $pythonExe -m py_compile $pythonFile.FullName
    if ($LASTEXITCODE -ne 0) {
        $failedSyntaxChecks += $pythonFile.FullName
    }
}

if ($failedSyntaxChecks.Count -gt 0) {
    $failedList = $failedSyntaxChecks -join "`n"
    throw "Python syntax validation failed for:`n$failedList"
}

Write-Host 'Smoke check passed.'
