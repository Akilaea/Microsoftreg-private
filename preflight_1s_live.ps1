param(
    [string]$Filter = "US 006",
    [int]$MaxNodes = 1,
    [int]$RunsPerNode = 3,
    [int]$MinSuccesses = 3,
    [switch]$SkipSelfTest
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[preflight] 1s live readiness check"
Write-Host "[preflight] filter=$Filter max_nodes=$MaxNodes runs_per_node=$RunsPerNode min_successes=$MinSuccesses"

if (-not $SkipSelfTest) {
    Write-Host "`n[preflight] offline selftest"
    python selftest_1s_offline.py
    if ($LASTEXITCODE -ne 0) {
        throw "offline selftest failed"
    }
}

Write-Host "`n[preflight] status"
$statusArgs = @("status_1s_repro.py")
if ($SkipSelfTest) {
    $statusArgs += "--skip-selftest"
}
python @statusArgs
if ($LASTEXITCODE -ne 0) {
    if ($SkipSelfTest) {
        Write-Host "[preflight] status reported not ready; continuing because -SkipSelfTest was requested"
    } else {
        throw "status_1s_repro.py failed"
    }
}

Write-Host "`n[preflight] batch dry-run"
powershell -ExecutionPolicy Bypass -File .\run_mihomo_us_1s_batch.ps1 `
    -Filter $Filter `
    -MaxNodes $MaxNodes `
    -RunsPerNode $RunsPerNode `
    -MinSuccesses $MinSuccesses `
    -StopOnRiskBlock `
    -DryRun `
    -SkipSelfTest
if ($LASTEXITCODE -ne 0) {
    throw "batch dry-run failed"
}

Write-Host "`n[preflight] OK: local scripts and parameters are ready; no live registration was executed."
