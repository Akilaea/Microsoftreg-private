param(
    [string]$Filter = "US 006|US 008|US 007",
    [int]$MaxNodes = 1,
    [int]$RunsPerNode = 3,
    [int]$MinSuccesses = 3,
    [int]$AliveTimeoutMs = 4500,
    [switch]$NoStopOnRiskBlock,
    [switch]$TriggerFinalSuccessSignals,
    [switch]$SkipPreflight,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[goal-live] filter=$Filter max_nodes=$MaxNodes runs_per_node=$RunsPerNode min_successes=$MinSuccesses dry_run=$($DryRun.IsPresent)"
Write-Host "[goal-live] stop_on_riskblock=$(-not $NoStopOnRiskBlock.IsPresent) trigger_final_success_signals=$($TriggerFinalSuccessSignals.IsPresent) alive_timeout_ms=$AliveTimeoutMs"

if ($DryRun) {
    Write-Host "`n[goal-live] DryRun preflight"
    powershell -ExecutionPolicy Bypass -File .\preflight_1s_live.ps1 `
        -Filter $Filter `
        -MaxNodes $MaxNodes `
        -RunsPerNode $RunsPerNode `
        -MinSuccesses $MinSuccesses `
        -SkipSelfTest
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    Write-Host "`n[goal-live] DryRun yaml/live batch"
    $dryArgs = @(
        "-ExecutionPolicy", "Bypass",
        "-File", ".\run_mihomo_yaml_alive_then_1s.ps1",
        "-Filter", $Filter,
        "-MaxNodes", "$MaxNodes",
        "-RunsPerNode", "$RunsPerNode",
        "-MinSuccesses", "$MinSuccesses",
        "-AliveTimeoutMs", "$AliveTimeoutMs",
        "-DryRun"
    )
    if (-not $NoStopOnRiskBlock) {
        $dryArgs += "-StopOnRiskBlock"
    }
    if ($TriggerFinalSuccessSignals) {
        $dryArgs += "-TriggerFinalSuccessSignals"
    }
    powershell @dryArgs
    exit $LASTEXITCODE
}

if (-not $SkipPreflight) {
    Write-Host "`n[goal-live] preflight"
    powershell -ExecutionPolicy Bypass -File .\preflight_1s_live.ps1 `
        -Filter $Filter `
        -MaxNodes $MaxNodes `
        -RunsPerNode $RunsPerNode `
        -MinSuccesses $MinSuccesses
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[goal-live] preflight failed; aborting before live batch"
        exit $LASTEXITCODE
    }
}

Write-Host "`n[goal-live] live yaml alive + 1s batch"
$liveArgs = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\run_mihomo_yaml_alive_then_1s.ps1",
    "-Filter", $Filter,
    "-MaxNodes", "$MaxNodes",
    "-RunsPerNode", "$RunsPerNode",
    "-MinSuccesses", "$MinSuccesses",
    "-AliveTimeoutMs", "$AliveTimeoutMs"
)
if (-not $NoStopOnRiskBlock) {
    $liveArgs += "-StopOnRiskBlock"
}
if ($TriggerFinalSuccessSignals) {
    $liveArgs += "-TriggerFinalSuccessSignals"
}
powershell @liveArgs
$batchExit = $LASTEXITCODE
Write-Host "[goal-live] live batch exit=$batchExit"

Write-Host "`n[goal-live] final completion audit"
python audit_1s_completion.py
$completionExit = $LASTEXITCODE
if ($completionExit -eq 0) {
    Write-Host "[goal-live] GOAL_COMPLETE_AUDIT_PASS"
    exit 0
}

Write-Host "`n[goal-live] triage latest incomplete result"
python triage_1s_latest.py
exit $completionExit
