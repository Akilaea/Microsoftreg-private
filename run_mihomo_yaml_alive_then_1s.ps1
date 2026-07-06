param(
    [string]$Config = ".mihomo-isolated\config.yaml",
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Filter = "US 006|US 008|US 007",
    [string]$ExcludeFilter = "SG001|GB006|FR 001",
    [int]$AliveTimeoutMs = 4500,
    [int]$MaxAliveNodes = 0,
    [int]$MaxNodes = 1,
    [int]$RunsPerNode = 3,
    [int]$MinSuccesses = 3,
    [switch]$StopOnRiskBlock,
    [switch]$TriggerFinalSuccessSignals,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

Write-Host "[yaml-live] config=$Config controller=$Controller group=$Group proxy=$ProxyUrl"
Write-Host "[yaml-live] filter=$Filter exclude_filter=$ExcludeFilter max_nodes=$MaxNodes runs_per_node=$RunsPerNode min_successes=$MinSuccesses dry_run=$($DryRun.IsPresent)"

if ($DryRun) {
    Write-Host "`n[yaml-live] DryRun: would refresh alive_*.json from YAML, then run batch from the refreshed alive file."
    Write-Host "[yaml-live] python .\mihomo_yaml_alive_probe.py --config $Config --controller $Controller --group $Group --proxy-url $ProxyUrl --filter `"$Filter`" --timeout-ms $AliveTimeoutMs"
    $dryBatchArgs = @(
        "-ExecutionPolicy", "Bypass",
        "-File", ".\run_mihomo_us_1s_batch.ps1",
        "-Filter", $Filter,
        "-ExcludeFilter", $ExcludeFilter,
        "-MaxNodes", "$MaxNodes",
        "-RunsPerNode", "$RunsPerNode",
        "-MinSuccesses", "$MinSuccesses",
        "-DryRun",
        "-SkipSelfTest"
    )
    if ($StopOnRiskBlock) {
        $dryBatchArgs += "-StopOnRiskBlock"
    }
    if ($TriggerFinalSuccessSignals) {
        $dryBatchArgs += "-TriggerFinalSuccessSignals"
    }
    powershell @dryBatchArgs
    exit $LASTEXITCODE
}

Write-Host "`n[yaml-live] refreshing alive list from current YAML"
$aliveArgs = @(
    ".\mihomo_yaml_alive_probe.py",
    "--config", $Config,
    "--controller", $Controller,
    "--group", $Group,
    "--proxy-url", $ProxyUrl,
    "--filter", $Filter,
    "--timeout-ms", "$AliveTimeoutMs"
)
if ($MaxAliveNodes -gt 0) {
    $aliveArgs += @("--max-nodes", "$MaxAliveNodes")
}
python @aliveArgs
if ($LASTEXITCODE -ne 0) {
    throw "YAML alive probe failed"
}

Write-Host "`n[yaml-live] running 1s stability batch using refreshed alive file"
$batchArgs = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\run_mihomo_us_1s_batch.ps1",
    "-Filter", $Filter,
    "-ExcludeFilter", $ExcludeFilter,
    "-Controller", $Controller,
    "-Group", $Group,
    "-ProxyUrl", $ProxyUrl,
    "-MaxNodes", "$MaxNodes",
    "-RunsPerNode", "$RunsPerNode",
    "-MinSuccesses", "$MinSuccesses"
)
if ($StopOnRiskBlock) {
    $batchArgs += "-StopOnRiskBlock"
}
if ($TriggerFinalSuccessSignals) {
    $batchArgs += "-TriggerFinalSuccessSignals"
}

powershell @batchArgs
exit $LASTEXITCODE
