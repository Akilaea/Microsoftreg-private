param(
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Config = ".\config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json",
    [string]$FreshProfilePrefix = "",
    [int]$WallMs = 5000,
    [int]$HoldMs = 13000,
    [int]$StopDelayMs = 900,
    [int]$PreDownDwellMs = 900,
    [int]$Attempts = 1,
    [int]$RetryAfterMs = 7000,
    [int]$CaptchaCloseGraceMs = 3000,
    [int]$PreholdReadinessGateMs = 1800,
    [int]$PreholdLoadedMinAgeMs = 0,
    [int]$RealTargetWaitMs = 20000,
    [int]$W0ResponseWaitMs = 3500,
    [int]$RiskVerifyGateMs = 1450,
    [int]$RiskVerifyGateTimeoutMs = 9000,
    [int]$RiskVerifyHumanSuccessAgeMs = 650,
    [int]$RiskVerifyHumanSuccessTimeoutMs = 3000,
    [double]$BotProtectionWaitSec = 0,
    [ValidateSet("outlook", "msal_authorize")]
    [string]$SignupEntryMode = "msal_authorize",
    [ValidateSet("fast_dom", "semi_protocol", "protocol_assist", "protocol_takeover")]
    [string]$SignupFillMode = "protocol_assist",
    [ValidateSet("", "sync", "off", "none", "disabled", "natural")]
    [string]$CheckAvailablePrefetchMode = "",
    [ValidateSet("", "dom_fast", "native", "playwright", "ui")]
    [string]$SubmitMode = "",
    [ValidateSet("", "native", "dom_fast", "playwright", "ui")]
    [string]$NameSubmitMode = "",
    [int]$FastPostEmailWaitMs = -1,
    [int]$FastPrePasswordSubmitWaitMs = -1,
    [int]$FastPostPasswordWaitMs = -1,
    [int]$FastBirthInputSettleMs = -1,
    [int]$FastBirthSelectSettleMs = -1,
    [int]$FastDobReadyWaitMs = -1,
    [int]$FastNameReadyWaitMs = -1,
    [int]$FastNameSubmitWaitMs = -1,
    [int]$FastNameSubmitPollMs = -1,
    [int]$FastLeftNamePageMs = -1,
    [int]$FastPostNameSubmitBufferMs = -1,
    [switch]$RiskVerifyChallengeToContinue,
    [switch]$AllowSecondAttempt,
    [switch]$NoExtractState,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"
if ($CheckAvailablePrefetchMode) {
    $env:OUTLOOK_SIGNUP_CHECK_AVAILABLE_PREFETCH_MODE = $CheckAvailablePrefetchMode
}
if ($SubmitMode) {
    $env:OUTLOOK_SIGNUP_SUBMIT_MODE = $SubmitMode
}
if ($NameSubmitMode) {
    $env:OUTLOOK_SIGNUP_NAME_SUBMIT_MODE = $NameSubmitMode
}
if ($FastPostEmailWaitMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_POST_EMAIL_WAIT_MS = "$FastPostEmailWaitMs" }
if ($FastPrePasswordSubmitWaitMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_PRE_PASSWORD_SUBMIT_WAIT_MS = "$FastPrePasswordSubmitWaitMs" }
if ($FastPostPasswordWaitMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_POST_PASSWORD_WAIT_MS = "$FastPostPasswordWaitMs" }
if ($FastBirthInputSettleMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_BIRTH_INPUT_SETTLE_MS = "$FastBirthInputSettleMs" }
if ($FastBirthSelectSettleMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_BIRTH_SELECT_SETTLE_MS = "$FastBirthSelectSettleMs" }
if ($FastDobReadyWaitMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_DOB_READY_WAIT_MS = "$FastDobReadyWaitMs" }
if ($FastNameReadyWaitMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_NAME_READY_WAIT_MS = "$FastNameReadyWaitMs" }
if ($FastNameSubmitWaitMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_NAME_SUBMIT_WAIT_MS = "$FastNameSubmitWaitMs" }
if ($FastNameSubmitPollMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_NAME_SUBMIT_POLL_MS = "$FastNameSubmitPollMs" }
if ($FastLeftNamePageMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_LEFT_NAME_PAGE_MS = "$FastLeftNamePageMs" }
if ($FastPostNameSubmitBufferMs -ge 0) { $env:OUTLOOK_SIGNUP_FAST_POST_NAME_SUBMIT_BUFFER_MS = "$FastPostNameSubmitBufferMs" }

if (-not $FreshProfilePrefix) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $FreshProfilePrefix = "semiprotocol-5s-$stamp"
}

$argsList = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\run_1s_protocol_restart_once.ps1",
    "-WallMs", "$WallMs",
    "-HoldMs", "$HoldMs",
    "-StopDelayMs", "$StopDelayMs",
    "-PreDownDwellMs", "$PreDownDwellMs",
    "-Attempts", "$Attempts",
    "-RetryAfterMs", "$RetryAfterMs",
    "-BotProtectionWaitSec", "$BotProtectionWaitSec",
    "-SignupEntryMode", $SignupEntryMode,
    "-SignupFillMode", $SignupFillMode,
    "-ProxyUrl", $ProxyUrl,
    "-Config", $Config,
    "-FreshProfilePrefix", $FreshProfilePrefix,
    "-FinalProofNormalizer", "ads_safe",
    "-W0Policy", "after160",
    "-W0ResponseMode", "real_final_neutral_w0_success",
    "-W0ResponseWaitMs", "$W0ResponseWaitMs",
    "-NoSyntheticU0",
    "-HybridLegacyDownCdpMoveUp",
    "-LegacyShortHoldSteps", "24",
    "-RequireChctxRuntimeReady",
    "-MinRuntimeHookReadyFrames", "6",
    "-MinKnpPrestartOk", "5",
    "-PreholdHookGuardRetries", "2",
    "-PreholdReadinessGateMs", "$PreholdReadinessGateMs",
    "-PreholdLoadedMinAgeMs", "$PreholdLoadedMinAgeMs",
    "-RealTargetWaitMs", "$RealTargetWaitMs",
    "-DelayCaptchaCloseMs", "8000",
    "-CaptchaCloseGraceMs", "$CaptchaCloseGraceMs",
    "-RiskVerifyGateMs", "$RiskVerifyGateMs",
    "-RiskVerifyGateTimeoutMs", "$RiskVerifyGateTimeoutMs",
    "-RiskVerifyHumanSuccessAgeMs", "$RiskVerifyHumanSuccessAgeMs",
    "-RiskVerifyHumanSuccessTimeoutMs", "$RiskVerifyHumanSuccessTimeoutMs"
)

if ($RiskVerifyChallengeToContinue) {
    $argsList += "-RiskVerifyChallengeToContinue"
}
if ($AllowSecondAttempt) {
    $argsList += "-AllowSecondAttempt"
}
if ($DryRun) {
    $argsList += "-DryRun"
}

Write-Host "[semiprotocol-5s] powershell $($argsList -join ' ')"
powershell @argsList
$childExit = $LASTEXITCODE

if (-not $DryRun -and -not $NoExtractState) {
    try {
        $latestNetwork = Get-ChildItem -LiteralPath ".\Results\network" -Filter "*.jsonl" -ErrorAction Stop |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        $latestRoute = $null
        if ($latestNetwork -and $latestNetwork.BaseName.Length -ge 15) {
            $netPrefix = $latestNetwork.BaseName.Substring(0, 15)
            $latestRoute = Get-ChildItem -LiteralPath ".\Results\protocol_runtime" -Filter "$netPrefix*_route_normalizer.jsonl" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
        }
        if (-not $latestRoute) {
            $windowStart = if ($latestNetwork) { $latestNetwork.LastWriteTime.AddMinutes(-8) } else { (Get-Date).AddMinutes(-8) }
            $windowEnd = if ($latestNetwork) { $latestNetwork.LastWriteTime.AddMinutes(2) } else { (Get-Date).AddMinutes(2) }
            $latestRoute = Get-ChildItem -LiteralPath ".\Results\protocol_runtime" -Filter "*_route_normalizer.jsonl" -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $windowStart -and $_.LastWriteTime -le $windowEnd } |
                Sort-Object LastWriteTime -Descending |
                Select-Object -First 1
        }
        if ($latestNetwork) {
            $extractArgs = @(".\extract_semiprotocol_state.py", $latestNetwork.FullName)
            if ($latestRoute) { $extractArgs += @("--route", $latestRoute.FullName) }
            Write-Host "[semiprotocol-5s] extracting state: python $($extractArgs -join ' ')"
            python @extractArgs
        }
    } catch {
        Write-Host "[semiprotocol-5s] state extraction failed: $($_.Exception.Message)"
    }
}

exit $childExit
