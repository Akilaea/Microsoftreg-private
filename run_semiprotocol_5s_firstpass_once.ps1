param(
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Config = ".\config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json",
    [string]$FreshProfilePrefix = "",
    [int]$WallMs = 5000,
    [int]$HoldMs = 13000,
    [int]$StopDelayMs = 900,
    [int]$PreDownDwellMs = 900,
    [int]$PreholdReadinessGateMs = 1800,
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
    [switch]$RiskVerifyChallengeToContinue,
    [switch]$NoRiskVerifyChallengeToContinue,
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

if (-not $FreshProfilePrefix) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $FreshProfilePrefix = "semiprotocol-5s-firstpass-$stamp"
}

$argsList = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\run_1s_protocol_restart_once.ps1",
    "-WallMs", "$WallMs",
    "-HoldMs", "$HoldMs",
    "-StopDelayMs", "$StopDelayMs",
    "-PreDownDwellMs", "$PreDownDwellMs",
    "-Attempts", "1",
    "-RetryAfterMs", "7000",
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
    "-RealTargetWaitMs", "$RealTargetWaitMs",
    "-DelayCaptchaCloseMs", "8000",
    "-CaptchaCloseGraceMs", "3000",
    "-RiskVerifyGateMs", "$RiskVerifyGateMs",
    "-RiskVerifyGateTimeoutMs", "$RiskVerifyGateTimeoutMs",
    "-RiskVerifyHumanSuccessAgeMs", "$RiskVerifyHumanSuccessAgeMs",
    "-RiskVerifyHumanSuccessTimeoutMs", "$RiskVerifyHumanSuccessTimeoutMs"
)

if ($RiskVerifyChallengeToContinue -and -not $NoRiskVerifyChallengeToContinue) {
    $argsList += "-RiskVerifyChallengeToContinue"
}
if ($DryRun) {
    $argsList += "-DryRun"
}

Write-Host "[semiprotocol-5s-firstpass] powershell $($argsList -join ' ')"
powershell @argsList
exit $LASTEXITCODE
