param(
    [string]$AliveFile = "",
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Filter = "^(Game|Web) ",
    [string]$ExcludeFilter = "",
    [switch]$UseControllerNodes,
    [int]$MaxNodes = 5,
    [int]$RunsPerNode = 1,
    [int]$RegisterTimeoutSec = 330,
    [int]$PauseBetweenRunsSec = 6,
    [int]$TargetSuccessCount = 0,
    [int]$WallMs = 5000,
    [int]$HoldMs = 13000,
    [int]$PreholdReadinessGateMs = 1800,
    [int]$RealTargetWaitMs = 20000,
    [int]$W0ResponseWaitMs = 3500,
    [int]$RiskVerifyGateMs = 1450,
    [int]$RiskVerifyGateTimeoutMs = 9000,
    [int]$RiskVerifyHumanSuccessAgeMs = 650,
    [int]$RiskVerifyHumanSuccessTimeoutMs = 3000,
    [ValidateSet("fast_dom", "semi_protocol", "protocol_assist", "protocol_takeover", "protocol_takeover_thin")]
    [string]$SignupFillMode = "protocol_assist",
    [ValidateSet("", "sync", "off", "none", "disabled", "natural")]
    [string]$CheckAvailablePrefetchMode = "",
    [ValidateSet("", "dom_fast", "native", "playwright", "ui")]
    [string]$SubmitMode = "",
    [ValidateSet("", "native", "dom_fast", "playwright", "ui")]
    [string]$NameSubmitMode = "",
    [switch]$RiskVerifyChallengeToContinue,
    [switch]$ContinueAfterSuccess,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
if ($CheckAvailablePrefetchMode) {
    $env:OUTLOOK_SIGNUP_CHECK_AVAILABLE_PREFETCH_MODE = $CheckAvailablePrefetchMode
}
if ($SubmitMode) {
    $env:OUTLOOK_SIGNUP_SUBMIT_MODE = $SubmitMode
}
if ($NameSubmitMode) {
    $env:OUTLOOK_SIGNUP_NAME_SUBMIT_MODE = $NameSubmitMode
}

$argsList = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\run_mihomo_protocol1s_batch.ps1",
    "-Controller", $Controller,
    "-Group", $Group,
    "-ProxyUrl", $ProxyUrl,
    "-Filter", $Filter,
    "-MaxNodes", "$MaxNodes",
    "-RunsPerNode", "$RunsPerNode",
    "-RegisterTimeoutSec", "$RegisterTimeoutSec",
    "-PauseBetweenRunsSec", "$PauseBetweenRunsSec",
    "-TargetSuccessCount", "$TargetSuccessCount",
    "-WallMs", "$WallMs",
    "-HoldMs", "$HoldMs",
    "-StopDelayMs", "900",
    "-PreDownDwellMs", "900",
    "-BotProtectionWaitSec", "0",
    "-SignupEntryMode", "msal_authorize",
    "-SignupFillMode", $SignupFillMode,
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
    "-RiskVerifyHumanSuccessTimeoutMs", "$RiskVerifyHumanSuccessTimeoutMs",
    "-W0ResponseMode", "real_final_neutral_w0_success",
    "-W0ResponseWaitMs", "$W0ResponseWaitMs",
    "-TargetFirstPass"
)

if ($AliveFile) { $argsList += @("-AliveFile", $AliveFile) }
if ($ExcludeFilter) { $argsList += @("-ExcludeFilter", $ExcludeFilter) }
if ($UseControllerNodes) { $argsList += "-UseControllerNodes" }
if ($RiskVerifyChallengeToContinue) { $argsList += "-RiskVerifyChallengeToContinue" }
if ($ContinueAfterSuccess) { $argsList += "-ContinueAfterSuccess" }
if ($DryRun) { $argsList += "-DryRun" }

Write-Host "[semiprotocol-5s-firstpass-batch] powershell $($argsList -join ' ')"
& powershell @argsList
exit $LASTEXITCODE
