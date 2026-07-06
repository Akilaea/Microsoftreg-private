param(
    [string]$AliveFile = "",
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Filter = "iKuuu_V2",
    [string]$ExcludeFilter = "",
    [switch]$UseControllerNodes,
    [int]$MaxNodes = 5,
    [int]$RunsPerNode = 1,
    [int]$TargetSuccessCount = 1,
    [int]$RegisterTimeoutSec = 360,
    [int]$PauseBetweenRunsSec = 4,
    [int]$WallMs = 5000,
    [int]$HoldMs = 13000,
    [int]$W0ResponseWaitMs = 3500,
    [int]$RiskVerifyGateMs = 1450,
    [int]$RiskVerifyGateTimeoutMs = 9000,
    [int]$RiskVerifyHumanSuccessAgeMs = 650,
    [int]$RiskVerifyHumanSuccessTimeoutMs = 3000,
    [int]$ThinBootstrapWaitMs = 12000,
    [int]$PreverifyMinTotalMs = 12000,
    [ValidateSet("api", "page_fetch")]
    [string]$PreverifyTransport = "page_fetch",
    [ValidateSet("commit", "domcontentloaded", "load", "networkidle")]
    [string]$ThinGotoWaitUntil = "commit",
    [switch]$ContinueAfterSuccess,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$env:OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_BOOTSTRAP_WAIT_MS = "$ThinBootstrapWaitMs"
$env:OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_THIN_GOTO_WAIT_UNTIL = $ThinGotoWaitUntil
# Thin bootstrap reaches canary/uaid much earlier than the full page.  In live
# A/B testing, sending the first risk/verify immediately produced frequent
# pre-captcha riskBlock.  Hold the preverify until the total flow age resembles
# the known-good V1 sample, and use page_fetch so the request originates from
# the page context instead of an isolated APIRequestContext.
$env:OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_MIN_TOTAL_MS = "$PreverifyMinTotalMs"
$env:OUTLOOK_SIGNUP_PROTOCOL_TAKEOVER_PREVERIFY_TRANSPORT = $PreverifyTransport

$argsList = @(
    "-ExecutionPolicy", "Bypass",
    "-File", ".\run_mihomo_protocol1s_batch.ps1",
    "-Controller", $Controller,
    "-Group", $Group,
    "-ProxyUrl", $ProxyUrl,
    "-Filter", $Filter,
    "-MaxNodes", "$MaxNodes",
    "-RunsPerNode", "$RunsPerNode",
    "-TargetSuccessCount", "$TargetSuccessCount",
    "-RegisterTimeoutSec", "$RegisterTimeoutSec",
    "-PauseBetweenRunsSec", "$PauseBetweenRunsSec",
    "-WallMs", "$WallMs",
    "-HoldMs", "$HoldMs",
    "-StopDelayMs", "900",
    "-PreDownDwellMs", "900",
    "-SignupEntryMode", "msal_authorize",
    "-SignupFillMode", "protocol_takeover_thin",
    "-MinRuntimeHookReadyFrames", "6",
    "-MinKnpPrestartOk", "5",
    "-PreholdHookGuardRetries", "2",
    "-PreholdReadinessGateMs", "1800",
    "-RealTargetWaitMs", "20000",
    "-DelayCaptchaCloseMs", "8000",
    "-CaptchaCloseGraceMs", "3000",
    "-RiskVerifyGateMs", "$RiskVerifyGateMs",
    "-RiskVerifyGateTimeoutMs", "$RiskVerifyGateTimeoutMs",
    "-RiskVerifyHumanSuccessAgeMs", "$RiskVerifyHumanSuccessAgeMs",
    "-RiskVerifyHumanSuccessTimeoutMs", "$RiskVerifyHumanSuccessTimeoutMs",
    "-W0ResponseMode", "real_final_neutral_w0_success",
    "-W0ResponseWaitMs", "$W0ResponseWaitMs"
)

if ($AliveFile) { $argsList += @("-AliveFile", $AliveFile) }
if ($ExcludeFilter) { $argsList += @("-ExcludeFilter", $ExcludeFilter) }
if ($UseControllerNodes) { $argsList += "-UseControllerNodes" }
if ($ContinueAfterSuccess) { $argsList += "-ContinueAfterSuccess" }
if ($DryRun) { $argsList += "-DryRun" }

Write-Host "[protocol-takeover-thin-batch] env preverify_transport=$PreverifyTransport preverify_min_total_ms=$PreverifyMinTotalMs thin_wait=$ThinBootstrapWaitMs goto=$ThinGotoWaitUntil"
Write-Host "[protocol-takeover-thin-batch] powershell $($argsList -join ' ')"
& powershell @argsList
exit $LASTEXITCODE
