param(
    [string]$AliveFile = "",
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    # The 5s stable profile is evidence-driven: recent live runs show Game/US/
    # SG/JP nodes frequently return collector result0 but fail host risk/verify
    # (fresh re-challenge/riskblock).  Prefer Web/Video pools and avoid the
    # noisy regions; callers can still override both filters.
    [string]$Filter = "^(Web|Video) ",
    # Use regex unicode escapes here so Windows PowerShell's legacy code page
    # cannot mojibake the default exclusion when this script shells out.
    [string]$ExcludeFilter = "(\u7F8E\u56FD|\u65B0\u52A0\u5761|\u65E5\u672C|\u6CD5\u56FD)",
    [switch]$UseControllerNodes,
    [int]$MaxNodes = 3,
    [int]$RunsPerNode = 1,
    [int]$TargetSuccessCount = 0,
    [switch]$TargetFirstPass,
    [int]$RegisterTimeoutSec = 330,
    [int]$PauseBetweenRunsSec = 6,
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
    [string]$OutcomeLedger = ".\.mihomo-isolated\protocol1s_outcomes.jsonl",
    [int]$RecentOutcomeWindowMinutes = 360,
    [int]$MaxRecentSuccessesPerIp = 1,
    [string]$QuarantineVerdicts = "riskblock,no_result0,real_w0_no_create,result0_rechallenge,result0_no_create,collector_minus1",
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
    [switch]$ContinueNodeAfterRiskBlock,
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
    "-OutcomeLedger", $OutcomeLedger,
    "-RecentOutcomeWindowMinutes", "$RecentOutcomeWindowMinutes",
    "-MaxRecentSuccessesPerIp", "$MaxRecentSuccessesPerIp",
    "-QuarantineVerdicts", $QuarantineVerdicts,
    "-W0ResponseMode", "real_final_neutral_w0_success",
    "-W0ResponseWaitMs", "$W0ResponseWaitMs"
)

if ($AliveFile) { $argsList += @("-AliveFile", $AliveFile) }
if ($ExcludeFilter) { $argsList += @("-ExcludeFilter", $ExcludeFilter) }
if ($UseControllerNodes) { $argsList += "-UseControllerNodes" }
if ($RiskVerifyChallengeToContinue) { $argsList += "-RiskVerifyChallengeToContinue" }
if ($AllowSecondAttempt) { $argsList += "-AllowSecondAttempt" }
if ($TargetFirstPass) { $argsList += "-TargetFirstPass" }
if ($ContinueNodeAfterRiskBlock) { $argsList += "-ContinueNodeAfterRiskBlock" }
if ($ContinueAfterSuccess) { $argsList += "-ContinueAfterSuccess" }
if ($DryRun) { $argsList += "-DryRun" }

Write-Host "[semiprotocol-5s-batch] powershell $($argsList -join ' ')"
& powershell @argsList
exit $LASTEXITCODE
