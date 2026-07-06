param(
    [string]$CountryLabel = "",
    [string]$ProxyUrl = "",
    [ValidateSet("manual", "trace")]
    [string]$ConfigProfile = "manual",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "careful",
    [string]$FreshProfilePrefix = "cloak1s",
    [int]$WallMs = 900,
    [int]$FakeHoldMs = 9800,
    [int]$Attempts = 3,
    [int]$RetryAfterMs = 9000,
    [int]$FinishedStableMs = 4500,
    [int]$W0AfterFinalMs = 160,
    # The only CreateAccount=200 sample submitted ~116s after the last
    # HumanCaptcha_Success event.  Keep the physical hold at ~1s, but wait
    # long enough for the host page's delayed CreateAccount branch.
    [int]$WaitAfterMs = 130000,
    [switch]$NoTriggerFinalSuccessSignals,
    [switch]$NoSyntheticU0,
    [switch]$OptimisticFinalSuccess,
    [switch]$DeferFinalResultToW0,
    [switch]$NeutralFinalFetchW0,
    [switch]$NeutralFinalMergeW0Success,
    [switch]$NeutralFinalCachedW0Success,
    [switch]$NeutralFinalCachedRichW0Success,
    [switch]$RealFinalNeutralW0Success,
    [switch]$SessionCachedRichFinalSuccess,
    [switch]$SessionCachedRichW0Success,
    [switch]$SessionCachedRichFinalAndW0Success,
    [switch]$WarmupNeutralThenRichFinalAndW0Success,
    [int]$SessionCachedRichInitialW0DelayMs = 2800,
    [int]$DeferW0WaitMs = 7000,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$args = @(
  "-ConfigProfile", $ConfigProfile,
  "-CloakHumanPreset", $CloakHumanPreset,
  "-FreshProfilePrefix", $FreshProfilePrefix,
  "-TimeWarpHoldMs", "$FakeHoldMs",
  "-TimeWarpWallMs", "$WallMs",
  "-TimeWarpStopDelayMs", "250",
  # A collector result0 / HumanCaptcha_Success can be an intermediate state:
  # the host often reloads a second challenge ~1s later, and only submits
  # CreateAccount after the next accepted round.  Keep the 1s physical hold,
  # but allow controlled second/third short holds instead of exiting after the
  # first iframe disappearance.
  "-TimeWarpAttempts", "$Attempts",
  "-TimeWarpRetryAfterMs", "$RetryAfterMs",
  "-TimeWarpFinishedStableMs", "$FinishedStableMs",
  "-W0AfterFinalMs", "$W0AfterFinalMs",
  "-WaitBeforeMs", "26000",
  "-WaitAfterMs", "$WaitAfterMs",
  "-DeferW0WaitMs", "$DeferW0WaitMs",
  "-SessionCachedRichInitialW0DelayMs", "$SessionCachedRichInitialW0DelayMs"
)

if ($CountryLabel) {
  $args += @("-CountryLabel", $CountryLabel)
}

if (-not $DeferFinalResultToW0) {
  $args += "-NoDeferFinalResultToW0"
}

if ($NoSyntheticU0) {
  $args += "-NoSyntheticU0"
}

if ($WarmupNeutralThenRichFinalAndW0Success) {
  $args += "-WarmupNeutralThenRichFinalAndW0Success"
} elseif ($SessionCachedRichFinalAndW0Success) {
  $args += "-SessionCachedRichFinalAndW0Success"
} elseif ($SessionCachedRichW0Success) {
  $args += "-SessionCachedRichW0Success"
} elseif ($SessionCachedRichFinalSuccess) {
  $args += "-SessionCachedRichFinalSuccess"
} elseif ($RealFinalNeutralW0Success) {
  $args += "-RealFinalNeutralW0Success"
} elseif ($NeutralFinalCachedRichW0Success) {
  $args += "-NeutralFinalCachedRichW0Success"
} elseif ($NeutralFinalCachedW0Success) {
  $args += "-NeutralFinalCachedW0Success"
} elseif ($NeutralFinalMergeW0Success) {
  $args += "-NeutralFinalMergeW0Success"
} elseif ($NeutralFinalFetchW0) {
  $args += "-NeutralFinalFetchW0"
} elseif ($OptimisticFinalSuccess) {
  # Local immediate score/result avoids route.fetch latency; useful when the
  # iframe closes status=-1 before the remote collector response can be
  # rewritten.  The normal default remains rewrite-final because it preserves
  # real collector _px3/_pxde when the response arrives in time.
  $args += "-OptimisticFinalSuccess"
} else {
  $args += "-RewriteFinalResultSuccess"
}

if (-not $NoTriggerFinalSuccessSignals) {
  $args += "-TriggerFinalSuccessSignals"
}

if ($ProxyUrl) {
  $args += @("-ProxyUrl", $ProxyUrl)
}

if ($DryRun) {
  Write-Host "[DryRun] powershell -ExecutionPolicy Bypass -File .\run_accel_defer_w0_once.ps1 $($args -join ' ')"
  exit 0
}

powershell -ExecutionPolicy Bypass -File .\run_accel_defer_w0_once.ps1 @args
