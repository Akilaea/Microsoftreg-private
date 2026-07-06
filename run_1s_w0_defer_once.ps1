param(
    [string]$CountryLabel = "",
    [string]$ProxyUrl = "",
    [ValidateSet("manual", "trace")]
    [string]$ConfigProfile = "manual",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "careful",
    [string]$FreshProfilePrefix = "cloak1sw0",
    [int]$WallMs = 900,
    [int]$FakeHoldMs = 9800,
    [int]$Attempts = 3,
    [int]$RetryAfterMs = 9000,
    [int]$FinishedStableMs = 4500,
    [int]$WaitAfterMs = 45000,
    [int]$DeferW0WaitMs = 3500,
    [switch]$TriggerFinalSuccessSignals,
    # Compatibility with mihomo_auto_proxy_test.py's generic flags.  This
    # script intentionally hard-codes the current best variant; these switches
    # are accepted so generic batch commands do not fail on unknown parameters.
    [switch]$NoTriggerFinalSuccessSignals,
    [switch]$OptimisticFinalSuccess,
    [switch]$RewriteFinalResultSuccess,
    [switch]$NoDeferFinalResultToW0,
    [switch]$DeferFinalResultToW0,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# Latest 1s candidate:
# - keep the real physical hold around 0.9s;
# - locally acknowledge the final PX561 quickly to avoid iframe status=-1;
# - defer the actual result0 to W0, matching the only known CreateAccount 200
#   trace where host submission happened after final->W0 result0 rather than
#   after an early final-only success.
$args = @(
  "-ConfigProfile", $ConfigProfile,
  "-CloakHumanPreset", $CloakHumanPreset,
  "-FreshProfilePrefix", $FreshProfilePrefix,
  "-WallMs", "$WallMs",
  "-FakeHoldMs", "$FakeHoldMs",
  "-Attempts", "$Attempts",
  "-RetryAfterMs", "$RetryAfterMs",
  "-FinishedStableMs", "$FinishedStableMs",
  "-WaitAfterMs", "$WaitAfterMs",
  "-OptimisticFinalSuccess",
  "-DeferFinalResultToW0",
  "-DeferW0WaitMs", "$DeferW0WaitMs",
  "-NoTriggerFinalSuccessSignals"
)

if ($CountryLabel) {
  $args += @("-CountryLabel", $CountryLabel)
}

if ($ProxyUrl) {
  $args += @("-ProxyUrl", $ProxyUrl)
}

if ($TriggerFinalSuccessSignals) {
  # Mostly for A/B experiments.  The default is intentionally off because the
  # synthetic host callbacks caused premature reload/stale-frame behavior in
  # the latest comparison runs.
  $args = $args | Where-Object { $_ -ne "-NoTriggerFinalSuccessSignals" }
  # run_1s_rewrite_once.ps1 triggers success signals by default unless
  # -NoTriggerFinalSuccessSignals is present, so do not pass an unsupported
  # -TriggerFinalSuccessSignals parameter through.
}

if ($DryRun) {
  $args += "-DryRun"
}

powershell -ExecutionPolicy Bypass -File .\run_1s_rewrite_once.ps1 @args
