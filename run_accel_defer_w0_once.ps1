param(
    [ValidateSet("manual", "trace")]
    [string]$ConfigProfile = "manual",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "careful",
    [string]$CountryLabel = "",
    [string]$ProxyUrl = "",
    [int]$W0AfterFinalMs = 160,
    [int]$DeferW0WaitMs = 2500,
    [int]$TimeWarpHoldMs = 9800,
    [int]$TimeWarpWallMs = 9000,
    [int]$TimeWarpStopDelayMs = 300,
    [int]$TimeWarpAttempts = 2,
    [int]$TimeWarpRetryAfterMs = 6500,
    [int]$TimeWarpFinishedStableMs = 2200,
    [int]$WaitBeforeMs = 32000,
    [int]$WaitAfterMs = 36000,
    # Keep automated Cloak launches close to the manual open_outlook.py baseline:
    # every run gets a brand-new profile instead of reusing
    # C:\Users\wdnmd\ZCodeProject\outlook_profile, which was observed to trip
    # the pre-captcha RiskBlock path.
    [string]$FreshProfilePrefix = "cloakauto",
    [switch]$CloakNoViewport,
    [switch]$NoDeferFinalResultToW0,
    [switch]$NoSyntheticU0,
    [switch]$PreserveFinalBfa,
    [switch]$OptimisticW0Success,
    [switch]$OptimisticFinalSuccess,
    [switch]$RewriteFinalResultSuccess,
    [switch]$NeutralFinalFetchW0,
    [switch]$NeutralFinalMergeW0Success,
    [switch]$NeutralFinalCachedW0Success,
    [switch]$NeutralFinalCachedRichW0Success,
    [switch]$RealFinalNeutralW0Success,
    [switch]$SessionCachedRichFinalSuccess,
    [switch]$SessionCachedRichW0Success,
    [switch]$SessionCachedRichFinalAndW0Success,
    [switch]$WarmupNeutralThenRichFinalAndW0Success,
    [int]$SessionCachedRichInitialW0DelayMs = 0,
    [switch]$TriggerFinalSuccessSignals
)

$ErrorActionPreference = "Stop"

$config = if ($ConfigProfile -eq "manual") {
  "config.ctf.cloak_manual_profile.json"
} else {
  "config.ctf.protocol_trace.json"
}

$cmd = @(
  "protocol_runtime_probe.py",
  "--config", $config,
  "--use-cloakbrowser",
  "--cloak-human-preset", $CloakHumanPreset,
  "--mode", "time_warp_hold",
  "--route-only-hook",
  "--defer-route-hook-until-proof",
  "--normalize-y1nz-preproof",
  "--final-proof-normalizer", "minimal",
  "--disable-visible-iframe-fallback",
  "--time-warp-hold-ms", "$TimeWarpHoldMs",
  "--time-warp-wall-ms", "$TimeWarpWallMs",
  "--time-warp-stop-delay-ms", "$TimeWarpStopDelayMs",
  "--time-warp-clock-mode", "full",
  "--normalize-px1200-timing", "on",
  "--align-px561-timing-from-px1200",
  "--inject-knp-sandbox-event",
  "--exact-knp-wait-ms", "1600",
  "--exact-knp-fallback-grace-ms", "1600",
  "--synthetic-u0-lead-ms", "650",
  "--early-w0-drain-before-final-ms", "-1",
  "--early-w0-drain-after-final-ms", "$W0AfterFinalMs",
  "--delayed-final-hard-extra-ms", "1200",
  "--time-warp-attempts", "$TimeWarpAttempts",
  "--time-warp-retry-visible-challenge-after-ms", "$TimeWarpRetryAfterMs",
  "--time-warp-finished-stable-ms", "$TimeWarpFinishedStableMs",
  "--wait-before-ms", "$WaitBeforeMs",
  "--wait-after-ms", "$WaitAfterMs",
  "--skip-mid-snapshots"
)

if ($RewriteFinalResultSuccess -and $OptimisticW0Success) {
  Write-Host "[Probe] RewriteFinalResultSuccess overrides OptimisticW0Success; disabling optimistic W0 for this run."
  $OptimisticW0Success = $false
}

if ($RewriteFinalResultSuccess -and -not $NoDeferFinalResultToW0) {
  Write-Host "[Probe] RewriteFinalResultSuccess is incompatible with final->W0 defer; disabling defer for this run."
  $NoDeferFinalResultToW0 = $true
}

if ($DeferW0WaitMs -gt 0) {
  $cmd += @("--defer-final-result-to-w0-wait-ms", "$DeferW0WaitMs")
}

if (-not $NoDeferFinalResultToW0) {
  $cmd += "--defer-final-result-to-w0"
}

if ($NoSyntheticU0) {
  $cmd += "--disable-synthetic-u0"
}

if ($PreserveFinalBfa) {
  $cmd += "--preserve-final-bfa"
}

if ($FreshProfilePrefix) {
  $cmd += @("--fresh-profile-prefix", $FreshProfilePrefix)
}

if ($CloakNoViewport) {
  $cmd += "--cloak-no-viewport"
}

if ($OptimisticW0Success) {
  $cmd += "--optimistic-w0-success"
}

if ($OptimisticFinalSuccess) {
  $cmd += "--optimistic-final-success"
}

if ($RewriteFinalResultSuccess) {
  $cmd += "--rewrite-final-result-success"
}

if ($NeutralFinalFetchW0) {
  $cmd += "--neutral-final-fetch-w0"
}

if ($NeutralFinalMergeW0Success) {
  $cmd += "--neutral-final-merge-w0-success"
}

if ($NeutralFinalCachedW0Success) {
  $cmd += "--neutral-final-cached-w0-success"
}

if ($NeutralFinalCachedRichW0Success) {
  $cmd += "--neutral-final-cached-rich-w0-success"
}

if ($RealFinalNeutralW0Success) {
  $cmd += "--real-final-neutral-w0-success"
}

if ($SessionCachedRichFinalSuccess) {
  $cmd += "--session-cached-rich-final-success"
}

if ($SessionCachedRichW0Success) {
  $cmd += "--session-cached-rich-w0-success"
}

if ($SessionCachedRichFinalAndW0Success) {
  $cmd += "--session-cached-rich-final-and-w0-success"
}

if ($WarmupNeutralThenRichFinalAndW0Success) {
  $cmd += "--warmup-neutral-then-rich-final-and-w0-success"
}

if ($SessionCachedRichInitialW0DelayMs -gt 0) {
  $cmd += @("--session-cached-rich-initial-w0-delay-ms", "$SessionCachedRichInitialW0DelayMs")
}

if ($CountryLabel) {
  $cmd += @("--signup-country-label", $CountryLabel)
}

if ($ProxyUrl) {
  $cmd += @("--proxy", $ProxyUrl)
}

if ($TriggerFinalSuccessSignals) {
  $cmd += "--trigger-final-success-signals"
}

try {
  python @cmd
  $exitCode = $LASTEXITCODE
} finally {
  Write-Host "`n[Analyze latest run]"
  python analyze_latest_protocol_run.py --no-decode-dump
}

exit $exitCode
