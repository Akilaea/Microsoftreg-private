param(
    [int]$WallMs = 7000,
    [int]$HoldMs = 11000,
    [int]$StopDelayMs = 250,
    [int]$WaitBeforeMs = 30000,
    [int]$WaitAfterMs = 34000,
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$FreshProfilePrefix = "",
    [ValidateSet("pure", "natural_long", "ads_long", "minimal")]
    [string]$Normalizer = "pure",
    [int]$EarlyW0AfterFinalMs = 160,
    [int]$EarlyW0BeforeFinalMs = -1,
    [int]$AsyncRawCdpReleaseMs = 0,
    [switch]$AsyncRawCdpReleaseNoWait,
    [int]$HybridPageMoveCount = 0,
    [switch]$HybridPageMoveNoReply,
    [switch]$DenseCdpHoldInput,
    [int]$LegacyShortHoldSteps = 0,
    [int]$MinRuntimeHookReadyFrames = 0,
    [int]$MinKnpPrestartOk = 0,
    [int]$PreholdHookGuardRetries = 2,
    [ValidateSet("default", "natural_long")]
    [string]$Px1200TimingProfile = "default",
    [switch]$InjectKnp,
    [switch]$PreserveFinalBfa,
    [switch]$AllowSecondAttempt
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

if (-not $FreshProfilePrefix) {
    $FreshProfilePrefix = "accel-late-only-w$WallMs"
}

# Use the currently validated conservative Cloak/ADS-like profile as the browser baseline,
# but only install the runtime hook after the visible HumanCaptcha button exists.
$config = ".\config.ctf.runtime.mihomo-jpb-conservative.manual.20260704_141220.json"
if (-not (Test-Path -LiteralPath $config)) {
    $config = ".\config.ctf.runtime.mihomo-jpb-conservative.20260704_141220.json"
}

$cmd = @(
    ".\protocol_runtime_probe.py",
    "--config", $config,
    "--fresh-profile-prefix", $FreshProfilePrefix,
    "--proxy", $ProxyUrl,
    "--use-cloakbrowser",
    "--cloak-human-preset", "careful",
    "--mode", "time_warp_hold",
    "--route-only-hook",
    "--defer-route-hook-until-proof",
    "--disable-visible-iframe-fallback",
    "--time-warp-install-mode", "early",
    "--time-warp-clock-mode", "full",
    "--normalize-px1200-timing", "on",
    "--px1200-timing-profile", $Px1200TimingProfile,
    "--time-warp-hold-ms", "$HoldMs",
    "--time-warp-wall-ms", "$WallMs",
    "--time-warp-stop-delay-ms", "$StopDelayMs",
    "--early-w0-drain-before-final-ms", "$EarlyW0BeforeFinalMs",
    "--early-w0-drain-after-final-ms", "$EarlyW0AfterFinalMs",
    "--time-warp-frame-scope", "challenge",
    "--time-warp-attempts", ($(if ($AllowSecondAttempt) { "2" } else { "1" })),
    "--time-warp-retry-visible-challenge-after-ms", "9000",
    "--time-warp-finished-stable-ms", "2200",
    "--disable-synthetic-u0",
    "--wait-before-ms", "$WaitBeforeMs",
    "--wait-after-ms", "$WaitAfterMs",
    "--skip-mid-snapshots"
)

if ($Normalizer -ne "pure") {
    $cmd += @(
        "--normalize-y1nz-preproof",
        "--final-proof-normalizer", $Normalizer
    )
}

if ($InjectKnp) {
    $cmd += @(
        "--inject-knp-sandbox-event",
        "--exact-knp-wait-ms", "1600",
        "--exact-knp-fallback-grace-ms", "1600"
    )
}

if ($PreserveFinalBfa) {
    $cmd += "--preserve-final-bfa"
}

if ($AsyncRawCdpReleaseMs -gt 0) {
    $cmd += @("--async-raw-cdp-release-ms", "$AsyncRawCdpReleaseMs")
    if ($AsyncRawCdpReleaseNoWait) {
        $cmd += "--async-raw-cdp-release-no-wait"
    }
}

if ($HybridPageMoveCount -gt 0) {
    $cmd += @("--hybrid-page-move-count", "$HybridPageMoveCount")
    if ($HybridPageMoveNoReply) {
        $cmd += "--hybrid-page-move-no-reply"
    }
}

Write-Host "[accel-late-only] wall=$WallMs hold=$HoldMs normalizer=$Normalizer pxProfile=$Px1200TimingProfile w0Before=$EarlyW0BeforeFinalMs w0After=$EarlyW0AfterFinalMs denseCdp=$($DenseCdpHoldInput.IsPresent) hybridMoves=$HybridPageMoveCount asyncRelease=$AsyncRawCdpReleaseMs injectKnp=$($InjectKnp.IsPresent) preserveBfa=$($PreserveFinalBfa.IsPresent)"

if ($DenseCdpHoldInput) {
    $cmd += "--dense-cdp-hold-input"
}

if ($MinRuntimeHookReadyFrames -gt 0) {
    $cmd += @("--min-runtime-hook-ready-frames", "$MinRuntimeHookReadyFrames")
}

if ($MinKnpPrestartOk -gt 0) {
    $cmd += @("--min-knp-prestart-ok", "$MinKnpPrestartOk")
}

if ($PreholdHookGuardRetries -ne 2) {
    $cmd += @("--prehold-hook-guard-retries", "$PreholdHookGuardRetries")
}

if ($LegacyShortHoldSteps -gt 0) {
    $cmd += @("--legacy-short-hold-steps", "$LegacyShortHoldSteps")
}

python @cmd
$runExit = $LASTEXITCODE

Write-Host "`n[Analyze latest network]"
$latest = Get-ChildItem .\Results\network\*.jsonl -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($latest) {
    python .\analyze_protocol_run.py $latest.FullName
}

exit $runExit
