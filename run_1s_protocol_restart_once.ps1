param(
    [int]$WallMs = 1100,
    [int]$HoldMs = 13000,
    [int]$StopDelayMs = 900,
    [int]$PrewaitMs = 0,
    [int]$PreDownDwellMs = 0,
    [int]$WaitBeforeMs = 30000,
    [int]$WaitAfterMs = 130000,
    [double]$BotProtectionWaitSec = -1,
    [ValidateSet("outlook", "msal_authorize")]
    [string]$SignupEntryMode = "outlook",
    [ValidateSet("ui", "fast_dom", "semi_protocol", "protocol_assist", "protocol_takeover", "protocol_takeover_thin")]
    [string]$SignupFillMode = "ui",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Config = "",
    [string]$FreshProfilePrefix = "",
    [ValidateSet("minimal", "template", "ads_safe", "ads_long", "natural_long", "old_1s", "off")]
    [string]$FinalProofNormalizer = "ads_safe",
    [ValidateSet("after160", "after800", "before50", "before250", "before500", "before900", "before0")]
    [string]$W0Policy = "after160",
    [ValidateSet("none", "optimistic_w0", "defer_final_to_w0", "neutral_fetch_w0", "neutral_merge_w0_success", "neutral_cached_w0_success", "neutral_cached_rich_w0_success", "real_final_neutral_w0_success", "session_cached_rich_final_success", "session_cached_rich_w0_success", "session_cached_rich_final_and_w0_success", "warmup_neutral_then_rich_final_and_w0_success")]
    [string]$W0ResponseMode = "none",
    [int]$W0ResponseWaitMs = 2500,
    [int]$SessionCachedRichInitialW0DelayMs = 0,
    [switch]$AsyncEarlyCachedRichW0,
    [int]$FinalResponseDelayMs = 0,
    [int]$DelayCaptchaCloseMs = 0,
    [int]$RiskVerifyGateMs = 0,
    [int]$RiskVerifyGateTimeoutMs = 1500,
    [int]$RiskVerifyHumanSuccessAgeMs = 0,
    [int]$RiskVerifyHumanSuccessTimeoutMs = 0,
    [int]$SyntheticU0LeadMs = 650,
    [int]$ExactKnpWaitMs = 1600,
    [int]$ExactKnpFallbackGraceMs = 1600,
    [int]$DelayedFinalHardExtraMs = 1200,
    [int]$Attempts = 1,
    [int]$RetryAfterMs = 9000,
    [int]$FinishedStableMs = 4500,
    [int]$MinRuntimeHookReadyFrames = 6,
    [int]$MinKnpPrestartOk = 5,
    [switch]$RequireChctxRuntimeReady,
    [int]$PreholdHookGuardRetries = 2,
    [int]$PreholdReadinessGateMs = 0,
    [int]$PreholdLoadedMinAgeMs = 0,
    [int]$RealTargetWaitMs = 12000,
    [ValidateSet("default", "natural_long")]
    [string]$Px1200TimingProfile = "default",
    [switch]$PreserveFinalBfa,
    [switch]$OptimisticFinalSuccess,
    [switch]$RewriteFinalResultSuccess,
    [switch]$TriggerFinalSuccessSignals,
    [switch]$ForceSyntheticFinalOnTimeout,
    [string]$ForceSyntheticFinalTemplateNetwork = ".\Results\network\20260704_200613_vde2anwfdvoerk.jsonl",
    [switch]$ForceSyntheticFinalPreserveBfa,
    [switch]$ForceSyntheticFinalTriggerSignals,
    [int]$ForceSyntheticFinalAfterHoldMs = -1,
    [switch]$ForceSyntheticFinalNoU0,
    [switch]$SuppressUnforcedFinalForSynthetic,
    [int]$CaptchaCloseGraceMs = 0,
    [switch]$RiskVerifyChallengeToContinue,
    [switch]$NoSyntheticU0,
    [switch]$NoCloakBrowser,
    [switch]$NoDenseCdpHoldInput,
    [switch]$LegacyShortHoldInput,
    [switch]$HybridLegacyDownCdpMoveUp,
    [switch]$HybridLegacyDownCdpMoveLegacyUp,
    [int]$HybridPageMoveCount = 0,
    [int]$LegacyShortHoldSteps = 0,
    [switch]$AllowSecondAttempt,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

if (-not $Config) {
    $Config = ".\config.ctf.runtime.mihomo-jpb-conservative.manual.20260704_141220.json"
    if (-not (Test-Path -LiteralPath $Config)) {
        $Config = ".\config.ctf.runtime.mihomo-jpb-conservative.20260704_141220.json"
    }
    if (-not (Test-Path -LiteralPath $Config)) {
        $Config = ".\config.ctf.cloak_manual_profile.json"
    }
}

if (-not $FreshProfilePrefix) {
    $FreshProfilePrefix = "protocol1s-restart-w$WallMs-$W0Policy-$FinalProofNormalizer"
}

$EffectiveProxyUrl = $ProxyUrl
$DisableProxyOverride = $false
if ($EffectiveProxyUrl -in @("__none__", "none", "off", "disabled", "direct")) {
    # Use a temporary config with proxy="" instead of trying to pass an empty
    # argparse value through nested PowerShell/native argument parsing.
    $DisableProxyOverride = $true
    $EffectiveProxyUrl = ""
}

$EffectiveConfig = $Config
$ProxyOverrideRequested = $PSBoundParameters.ContainsKey("ProxyUrl")
if ($DisableProxyOverride -or $ProxyOverrideRequested) {
    $stamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $proxyLabel = if ($DisableProxyOverride) { "direct" } else { "proxy" }
    $EffectiveConfig = ".\config.ctf.runtime.$proxyLabel-$FreshProfilePrefix.$stamp.json"
    $cfg = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
    $cfg.proxy = $EffectiveProxyUrl
    $json = $cfg | ConvertTo-Json -Depth 100
    # Windows PowerShell's "-Encoding UTF8" writes a BOM, but Python json.load()
    # opens config files as plain utf-8.  Write an explicit UTF-8-no-BOM file.
    [System.IO.File]::WriteAllText(
        (Resolve-Path -LiteralPath (Split-Path -Parent $EffectiveConfig)).Path + "\" + (Split-Path -Leaf $EffectiveConfig),
        $json,
        [System.Text.UTF8Encoding]::new($false)
    )
}

$earlyW0Before = -1
$earlyW0After = 160
switch ($W0Policy) {
    "after160" { $earlyW0Before = -1; $earlyW0After = 160 }
    "after800" { $earlyW0Before = -1; $earlyW0After = 800 }
    "before50" { $earlyW0Before = 50; $earlyW0After = 160 }
    "before250" { $earlyW0Before = 250; $earlyW0After = 160 }
    "before500" { $earlyW0Before = 500; $earlyW0After = 160 }
    "before900" { $earlyW0Before = 900; $earlyW0After = 160 }
    "before0" { $earlyW0Before = 0; $earlyW0After = 160 }
}

if ($AllowSecondAttempt -and $Attempts -lt 2) {
    $Attempts = 2
}

$cmd = @(
    ".\protocol_runtime_probe.py",
    "--config", $EffectiveConfig,
    "--fresh-profile-prefix", $FreshProfilePrefix,
    "--cloak-human-preset", "careful",
    "--mode", "time_warp_hold",
    "--route-only-hook",
    "--defer-route-hook-until-proof",
    "--normalize-y1nz-preproof",
    "--final-proof-normalizer", $FinalProofNormalizer,
    "--disable-visible-iframe-fallback",
    "--time-warp-install-mode", "early",
    "--time-warp-clock-mode", "full",
    "--normalize-px1200-timing", "on",
    "--px1200-timing-profile", $Px1200TimingProfile,
    "--align-px561-timing-from-px1200",
    "--inject-knp-sandbox-event",
    "--exact-knp-wait-ms", "$ExactKnpWaitMs",
    "--exact-knp-fallback-grace-ms", "$ExactKnpFallbackGraceMs",
    "--synthetic-u0-lead-ms", "$SyntheticU0LeadMs",
    "--early-w0-drain-before-final-ms", "$earlyW0Before",
    "--early-w0-drain-after-final-ms", "$earlyW0After",
    "--delayed-final-hard-extra-ms", "$DelayedFinalHardExtraMs",
    "--time-warp-hold-ms", "$HoldMs",
    "--time-warp-wall-ms", "$WallMs",
    "--time-warp-stop-delay-ms", "$StopDelayMs",
    "--time-warp-prewait-ms", "$PrewaitMs",
    "--time-warp-pre-down-dwell-ms", "$PreDownDwellMs",
    "--time-warp-frame-scope", "challenge",
    "--time-warp-attempts", "$Attempts",
    "--time-warp-retry-visible-challenge-after-ms", "$RetryAfterMs",
    "--time-warp-finished-stable-ms", "$FinishedStableMs",
    "--wait-before-ms", "$WaitBeforeMs",
    "--wait-after-ms", "$WaitAfterMs",
    "--skip-mid-snapshots"
)

if (-not $NoCloakBrowser) {
    $cmd += "--use-cloakbrowser"
}

if ($NoSyntheticU0) {
    $cmd += "--disable-synthetic-u0"
}

if ($PreserveFinalBfa) {
    $cmd += "--preserve-final-bfa"
}

if ($OptimisticFinalSuccess) {
    $cmd += "--optimistic-final-success"
}

if ($RewriteFinalResultSuccess) {
    $cmd += "--rewrite-final-result-success"
}

if ($TriggerFinalSuccessSignals) {
    $cmd += "--trigger-final-success-signals"
}

if ($ForceSyntheticFinalOnTimeout) {
    $cmd += "--force-synthetic-final-on-timeout"
}

if ($ForceSyntheticFinalTemplateNetwork) {
    $cmd += @("--force-synthetic-final-template-network", $ForceSyntheticFinalTemplateNetwork)
}

if ($ForceSyntheticFinalPreserveBfa) {
    $cmd += "--force-synthetic-final-preserve-bfa"
}

if ($ForceSyntheticFinalTriggerSignals) {
    $cmd += "--force-synthetic-final-trigger-signals"
}

if ($ForceSyntheticFinalAfterHoldMs -ge 0) {
    $cmd += @("--force-synthetic-final-after-hold-ms", "$ForceSyntheticFinalAfterHoldMs")
}

if ($ForceSyntheticFinalNoU0) {
    $cmd += "--force-synthetic-final-no-u0"
}

if ($SuppressUnforcedFinalForSynthetic) {
    $cmd += "--suppress-unforced-final-for-synthetic"
}

if ($CaptchaCloseGraceMs -gt 0) {
    $cmd += @("--captcha-close-grace-ms", "$CaptchaCloseGraceMs")
}

if ($RealTargetWaitMs -ne 12000) {
    $cmd += @("--real-target-wait-ms", "$RealTargetWaitMs")
}

if ($RiskVerifyChallengeToContinue) {
    $cmd += "--risk-verify-challenge-to-continue"
}

if ($BotProtectionWaitSec -ge 0) {
    $cmd += @("--bot-protection-wait-seconds", "$BotProtectionWaitSec")
}

if ($SignupEntryMode -ne "outlook") {
    $cmd += @("--signup-entry-mode", $SignupEntryMode)
}

if ($SignupFillMode -ne "ui") {
    $cmd += @("--signup-fill-mode", $SignupFillMode)
}

switch ($W0ResponseMode) {
    "none" { }
    "optimistic_w0" {
        $cmd += "--optimistic-w0-success"
    }
    "defer_final_to_w0" {
        $cmd += "--defer-final-result-to-w0"
    }
    "neutral_fetch_w0" {
        $cmd += "--neutral-final-fetch-w0"
    }
    "neutral_merge_w0_success" {
        $cmd += "--neutral-final-merge-w0-success"
    }
    "neutral_cached_w0_success" {
        $cmd += "--neutral-final-cached-w0-success"
    }
    "neutral_cached_rich_w0_success" {
        $cmd += "--neutral-final-cached-rich-w0-success"
    }
    "real_final_neutral_w0_success" {
        $cmd += "--real-final-neutral-w0-success"
    }
    "session_cached_rich_final_success" {
        $cmd += "--session-cached-rich-final-success"
    }
    "session_cached_rich_w0_success" {
        $cmd += "--session-cached-rich-w0-success"
    }
    "session_cached_rich_final_and_w0_success" {
        $cmd += "--session-cached-rich-final-and-w0-success"
    }
    "warmup_neutral_then_rich_final_and_w0_success" {
        $cmd += "--warmup-neutral-then-rich-final-and-w0-success"
    }
    default {
        throw "Unsupported W0ResponseMode: $W0ResponseMode"
    }
}

if ($W0ResponseMode -ne "none") {
    $cmd += @("--defer-final-result-to-w0-wait-ms", "$W0ResponseWaitMs")
}

if ($SessionCachedRichInitialW0DelayMs -gt 0) {
    $cmd += @("--session-cached-rich-initial-w0-delay-ms", "$SessionCachedRichInitialW0DelayMs")
}

if ($AsyncEarlyCachedRichW0) {
    $cmd += "--async-early-cached-rich-w0"
}

if ($FinalResponseDelayMs -gt 0) {
    $cmd += @("--final-response-delay-ms", "$FinalResponseDelayMs")
}

if ($DelayCaptchaCloseMs -gt 0) {
    $cmd += @("--delay-captcha-close-ms", "$DelayCaptchaCloseMs")
}

if ($RiskVerifyGateMs -gt 0) {
    $cmd += @("--risk-verify-gate-ms", "$RiskVerifyGateMs")
    $cmd += @("--risk-verify-gate-timeout-ms", "$RiskVerifyGateTimeoutMs")
}
if ($RiskVerifyHumanSuccessAgeMs -gt 0) {
    $cmd += @("--risk-verify-human-success-age-ms", "$RiskVerifyHumanSuccessAgeMs")
    $cmd += @("--risk-verify-human-success-timeout-ms", "$RiskVerifyHumanSuccessTimeoutMs")
}

if (-not $NoDenseCdpHoldInput) {
    $cmd += "--dense-cdp-hold-input"
}

if ($LegacyShortHoldInput) {
    $cmd += "--legacy-short-hold-input"
}

if ($HybridLegacyDownCdpMoveUp) {
    $cmd += "--hybrid-legacy-down-cdp-move-up"
}

if ($HybridLegacyDownCdpMoveLegacyUp) {
    $cmd += "--hybrid-legacy-down-cdp-move-legacy-up"
}

if ($HybridPageMoveCount -gt 0) {
    $cmd += @("--hybrid-page-move-count", "$HybridPageMoveCount")
}

if ($LegacyShortHoldSteps -gt 0) {
    $cmd += @("--legacy-short-hold-steps", "$LegacyShortHoldSteps")
}

if ($MinRuntimeHookReadyFrames -gt 0) {
    $cmd += @("--min-runtime-hook-ready-frames", "$MinRuntimeHookReadyFrames")
}

if ($MinKnpPrestartOk -gt 0) {
    $cmd += @("--min-knp-prestart-ok", "$MinKnpPrestartOk")
}

if ($RequireChctxRuntimeReady) {
    $cmd += "--require-chctx-runtime-ready"
}

if ($PreholdHookGuardRetries -ne 2) {
    $cmd += @("--prehold-hook-guard-retries", "$PreholdHookGuardRetries")
}

if ($PreholdReadinessGateMs -gt 0) {
    $cmd += @("--prehold-readiness-gate-ms", "$PreholdReadinessGateMs")
}
if ($PreholdLoadedMinAgeMs -gt 0) {
    $cmd += @("--prehold-loaded-min-age-ms", "$PreholdLoadedMinAgeMs")
}

Write-Host "[protocol1s-restart] wall=$WallMs hold=$HoldMs stopDelay=$StopDelayMs prewait=$PrewaitMs preDownDwell=$PreDownDwellMs botWait=$BotProtectionWaitSec entry=$SignupEntryMode fill=$SignupFillMode cloak=$(-not $NoCloakBrowser.IsPresent) normalizer=$FinalProofNormalizer w0=$W0Policy before=$earlyW0Before after=$earlyW0After w0Response=$W0ResponseMode w0Wait=$W0ResponseWaitMs w0InitialDelay=$SessionCachedRichInitialW0DelayMs asyncEarlyW0=$($AsyncEarlyCachedRichW0.IsPresent) finalRespDelay=$FinalResponseDelayMs delayClose=$DelayCaptchaCloseMs riskGate=$RiskVerifyGateMs/$RiskVerifyGateTimeoutMs humanSuccessGate=$RiskVerifyHumanSuccessAgeMs/$RiskVerifyHumanSuccessTimeoutMs closeGrace=$CaptchaCloseGraceMs chctxGuard=$($RequireChctxRuntimeReady.IsPresent) riskContinue=$($RiskVerifyChallengeToContinue.IsPresent) syntheticU0=$(-not $NoSyntheticU0.IsPresent) u0Lead=$SyntheticU0LeadMs exactKnp=$ExactKnpWaitMs/$ExactKnpFallbackGraceMs preserveBfa=$($PreserveFinalBfa.IsPresent) optimisticFinal=$($OptimisticFinalSuccess.IsPresent) rewriteFinal=$($RewriteFinalResultSuccess.IsPresent) triggerSignals=$($TriggerFinalSuccessSignals.IsPresent) forceFinal=$($ForceSyntheticFinalOnTimeout.IsPresent) forceBfa=$($ForceSyntheticFinalPreserveBfa.IsPresent) forceAfterHoldMs=$ForceSyntheticFinalAfterHoldMs forceNoU0=$($ForceSyntheticFinalNoU0.IsPresent) suppressNaturalFinal=$($SuppressUnforcedFinalForSynthetic.IsPresent) legacyInput=$($LegacyShortHoldInput.IsPresent) hybridDownCdp=$($HybridLegacyDownCdpMoveUp.IsPresent) hybridDownCdpLegacyUp=$($HybridLegacyDownCdpMoveLegacyUp.IsPresent) hybridPageMoves=$HybridPageMoveCount legacySteps=$LegacyShortHoldSteps readinessGate=$PreholdReadinessGateMs loadedMinAge=$PreholdLoadedMinAgeMs realTargetWait=$RealTargetWaitMs"
Write-Host "[protocol1s-restart] config=$EffectiveConfig profile=$FreshProfilePrefix proxy=$EffectiveProxyUrl"

if ($DryRun) {
    Write-Host "[DryRun] python $($cmd -join ' ')"
    exit 0
}

$runStartedAt = Get-Date
python @cmd
$runExit = $LASTEXITCODE

Write-Host "`n[Analyze latest network]"
$latest = Get-ChildItem .\Results\network\*.jsonl -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -ge $runStartedAt.AddSeconds(-2) } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
if ($latest) {
    python .\analyze_protocol_run.py $latest.FullName
} else {
    Write-Host "[Analyze latest network] no new network capture for this run"
}

exit $runExit
