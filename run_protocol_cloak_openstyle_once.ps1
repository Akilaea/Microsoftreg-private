param(
    [string]$FreshProfilePrefix = "cloak-openstyle-oldsuccess",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "default",
    [string]$TimezoneId = "Asia/Shanghai",
    [switch]$RouteOnlyHook,
    [switch]$DeferRouteHookUntilProof,
    [switch]$NormalizeY1nzPreproof,
    [switch]$DisableVisibleIframeFallback,
    [switch]$NoInjectKnpSandbox,
    [switch]$AcceptLanguageHeader,
    [switch]$ScoreProbe,
    [switch]$NoJsInputFallback,
    [int]$ScoreProbeWaitMs = 8000,
    [string]$WindowSize = "1365,768",
    [string]$WindowPosition = "",
    [switch]$NoWindowSize
)

$ErrorActionPreference = "Stop"

# Match the user's manual open_outlook.py as closely as possible while keeping
# protocol_runtime_probe automation:
#   - CloakBrowser
#   - fresh profile every run
#   - no Playwright-emulated viewport (native browser window)
#   - zh-CN locale, configurable timezone (manual script uses Asia/Shanghai)
#   - old 20260620 successful time_warp_hold parameters
#   - no --log-net-log

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$baseConfig = Join-Path $PSScriptRoot "config.ctf.protocol_trace.json"
$runtimeConfig = Join-Path $PSScriptRoot "config.ctf.openstyle.$stamp.json"

$json = Get-Content $baseConfig -Raw | ConvertFrom-Json
if (-not $json.context) {
  $json | Add-Member -MemberType NoteProperty -Name context -Value ([pscustomobject]@{})
}
$json.context.locale = "zh-CN"
$json.context.timezone_id = $TimezoneId
if ($AcceptLanguageHeader) {
  if (-not $json.context.extra_http_headers) {
    $json.context | Add-Member -MemberType NoteProperty -Name extra_http_headers -Value ([pscustomobject]@{}) -Force
  }
  $json.context.extra_http_headers | Add-Member -MemberType NoteProperty -Name "Accept-Language" -Value "zh-CN,zh;q=0.9" -Force
}
if ($json.context.PSObject.Properties.Name -contains "viewport") {
  $json.context.viewport = $null
} else {
  $json.context | Add-Member -MemberType NoteProperty -Name viewport -Value $null
}
if (-not $json.cloakbrowser) {
  $json | Add-Member -MemberType NoteProperty -Name cloakbrowser -Value ([pscustomobject]@{})
}
$cloakArgs = @()
if (($json.cloakbrowser.PSObject.Properties.Name -contains "args") -and $json.cloakbrowser.args) {
  $cloakArgs = @($json.cloakbrowser.args)
}
$cloakArgs = @($cloakArgs | Where-Object {
  ($_ -notlike "--window-size=*") -and ($_ -notlike "--window-position=*")
})
if (-not $NoWindowSize) {
  $cloakArgs += "--window-size=$WindowSize"
}
$windowPosLog = "default"
if ($WindowPosition) {
  $cloakArgs += "--window-position=$WindowPosition"
  $windowPosLog = $WindowPosition
}
$json.cloakbrowser | Add-Member -MemberType NoteProperty -Name args -Value $cloakArgs -Force
$jsonText = $json | ConvertTo-Json -Depth 32
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($runtimeConfig, $jsonText, $utf8NoBom)

$probeMode = if ($ScoreProbe) { "chctx_score_probe" } else { "time_warp_hold" }
$cmd = @(
  "protocol_runtime_probe.py",
  "--config", $runtimeConfig,
  "--fresh-profile-prefix", $FreshProfilePrefix,
  "--use-cloakbrowser",
  "--cloak-human-preset", $CloakHumanPreset,
  "--cloak-no-viewport",
  "--mode", $probeMode,
  "--time-warp-install-mode", "early",
  "--time-warp-clock-mode", "full",
  "--normalize-px1200-timing", "on",
  "--exact-knp-wait-ms", "4200",
  "--early-w0-drain-before-final-ms", "0",
  "--early-w0-drain-after-final-ms", "0",
  "--abort-on-score1",
  "--time-warp-hold-ms", "9300",
  "--time-warp-wall-ms", "900",
  "--time-warp-stop-delay-ms", "1200",
  "--time-warp-prewait-ms", "2500",
  "--time-warp-frame-scope", "challenge",
  "--skip-mid-snapshots",
  "--wait-before-ms", "24000",
  "--wait-after-ms", "12000"
)

if (-not $NoInjectKnpSandbox) {
  $cmd += "--inject-knp-sandbox-event"
}
if ($RouteOnlyHook) {
  $cmd += "--route-only-hook"
}
if ($DeferRouteHookUntilProof) {
  $cmd += "--defer-route-hook-until-proof"
}
if ($NormalizeY1nzPreproof) {
  $cmd += @("--normalize-y1nz-preproof", "--final-proof-normalizer", "minimal")
}
if ($DisableVisibleIframeFallback) {
  $cmd += "--disable-visible-iframe-fallback"
}
if ($ScoreProbe) {
  $cmd += @("--score-probe-stop-after-chctx-ms", "$ScoreProbeWaitMs")
}
if ($NoJsInputFallback) {
  $cmd += "--no-js-input-fallback"
}

Write-Host "[openstyle] runtime config: $runtimeConfig"
Write-Host "[openstyle] timezone: $TimezoneId"
Write-Host "[openstyle] window: size=$(if($NoWindowSize){'default'}else{$WindowSize}) position=$windowPosLog"
Write-Host "[openstyle] no --log-net-log; fresh prefix: $FreshProfilePrefix"
Write-Host "[openstyle] variants: mode=$probeMode routeOnly=$RouteOnlyHook deferRoute=$DeferRouteHookUntilProof normalizeY1nz=$NormalizeY1nzPreproof noInjectKnp=$NoInjectKnpSandbox acceptLanguageHeader=$AcceptLanguageHeader noJsInputFallback=$NoJsInputFallback"
python @cmd
