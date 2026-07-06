param(
    [string]$CountryLabel = "",
    [string]$FreshProfilePrefix = "origcdp1s",
    [int]$Port = 19223,
    [int]$WallMs = 900,
    [int]$FakeHoldMs = 9800,
    [int]$Attempts = 1,
    [int]$RetryAfterMs = 9000,
    [int]$FinishedStableMs = 4500,
    [int]$WaitAfterMs = 90000,
    [int]$DeferW0WaitMs = 3500,
    [switch]$RewriteFinal,
    [switch]$NoTriggerFinalSuccessSignals,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$profileName = "$FreshProfilePrefix-$stamp"
$profileDir = "C:\Users\wdnmd\ZCodeProject\profiles\$profileName"
$cdpEndpoint = "http://127.0.0.1:$Port"

$launch = @(
  ".\launch_cloak_cdp.py",
  "--url", "about:blank",
  "--profile-dir", $profileDir,
  "--port", "$Port"
)

$probe = @(
  ".\protocol_runtime_probe.py",
  "--config", "config.ctf.cloak_manual_profile.json",
  "--cdp-endpoint", $cdpEndpoint,
  "--mode", "time_warp_hold",
  "--route-only-hook",
  "--defer-route-hook-until-proof",
  "--normalize-y1nz-preproof",
  "--final-proof-normalizer", "minimal",
  "--disable-visible-iframe-fallback",
  "--time-warp-hold-ms", "$FakeHoldMs",
  "--time-warp-wall-ms", "$WallMs",
  "--time-warp-stop-delay-ms", "250",
  "--time-warp-clock-mode", "full",
  "--normalize-px1200-timing", "on",
  "--align-px561-timing-from-px1200",
  "--inject-knp-sandbox-event",
  "--exact-knp-wait-ms", "1600",
  "--exact-knp-fallback-grace-ms", "1600",
  "--synthetic-u0-lead-ms", "650",
  "--early-w0-drain-before-final-ms", "-1",
  "--early-w0-drain-after-final-ms", "160",
  "--delayed-final-hard-extra-ms", "1200",
  "--time-warp-attempts", "$Attempts",
  "--time-warp-retry-visible-challenge-after-ms", "$RetryAfterMs",
  "--time-warp-finished-stable-ms", "$FinishedStableMs",
  "--wait-before-ms", "26000",
  "--wait-after-ms", "$WaitAfterMs",
  "--defer-final-result-to-w0-wait-ms", "$DeferW0WaitMs",
  "--skip-mid-snapshots"
)

if ($CountryLabel) {
  $probe += @("--signup-country-label", $CountryLabel)
}

if ($RewriteFinal) {
  $probe += "--rewrite-final-result-success"
} else {
  $probe += @("--optimistic-final-success", "--defer-final-result-to-w0")
}

if (-not $NoTriggerFinalSuccessSignals -and $RewriteFinal) {
  $probe += "--trigger-final-success-signals"
}

if ($DryRun) {
  Write-Host "[DryRun] python $($launch -join ' ')"
  Write-Host "[DryRun] python $($probe -join ' ')"
  exit 0
}

Write-Host "[orig-cdp] profile=$profileDir cdp=$cdpEndpoint"
python @launch
Start-Sleep -Seconds 2
try {
  python @probe
  $exitCode = $LASTEXITCODE
} finally {
  Write-Host "`n[Analyze latest run]"
  python analyze_latest_protocol_run.py --no-decode-dump
  try {
    $escapedProfile = $profileDir.Replace('\', '\\')
    $procs = Get-CimInstance Win32_Process -Filter "Name = 'chrome.exe'" |
      Where-Object { $_.CommandLine -and $_.CommandLine.Contains($profileDir) }
    foreach ($p in $procs) {
      Write-Host "[orig-cdp] stopping chrome pid=$($p.ProcessId)"
      Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
    }
  } catch {
    Write-Host "[orig-cdp] cleanup warning: $($_.Exception.Message)"
  }
}
exit $exitCode
