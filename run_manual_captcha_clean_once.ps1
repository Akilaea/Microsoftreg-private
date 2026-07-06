param(
    [int]$WaitSeconds = 300,
    [int]$PostVerifyWaitSeconds = 20,
    [string]$CdpEndpoint = "",
    [switch]$UseCloakBrowser,
    [string]$CloakFingerprint = "",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "default"
)

$ErrorActionPreference = "Stop"

$cmd = @(
  "main.py",
  "--config", "config.ctf.protocol_trace.json",
  "--max-tasks", "1",
  "--concurrent", "1",
  "--manual-captcha",
  "--manual-captcha-wait-seconds", "$WaitSeconds",
  "--manual-post-verify-wait-seconds", "$PostVerifyWaitSeconds",
  "--skip-preflight"
)

if ($CdpEndpoint) {
  $cmd += @("--cdp-endpoint", $CdpEndpoint)
}
if ($UseCloakBrowser) {
  $cmd += @("--use-cloakbrowser", "--cloak-human-preset", $CloakHumanPreset)
  if ($CloakFingerprint) {
    $cmd += @("--cloak-fingerprint", $CloakFingerprint)
  }
}

python @cmd
