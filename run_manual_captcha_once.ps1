param(
    [string]$FreshProfilePrefix = "manual-captcha",
    [int]$WaitSeconds = 300,
    [int]$PostVerifyWaitSeconds = 20,
    [string]$CdpEndpoint = ""
)

$ErrorActionPreference = "Stop"

$cmd = @(
  "protocol_runtime_probe.py",
  "--config", "config.ctf.protocol_trace.json",
  "--fresh-profile-prefix", $FreshProfilePrefix,
  "--mode", "observe_hold",
  "--manual-captcha",
  "--manual-captcha-wait-seconds", "$WaitSeconds",
  "--manual-post-verify-wait-seconds", "$PostVerifyWaitSeconds",
  "--wait-before-ms", "24000",
  "--wait-after-ms", "24000"
)

if ($CdpEndpoint) {
  $cmd += @("--cdp-endpoint", $CdpEndpoint)
}

python @cmd
