param(
    [string]$FreshProfilePrefix = "cloak-short-nou0",
    [string]$CloakFingerprint = "",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "careful"
)

$ErrorActionPreference = "Stop"

$cmd = @(
  "protocol_runtime_probe.py",
  "--config", "config.ctf.protocol_trace.json",
  "--fresh-profile-prefix", $FreshProfilePrefix,
  "--use-cloakbrowser",
  "--cloak-human-preset", $CloakHumanPreset,
  "--mode", "time_warp_hold",
  "--time-warp-install-mode", "early",
  "--time-warp-clock-mode", "full",
  "--normalize-px1200-timing", "on",
  "--inject-knp-sandbox-event",
  "--exact-knp-wait-ms", "0",
  "--synthetic-u0-lead-ms", "0",
  "--early-w0-drain-before-final-ms", "-1",
  "--early-w0-drain-after-final-ms", "120",
  "--time-warp-hold-ms", "3300",
  "--time-warp-wall-ms", "900",
  "--time-warp-stop-delay-ms", "900",
  "--time-warp-prewait-ms", "3500",
  "--time-warp-frame-scope", "challenge",
  "--skip-mid-snapshots",
  "--wait-before-ms", "26000",
  "--wait-after-ms", "24000"
)

if ($CloakFingerprint) {
  $cmd += @("--cloak-fingerprint", $CloakFingerprint)
}

python @cmd
