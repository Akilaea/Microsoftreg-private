param(
    [string]$FreshProfilePrefix = "cloak-protocol",
    [string]$CloakFingerprint = "",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "default"
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
  "--exact-knp-wait-ms", "1600",
  "--exact-knp-fallback-grace-ms", "1600",
  "--synthetic-u0-lead-ms", "650",
  "--early-w0-drain-before-final-ms", "0",
  "--early-w0-drain-after-final-ms", "0",
  "--delayed-final-hard-extra-ms", "1200",
  "--time-warp-hold-ms", "9300",
  "--time-warp-wall-ms", "900",
  "--time-warp-stop-delay-ms", "1200",
  "--time-warp-prewait-ms", "2500",
  "--time-warp-frame-scope", "challenge",
  "--skip-mid-snapshots",
  "--wait-before-ms", "24000",
  "--wait-after-ms", "24000"
)

if ($CloakFingerprint) {
  $cmd += @("--cloak-fingerprint", $CloakFingerprint)
}

python @cmd
