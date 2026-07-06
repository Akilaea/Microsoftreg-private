param(
  [string]$FreshProfilePrefix = "ctf-natural-long-live"
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

python protocol_runtime_probe.py `
  --config config.ctf.protocol_trace.json `
  --fresh-profile-prefix $FreshProfilePrefix `
  --mode observe_hold `
  --wait-before-ms 24000 `
  --wait-after-ms 12000

python analyze_latest_protocol_run.py --no-decode-dump
