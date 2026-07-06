param(
    [string]$CountryLabel = "台湾",
    [ValidateSet("manual", "trace")]
    [string]$ConfigProfile = "manual",
    [ValidateSet("default", "careful")]
    [string]$CloakHumanPreset = "careful",
    [string]$FreshProfilePrefix = "cloakrewrite",
    [int]$W0AfterFinalMs = 160
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

# New-IP verification path:
# - fresh Cloak profile, matching manual open_outlook.py's non-reused identity
# - no final->W0 defer and no optimistic W0; preserve the real final _px3/_pxde
#   response, but rewrite only score/result to success for the client
# - success is only CreateAccount 200, printed by analyze_latest_protocol_run.py
powershell -ExecutionPolicy Bypass -File .\run_accel_defer_w0_once.ps1 `
  -ConfigProfile $ConfigProfile `
  -CloakHumanPreset $CloakHumanPreset `
  -CountryLabel $CountryLabel `
  -FreshProfilePrefix $FreshProfilePrefix `
  -W0AfterFinalMs $W0AfterFinalMs `
  -NoDeferFinalResultToW0 `
  -RewriteFinalResultSuccess `
  -TriggerFinalSuccessSignals
