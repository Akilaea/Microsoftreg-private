param(
    [string]$WorkDir = ".mihomo-isolated"
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$iso = Resolve-Path -LiteralPath $WorkDir -ErrorAction SilentlyContinue
if (!$iso) {
  Write-Host "[mihomo-isolated] work dir not found"
  exit 0
}

$pidFile = Join-Path $iso "mihomo.pid"
if (!(Test-Path -LiteralPath $pidFile)) {
  Write-Host "[mihomo-isolated] pid file not found"
  exit 0
}

$targetPidText = Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue
if (!$targetPidText) {
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  Write-Host "[mihomo-isolated] empty pid file removed"
  exit 0
}

$proc = Get-Process -Id ([int]$targetPidText) -ErrorAction SilentlyContinue
if (!$proc) {
  Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
  Write-Host "[mihomo-isolated] process not running; pid file removed"
  exit 0
}

if ($proc.Path -and $proc.Path -notlike "*mihomo*") {
  throw "Refusing to stop pid=$targetPidText because process path is not mihomo: $($proc.Path)"
}

Stop-Process -Id $proc.Id -Force
Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
Write-Host "[mihomo-isolated] stopped pid=$targetPidText"
