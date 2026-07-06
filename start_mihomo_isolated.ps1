param(
    [string]$MihomoDir = "C:\Users\wdnmd\Documents\mihomo-windows-amd64-v1-go120-v1.19.27",
    [string]$WorkDir = ".mihomo-isolated",
    [string]$SourceConfig = "",
    [switch]$UseExistingConfig,
    [switch]$Restart
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$exe = Join-Path $MihomoDir "mihomo-windows-amd64-v1-go120.exe"
if (!(Test-Path -LiteralPath $exe)) {
  throw "mihomo executable not found: $exe"
}

if ($SourceConfig) {
  python setup_mihomo_isolated.py --source-config $SourceConfig --out-dir $WorkDir | Out-Host
} elseif (!$UseExistingConfig) {
  python setup_mihomo_isolated.py --out-dir $WorkDir | Out-Host
}

$iso = Resolve-Path -LiteralPath $WorkDir
$config = Join-Path $iso "config.yaml"
$pidFile = Join-Path $iso "mihomo.pid"
$stdout = Join-Path $iso "mihomo.stdout.log"
$stderr = Join-Path $iso "mihomo.stderr.log"

if (Test-Path -LiteralPath $pidFile) {
  $oldPid = Get-Content -LiteralPath $pidFile -ErrorAction SilentlyContinue
  if ($oldPid) {
    $old = Get-Process -Id ([int]$oldPid) -ErrorAction SilentlyContinue
    if ($old) {
      if ($Restart) {
        if ($old.Path -and $old.Path -notlike "*mihomo*") {
          throw "Refusing to stop pid=$oldPid because process path is not mihomo: $($old.Path)"
        }
        Stop-Process -Id $old.Id -Force
        Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
      } else {
      Write-Host "[mihomo-isolated] already running pid=$oldPid"
      exit 0
      }
    }
  }
}

$proc = Start-Process `
  -FilePath $exe `
  -ArgumentList @("-d", "$iso", "-f", "$config") `
  -WorkingDirectory $iso `
  -RedirectStandardOutput $stdout `
  -RedirectStandardError $stderr `
  -WindowStyle Hidden `
  -PassThru

Set-Content -LiteralPath $pidFile -Value $proc.Id -Encoding ASCII
Write-Host "[mihomo-isolated] started pid=$($proc.Id)"
Write-Host "[mihomo-isolated] http proxy: http://127.0.0.1:17890"
Write-Host "[mihomo-isolated] controller: http://127.0.0.1:19090"
