param(
    [string]$CountryLabel = "",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [int]$Count = 3,
    [int]$RegisterTimeoutSeconds = 320,
    [int]$PauseBetweenSeconds = 8,
    [switch]$StopOnRiskBlock,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if ($Count -lt 1) {
  throw "Count must be >= 1"
}

$runArgs = @("-ProxyUrl", $ProxyUrl)

if ($CountryLabel) {
  $runArgs += @("-CountryLabel", $CountryLabel)
}

Write-Host "[1s-batch] count=$Count proxy=$ProxyUrl country=$CountryLabel timeout=${RegisterTimeoutSeconds}s"
Write-Host "[1s-batch] script=.\run_1s_w0_defer_once.ps1 args=$($runArgs -join ' ')"

$batchStart = Get-Date
$knownNetwork = @{}
Get-ChildItem -Path "Results\network" -Filter "*.jsonl" -File -ErrorAction SilentlyContinue | ForEach-Object {
  $knownNetwork[$_.FullName] = $true
}

function Get-NewNetworkLogs {
  $logs = @(
    Get-ChildItem -Path "Results\network" -Filter "*.jsonl" -File -ErrorAction SilentlyContinue |
      Where-Object { -not $knownNetwork.ContainsKey($_.FullName) -or $_.LastWriteTime -ge $batchStart } |
      Sort-Object LastWriteTime
  )
  return @($logs | ForEach-Object { $_.FullName })
}

if ($DryRun) {
  for ($i = 1; $i -le $Count; $i++) {
    Write-Host "[DryRun] attempt $i/$Count powershell -ExecutionPolicy Bypass -File .\run_1s_w0_defer_once.ps1 $($runArgs -join ' ')"
  }
  Write-Host "[DryRun] python verify_1s_stability.py <new-network-jsonl...> --min-successes $Count"
  exit 0
}

for ($i = 1; $i -le $Count; $i++) {
  Write-Host ""
  Write-Host "[1s-batch] attempt $i/$Count start"
  $start = Get-Date
  $outFile = Join-Path "Results\protocol_runtime" ("batch_1s_attempt_{0:yyyyMMdd_HHmmss}_{1}.log" -f $start, $i)
  $errFile = Join-Path "Results\protocol_runtime" ("batch_1s_attempt_{0:yyyyMMdd_HHmmss}_{1}.err.log" -f $start, $i)
  try {
    $childArgs = @("-ExecutionPolicy", "Bypass", "-File", ".\run_1s_w0_defer_once.ps1") + $runArgs
    $proc = Start-Process -FilePath "powershell" `
      -ArgumentList $childArgs `
      -NoNewWindow `
      -PassThru `
      -RedirectStandardOutput $outFile `
      -RedirectStandardError $errFile
    $completed = $proc.WaitForExit([Math]::Max(30, $RegisterTimeoutSeconds) * 1000)
    if (-not $completed) {
      try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
      $exitCode = 124
      Write-Host "[1s-batch] attempt $i timed out after ${RegisterTimeoutSeconds}s"
    } else {
      $exitCode = $proc.ExitCode
    }
    if (Test-Path -LiteralPath $outFile) {
      Get-Content -LiteralPath $outFile -Tail 80
    }
    if ((Test-Path -LiteralPath $errFile) -and (Get-Item -LiteralPath $errFile).Length -gt 0) {
      Write-Host "[1s-batch] stderr tail:"
      Get-Content -LiteralPath $errFile -Tail 40
    }
    Write-Host "[1s-batch] attempt $i exit=$exitCode log=$outFile"
  } catch {
    Write-Host "[1s-batch] attempt $i launch failed: $($_.Exception.Message)"
  }

  $newNetworkLogs = @(Get-NewNetworkLogs)
  Write-Host "[1s-batch] latest summary:"
  if ($newNetworkLogs.Count -gt 0) {
    python summarize_1s_attempts.py $($newNetworkLogs[-1])
  } else {
    Write-Host "[1s-batch] no new network log observed; falling back to latest summary"
    python summarize_1s_attempts.py --limit 1
  }

  if ($StopOnRiskBlock) {
    if ($newNetworkLogs.Count -gt 0) {
      $verifyOut = python verify_1s_stability.py $($newNetworkLogs[-1]) 2>&1
    } else {
      $verifyOut = python verify_1s_stability.py --attempts 1 2>&1
    }
    $verifyText = $verifyOut -join "`n"
    Write-Host $verifyText
    if ($verifyText -match "STABLE_FAIL_RISKBLOCK") {
      Write-Host "[1s-batch] stopping early because RiskBlock was detected."
      exit 2
    }
  }

  if ($i -lt $Count -and $PauseBetweenSeconds -gt 0) {
    Start-Sleep -Seconds $PauseBetweenSeconds
  }
}

Write-Host ""
Write-Host "[1s-batch] final stability check:"
$newNetworkLogs = @(Get-NewNetworkLogs)
if ($newNetworkLogs.Count -gt 0) {
  Write-Host "[1s-batch] new network logs=$($newNetworkLogs.Count)"
  python verify_1s_stability.py $newNetworkLogs --min-successes $Count
} else {
  Write-Host "[1s-batch] no new network logs; falling back to latest $Count logs"
  python verify_1s_stability.py --attempts $Count
}
exit $LASTEXITCODE
