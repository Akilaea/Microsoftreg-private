param(
    [string]$CountryLabel = "",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [ValidateSet("minimal", "expanded")]
    [string]$Profile = "minimal",
    [int]$TimeoutSeconds = 320,
    [int]$PauseBetweenSeconds = 8,
    [switch]$StopOnRiskBlock,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function New-Variant($Name, $Script, [string[]]$VariantArgs) {
  [PSCustomObject]@{
    Name = $Name
    Script = $Script
    Args = $VariantArgs
  }
}

$common = @("-ProxyUrl", $ProxyUrl)
if ($CountryLabel) {
  $common += @("-CountryLabel", $CountryLabel)
}

# Minimal matrix is ordered from least noisy/current-best to fallback variants.
# All variants keep wall_ms <= 1500 so a CreateAccount 200 can still pass the
# 1s verifier gate.
$variants = @(
  (New-Variant "w0defer_wall900" ".\run_1s_w0_defer_once.ps1" ([string[]]($common + @("-WallMs", "900", "-DeferW0WaitMs", "3500")))),
  (New-Variant "w0defer_wall1200" ".\run_1s_w0_defer_once.ps1" ([string[]]($common + @("-WallMs", "1200", "-DeferW0WaitMs", "3500")))),
  (New-Variant "rewrite_wall900_nosig" ".\run_1s_rewrite_once.ps1" ([string[]]($common + @("-WallMs", "900", "-NoTriggerFinalSuccessSignals"))))
)

if ($Profile -eq "expanded") {
  $variants += @(
    (New-Variant "rewrite_wall1200_nosig" ".\run_1s_rewrite_once.ps1" ([string[]]($common + @("-WallMs", "1200", "-NoTriggerFinalSuccessSignals")))),
    (New-Variant "rewrite_wall900_sig" ".\run_1s_rewrite_once.ps1" ([string[]]($common + @("-WallMs", "900")))),
    (New-Variant "optimistic_final_wall900" ".\run_1s_rewrite_once.ps1" ([string[]]($common + @("-WallMs", "900", "-OptimisticFinalSuccess", "-NoTriggerFinalSuccessSignals"))))
  )
}

$matrixStart = Get-Date
$knownNetwork = @{}
Get-ChildItem -Path "Results\network" -Filter "*.jsonl" -File -ErrorAction SilentlyContinue | ForEach-Object {
  $knownNetwork[$_.FullName] = $true
}

function Get-NewNetworkLogs {
  $logs = @(
    Get-ChildItem -Path "Results\network" -Filter "*.jsonl" -File -ErrorAction SilentlyContinue |
      Where-Object { -not $knownNetwork.ContainsKey($_.FullName) -or $_.LastWriteTime -ge $matrixStart } |
      Sort-Object LastWriteTime
  )
  return @($logs | ForEach-Object { $_.FullName })
}

Write-Host "[1s-matrix] profile=$Profile variants=$($variants.Count) proxy=$ProxyUrl country=$CountryLabel timeout=${TimeoutSeconds}s"

if ($DryRun) {
  foreach ($v in $variants) {
    Write-Host "[DryRun] $($v.Name): powershell -ExecutionPolicy Bypass -File $($v.Script) $($v.Args -join ' ')"
  }
  Write-Host "[DryRun] python verify_1s_stability.py <new-network-jsonl...> --min-successes 1"
  exit 0
}

$variantIndex = 0
foreach ($v in $variants) {
  $variantIndex += 1
  Write-Host ""
  Write-Host "[1s-matrix] variant $variantIndex/$($variants.Count): $($v.Name)"
  $start = Get-Date
  $safeName = ($v.Name -replace '[^A-Za-z0-9_.-]', '_')
  $outFile = Join-Path "Results\protocol_runtime" ("matrix_1s_{0:yyyyMMdd_HHmmss}_{1}.log" -f $start, $safeName)
  $errFile = Join-Path "Results\protocol_runtime" ("matrix_1s_{0:yyyyMMdd_HHmmss}_{1}.err.log" -f $start, $safeName)
  try {
    $childArgs = @("-ExecutionPolicy", "Bypass", "-File", $v.Script) + $v.Args
    $proc = Start-Process -FilePath "powershell" `
      -ArgumentList $childArgs `
      -NoNewWindow `
      -PassThru `
      -RedirectStandardOutput $outFile `
      -RedirectStandardError $errFile
    $completed = $proc.WaitForExit([Math]::Max(30, $TimeoutSeconds) * 1000)
    if (-not $completed) {
      try { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue } catch {}
      $exitCode = 124
      Write-Host "[1s-matrix] variant $($v.Name) timed out after ${TimeoutSeconds}s"
    } else {
      $exitCode = $proc.ExitCode
    }
    if (Test-Path -LiteralPath $outFile) {
      Get-Content -LiteralPath $outFile -Tail 70
    }
    if ((Test-Path -LiteralPath $errFile) -and (Get-Item -LiteralPath $errFile).Length -gt 0) {
      Write-Host "[1s-matrix] stderr tail:"
      Get-Content -LiteralPath $errFile -Tail 30
    }
    Write-Host "[1s-matrix] variant $($v.Name) exit=$exitCode log=$outFile"
  } catch {
    Write-Host "[1s-matrix] variant $($v.Name) launch failed: $($_.Exception.Message)"
  }

  $newNetworkLogs = @(Get-NewNetworkLogs)
  if ($newNetworkLogs.Count -gt 0) {
    Write-Host "[1s-matrix] latest summary:"
    python summarize_1s_attempts.py $($newNetworkLogs[-1])
    $verifyOut = python verify_1s_stability.py $($newNetworkLogs[-1]) --min-successes 1 2>&1
    $verifyText = $verifyOut -join "`n"
    Write-Host $verifyText
    if ($verifyText -match "STABLE_PASS") {
      Write-Host "[1s-matrix] first 1s CreateAccount 200 found on variant=$($v.Name). Run run_1s_stability_batch.ps1 next to test stability."
      exit 0
    }
    if ($StopOnRiskBlock -and $verifyText -match "STABLE_FAIL_RISKBLOCK") {
      Write-Host "[1s-matrix] stopping early because RiskBlock was detected."
      exit 2
    }
  } else {
    Write-Host "[1s-matrix] no new network log observed for variant=$($v.Name)"
  }

  if ($PauseBetweenSeconds -gt 0 -and $variantIndex -lt $variants.Count) {
    Start-Sleep -Seconds $PauseBetweenSeconds
  }
}

Write-Host ""
Write-Host "[1s-matrix] final matrix summary:"
$newNetworkLogs = @(Get-NewNetworkLogs)
if ($newNetworkLogs.Count -gt 0) {
  python verify_1s_stability.py $newNetworkLogs --min-successes 1 --allow-riskblock
  exit $LASTEXITCODE
}
Write-Host "[1s-matrix] no new network logs captured."
exit 1
