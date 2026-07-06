param(
    [string]$Filter = "US 006|US 008|US 007",
    [string]$ExcludeFilter = "SG001|GB006|FR 001",
    [string]$AliveFile = "",
    [string]$RiskBlockLedger = ".mihomo-isolated\riskblock_nodes.json",
    [int]$MaxNodes = 2,
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$CountryLabel = ([string]([char]0x7F8E) + [string]([char]0x56FD)),
    [int]$Attempts = 3,
    [int]$WallMs = 900,
    [int]$WaitAfterMs = 130000,
    [int]$RetryAfterMs = 9000,
    [int]$W0AfterFinalMs = 160,
    [int]$SessionCachedRichInitialW0DelayMs = 2800,
    [int]$DeferW0WaitMs = 7000,
    [int]$RegisterTimeoutSec = 480,
    [int]$RunsPerNode = 1,
    [int]$MinSuccesses = 1,
    [int]$PauseBetweenRunsSec = 8,
    [switch]$ContinueAfterSuccess,
    [switch]$StopOnRiskBlock,
    [switch]$AllowRiskBlockInGate,
    [switch]$UseSessionCachedRichW0Only,
    [switch]$UseNeutralFinalCachedRichW0,
    [switch]$UseWarmupNeutralThenRichFinalAndW0,
    [switch]$NoSyntheticU0,
    [switch]$TriggerFinalSuccessSignals,
    [switch]$IgnoreRiskBlockLedger,
    [switch]$SkipSelfTest,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not $SkipSelfTest) {
    Write-Host "[batch] running offline selftest before touching mihomo/network"
    $env:PYTHONIOENCODING = "utf-8"
    python selftest_1s_offline.py
    if ($LASTEXITCODE -ne 0) {
        throw "offline selftest failed; aborting before switching nodes"
    }
}

if ($DryRun) {
    $variant = if ($UseWarmupNeutralThenRichFinalAndW0) { "WarmupNeutralThenRichFinalAndW0Success" } elseif ($UseNeutralFinalCachedRichW0) { "NeutralFinalCachedRichW0Success" } elseif ($UseSessionCachedRichW0Only) { "SessionCachedRichW0Success" } else { "SessionCachedRichFinalAndW0Success" }
    Write-Host "[DryRun] run_mihomo_us_1s_batch"
    Write-Host "[DryRun] filter=$Filter exclude_filter=$ExcludeFilter alive_file=$AliveFile max_nodes=$MaxNodes runs_per_node=$RunsPerNode min_successes=$MinSuccesses variant=$variant"
    Write-Host "[DryRun] proxy=$ProxyUrl country=$CountryLabel wall_ms=$WallMs wait_after_ms=$WaitAfterMs retry_after_ms=$RetryAfterMs w0_after_final_ms=$W0AfterFinalMs defer_w0_wait_ms=$DeferW0WaitMs timeout_s=$RegisterTimeoutSec"
    Write-Host "[DryRun] session_cached_rich_initial_w0_delay_ms=$SessionCachedRichInitialW0DelayMs no_synthetic_u0=$($NoSyntheticU0.IsPresent) stop_on_riskblock=$($StopOnRiskBlock.IsPresent) trigger_final_success_signals=$($TriggerFinalSuccessSignals.IsPresent) riskblock_ledger=$RiskBlockLedger ignore_riskblock_ledger=$($IgnoreRiskBlockLedger.IsPresent)"
    for ($nodeIdx = 1; $nodeIdx -le [Math]::Max(1, $MaxNodes); $nodeIdx++) {
        for ($run = 1; $run -le [Math]::Max(1, $RunsPerNode); $run++) {
            $args = @(
                "-ProxyUrl", $ProxyUrl,
                "-CountryLabel", $CountryLabel,
                "-WallMs", "$WallMs",
                "-Attempts", "$Attempts",
                "-RetryAfterMs", "$RetryAfterMs",
                "-W0AfterFinalMs", "$W0AfterFinalMs",
                "-WaitAfterMs", "$WaitAfterMs",
                "-DeferW0WaitMs", "$DeferW0WaitMs",
                "-SessionCachedRichInitialW0DelayMs", "$SessionCachedRichInitialW0DelayMs"
            )
            if (-not $TriggerFinalSuccessSignals) {
                $args += "-NoTriggerFinalSuccessSignals"
            }
            if ($NoSyntheticU0) {
                $args += "-NoSyntheticU0"
            }
            if ($UseWarmupNeutralThenRichFinalAndW0) {
                $args += "-WarmupNeutralThenRichFinalAndW0Success"
            } elseif ($UseNeutralFinalCachedRichW0) {
                $args += "-NeutralFinalCachedRichW0Success"
            } elseif ($UseSessionCachedRichW0Only) {
                $args += "-SessionCachedRichW0Success"
            } else {
                $args += "-SessionCachedRichFinalAndW0Success"
            }
            Write-Host "[DryRun] node $nodeIdx/$MaxNodes run $run/$RunsPerNode powershell -ExecutionPolicy Bypass -File .\run_1s_rewrite_once.ps1 $($args -join ' ')"
        }
    }
    $verifyArgs = @("verify_1s_stability.py", "<batch-network-logs>", "--min-successes", "$MinSuccesses")
    if ($AllowRiskBlockInGate) {
        $verifyArgs += "--allow-riskblock"
    }
    Write-Host "[DryRun] python $($verifyArgs -join ' ')"
    Write-Host "[DryRun] python diagnose_1s_gap.py <batch-network-logs> --wait-after-ms $WaitAfterMs"
    Write-Host "[DryRun] python audit_1s_goal_status.py <batch-network-logs> --min-successes $MinSuccesses"
    Write-Host "[DryRun] python audit_1s_live_evidence.py <batch-summary-json> --min-successes $MinSuccesses --json"
    Write-Host "[DryRun] summary JSON final_gate records verify/audit exits, STABLE_PASS, and GOAL_COMPLETE"
    Write-Host "[DryRun] final_evidence records strict rerun gate; GOAL_EVIDENCE_COMPLETE required for exit 0"
    exit 0
}

function Get-LatestAliveNodes {
    if ($AliveFile) {
        $alive = Get-Item -LiteralPath $AliveFile -ErrorAction SilentlyContinue
    } else {
        $alive = Get-ChildItem -LiteralPath ".\.mihomo-isolated" -Filter "alive_*.json" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
    }
    if (-not $alive) {
        return @()
    }
    try {
        $data = Get-Content -LiteralPath $alive.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
        Write-Host "[batch] using alive file: $($alive.FullName) alive_count=$($data.alive_count)"
        return @($data.alive)
    } catch {
        Write-Host "[batch] failed to read alive file: $($_.Exception.Message)"
        return @()
    }
}

function Invoke-MihomoSwitch([string]$Name) {
    $uri = "$Controller/proxies/$([uri]::EscapeDataString($Group))"
    $body = @{ name = $Name } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Put -Uri $uri -ContentType "application/json; charset=utf-8" -Body $body | Out-Null
}

function Invoke-TraceProbe {
    try {
        $py = @'
import json
import re
import sys
import urllib.request

proxy = sys.argv[1]
try:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    req = urllib.request.Request(
        "https://www.cloudflare.com/cdn-cgi/trace",
        headers={"User-Agent": "Mozilla/5.0"},
    )
    with opener.open(req, timeout=12) as resp:
        text = resp.read(8192).decode("utf-8", errors="replace")
    ip = re.search(r"(?m)^ip=(.+)$", text)
    loc = re.search(r"(?m)^loc=(.+)$", text)
    ip = ip.group(1) if ip else ""
    loc = loc.group(1) if loc else ""
    print(json.dumps({"ok": True, "ip": ip, "loc": loc, "detail": f"ip={ip} loc={loc}"}))
except Exception as exc:
    print(json.dumps({"ok": False, "ip": "", "loc": "", "detail": repr(exc)[:180]}))
'@
        $jsonText = $py | python - $ProxyUrl
        $data = $jsonText | ConvertFrom-Json
        return @{ ok = [bool]$data.ok; ip = [string]$data.ip; loc = [string]$data.loc; detail = [string]$data.detail }
    } catch {
        return @{ ok = $false; detail = $_.Exception.Message }
    }
}

$script:riskBlockedEntries = @()
if (-not $IgnoreRiskBlockLedger -and (Test-Path -LiteralPath $RiskBlockLedger)) {
    try {
        $loaded = Get-Content -LiteralPath $RiskBlockLedger -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:riskBlockedEntries = @($loaded)
        Write-Host "[batch] loaded riskblock ledger: $RiskBlockLedger entries=$($script:riskBlockedEntries.Count)"
    } catch {
        Write-Host "[batch] failed to read riskblock ledger: $($_.Exception.Message)"
        $script:riskBlockedEntries = @()
    }
}

function Test-RiskBlockedNode([string]$Name, [string]$Ip = "") {
    if ($IgnoreRiskBlockLedger) {
        return $false
    }
    foreach ($entry in @($script:riskBlockedEntries)) {
        $entryName = [string]($entry.name)
        $entryIp = [string]($entry.egress_ip)
        if ($entryName -and $entryName -eq $Name) {
            return $true
        }
        if ($Ip -and $entryIp -and $entryIp -eq $Ip) {
            return $true
        }
    }
    return $false
}

function Add-RiskBlockLedgerEntry([string]$Name, $Trace, [string]$Reason) {
    if ($IgnoreRiskBlockLedger) {
        return
    }
    $ip = ""
    $loc = ""
    try {
        if ($Trace -and $Trace.ContainsKey("ip")) { $ip = [string]$Trace.ip }
        if ($Trace -and $Trace.ContainsKey("loc")) { $loc = [string]$Trace.loc }
    } catch {}
    if (Test-RiskBlockedNode $Name $ip) {
        return
    }
    $entry = [pscustomobject]@{
        name = $Name
        egress_ip = $ip
        loc = $loc
        reason = $Reason
        saved_at = (Get-Date).ToString("o")
    }
    $script:riskBlockedEntries = @($script:riskBlockedEntries) + @($entry)
    $dir = Split-Path -Parent $RiskBlockLedger
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $script:riskBlockedEntries | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $RiskBlockLedger -Encoding UTF8
    Write-Host "[batch] recorded RiskBlock node in ledger: $RiskBlockLedger name=$Name ip=$ip"
}

try {
    Invoke-RestMethod -Uri "$Controller/proxies" -TimeoutSec 5 | Out-Null
} catch {
    throw "mihomo controller not reachable: $($_.Exception.Message)"
}

$rx = [regex]::new($Filter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
$excludeRx = if ($ExcludeFilter) { [regex]::new($ExcludeFilter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) } else { $null }
$nodes = @(Get-LatestAliveNodes | Where-Object {
    $_.trace_ok -and $_.name -and $rx.IsMatch([string]$_.name) -and (-not $excludeRx -or -not $excludeRx.IsMatch([string]$_.name)) -and (-not (Test-RiskBlockedNode ([string]$_.name) ([string]$_.ip)))
} | Sort-Object delay | Select-Object -First ([Math]::Max(1, $MaxNodes)))

if (-not $nodes -or $nodes.Count -eq 0) {
    $proxies = (Invoke-RestMethod -Uri "$Controller/proxies").proxies
    $names = @($proxies.PSObject.Properties.Name | Where-Object {
        $rx.IsMatch([string]$_) -and (-not $excludeRx -or -not $excludeRx.IsMatch([string]$_)) -and (-not (Test-RiskBlockedNode ([string]$_) ""))
    } | Select-Object -First ([Math]::Max(1, $MaxNodes)))
    $nodes = @($names | ForEach-Object { [pscustomobject]@{ name = $_; delay = $null; ip = ""; loc = "" } })
}

if (-not $nodes -or $nodes.Count -eq 0) {
    throw "no nodes matched filter: $Filter"
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$summaryPath = Join-Path "Results\protocol_runtime" "mihomo_us_1s_batch_$stamp.json"
$results = @()
$batchNetworkLogs = @()
$successCount = 0

$variantName = if ($UseWarmupNeutralThenRichFinalAndW0) { 'WarmupNeutralThenRichFinalAndW0Success' } elseif ($UseNeutralFinalCachedRichW0) { 'NeutralFinalCachedRichW0Success' } elseif ($UseSessionCachedRichW0Only) { 'SessionCachedRichW0Success' } else { 'SessionCachedRichFinalAndW0Success' }
Write-Host "[batch] nodes=$($nodes.Count) filter=$Filter exclude_filter=$ExcludeFilter runs_per_node=$RunsPerNode min_successes=$MinSuccesses variant=$variantName"

foreach ($node in $nodes) {
    $name = [string]$node.name
    Write-Host "`n[batch] switch $name"
    Invoke-MihomoSwitch $name
    Start-Sleep -Milliseconds 900
    $trace = Invoke-TraceProbe
    Write-Host "[batch] trace ok=$($trace.ok) $($trace.detail)"
    if (-not $trace.ok) {
        $results += [pscustomobject]@{ name = $name; trace = $trace; exit = $null; verdict = "trace_fail" }
        continue
    }

    for ($run = 1; $run -le [Math]::Max(1, $RunsPerNode); $run++) {
        Write-Host "`n[batch] node_run $run/$RunsPerNode success_count=$successCount/$MinSuccesses"
        $scriptArgs = @(
            "-ExecutionPolicy", "Bypass",
            "-File", ".\run_1s_rewrite_once.ps1",
            "-ProxyUrl", $ProxyUrl,
            "-CountryLabel", $CountryLabel,
            "-WallMs", "$WallMs",
            "-Attempts", "$Attempts",
            "-RetryAfterMs", "$RetryAfterMs",
            "-W0AfterFinalMs", "$W0AfterFinalMs",
            "-WaitAfterMs", "$WaitAfterMs",
            "-DeferW0WaitMs", "$DeferW0WaitMs",
            "-SessionCachedRichInitialW0DelayMs", "$SessionCachedRichInitialW0DelayMs"
        )
        if (-not $TriggerFinalSuccessSignals) {
            $scriptArgs += "-NoTriggerFinalSuccessSignals"
        }
        if ($NoSyntheticU0) {
            $scriptArgs += "-NoSyntheticU0"
        }
        if ($UseWarmupNeutralThenRichFinalAndW0) {
            $scriptArgs += "-WarmupNeutralThenRichFinalAndW0Success"
        } elseif ($UseNeutralFinalCachedRichW0) {
            $scriptArgs += "-NeutralFinalCachedRichW0Success"
        } elseif ($UseSessionCachedRichW0Only) {
            $scriptArgs += "-SessionCachedRichW0Success"
        } else {
            $scriptArgs += "-SessionCachedRichFinalAndW0Success"
        }

        Write-Host "[batch] run powershell $($scriptArgs -join ' ')"
        $beforeNetworkLogs = @(Get-ChildItem -LiteralPath "Results\network" -Filter "*.jsonl" -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)
        $job = Start-Job -ScriptBlock {
            param($WorkDir, $ArgsList)
            Set-Location -LiteralPath $WorkDir
            $env:PYTHONIOENCODING = "utf-8"
            $output = & powershell @ArgsList 2>&1 | Out-String
            [pscustomobject]@{
                Output = $output
                ExitCode = $LASTEXITCODE
            }
        } -ArgumentList (Get-Location).Path, $scriptArgs
        Wait-Job -Job $job -Timeout $RegisterTimeoutSec | Out-Null
        if ($job.State -eq "Running") {
            Stop-Job -Job $job | Out-Null
            $out = "[batch] register timeout after ${RegisterTimeoutSec}s"
            $exitCode = 124
        } else {
            $jobResult = Receive-Job -Job $job
            $out = [string]$jobResult.Output
            $exitCode = [int]$jobResult.ExitCode
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
        $afterNetworkLogs = @(Get-ChildItem -LiteralPath "Results\network" -Filter "*.jsonl" -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName)
        $newNetworkLogs = @($afterNetworkLogs | Where-Object { $beforeNetworkLogs -notcontains $_ } | Sort-Object)
        $batchNetworkLogs += $newNetworkLogs
        $tail = ($out -split "`r?`n" | Select-Object -Last 80) -join "`n"
        Write-Host $tail

        $verdict = "failed"
        if ($out -match "signup\.live\.com/API/CreateAccount" -and $out -match "response POST status=200") {
            $verdict = "create_account_200"
            $successCount += 1
        } elseif ($out -match "RiskBlock|state=blocked|Rate limit|Abuse|Enforcement") {
            $verdict = "riskblock"
        } elseif ($out -match "HumanCaptcha_Success|collector_result=0|CAPTCHA_CLOSE_-1|PX1200 calls=") {
            $verdict = "captcha_or_protocol"
        } elseif ($exitCode -eq 0) {
            $verdict = "script_success"
        }
        Write-Host "[batch] exit=$exitCode verdict=$verdict success_count=$successCount/$MinSuccesses"
        $results += [pscustomobject]@{
            name = $name
            run = $run
            trace = $trace
            exit = $exitCode
            verdict = $verdict
            network_logs = $newNetworkLogs
        }
        if ($newNetworkLogs.Count -gt 0) {
            Write-Host "[batch] new network logs:"
            $newNetworkLogs | ForEach-Object { Write-Host "  $_" }
            try {
                python summarize_1s_attempts.py @newNetworkLogs
                python diagnose_1s_gap.py @newNetworkLogs --wait-after-ms $WaitAfterMs
            } catch {
                Write-Host "[batch] summarize failed: $($_.Exception.Message)"
            }
        }
        if ($verdict -eq "riskblock") {
            Add-RiskBlockLedgerEntry $name $trace "batch_verdict_riskblock"
            Write-Host "[batch] RiskBlock detected; stopping current node."
            if ($StopOnRiskBlock) {
                break
            }
        }
        if ($successCount -ge [Math]::Max(1, $MinSuccesses) -and -not $ContinueAfterSuccess) {
            break
        }
        if ($run -lt [Math]::Max(1, $RunsPerNode) -and $PauseBetweenRunsSec -gt 0) {
            Start-Sleep -Seconds $PauseBetweenRunsSec
        }
    }
    if ($successCount -ge [Math]::Max(1, $MinSuccesses) -and -not $ContinueAfterSuccess) {
        break
    }
}

$report = [pscustomobject]@{
    created_at = $stamp
    filter = $Filter
    exclude_filter = $ExcludeFilter
    proxy = $ProxyUrl
    controller = $Controller
    country_label = $CountryLabel
    min_successes = $MinSuccesses
    success_count = $successCount
    network_logs = $batchNetworkLogs
    results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "`n[batch] summary=$summaryPath"
$results | ForEach-Object {
    Write-Host ("  {0} {1} {2}" -f $_.verdict, $_.trace.detail, $_.name)
}

if ($batchNetworkLogs.Count -gt 0) {
    Write-Host "`n[batch] stability check for this batch"
    $verifyArgs = @("verify_1s_stability.py") + $batchNetworkLogs + @("--min-successes", "$MinSuccesses")
    if ($AllowRiskBlockInGate) {
        $verifyArgs += "--allow-riskblock"
    }
    $verifyOut = @(python @verifyArgs 2>&1)
    $verifyExit = $LASTEXITCODE
    $verifyOut | ForEach-Object { Write-Host $_ }
    $diagnoseOut = @(python diagnose_1s_gap.py @batchNetworkLogs --wait-after-ms $WaitAfterMs 2>&1)
    $diagnoseExit = $LASTEXITCODE
    $diagnoseOut | ForEach-Object { Write-Host $_ }
    $auditOut = @(python audit_1s_goal_status.py @batchNetworkLogs --min-successes $MinSuccesses 2>&1)
    $auditExit = $LASTEXITCODE
    $auditOut | ForEach-Object { Write-Host $_ }
    $verifyText = ($verifyOut -join "`n")
    $auditText = ($auditOut -join "`n")
    $stablePass = ($verifyExit -eq 0 -and $verifyText -match "STABLE_PASS")
    $goalComplete = ($auditExit -eq 0 -and $auditText -match "GOAL_COMPLETE")
    $report | Add-Member -Force -MemberType NoteProperty -Name final_gate -Value ([pscustomobject]@{
        verify_exit = $verifyExit
        diagnose_exit = $diagnoseExit
        audit_exit = $auditExit
        stable_pass = $stablePass
        goal_complete = $goalComplete
        verify_output_tail = @($verifyOut | Select-Object -Last 80)
        diagnose_output_tail = @($diagnoseOut | Select-Object -Last 80)
        audit_output_tail = @($auditOut | Select-Object -Last 80)
    })
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Host "[batch] summary updated with final_gate=$summaryPath"
    Write-Host "[batch] final exits verify=$verifyExit diagnose=$diagnoseExit audit=$auditExit"

    Write-Host "`n[batch] strict evidence check for this batch summary"
    $evidenceOut = @(python audit_1s_live_evidence.py $summaryPath --min-successes $MinSuccesses --json 2>&1)
    $evidenceExit = $LASTEXITCODE
    $evidenceOut | ForEach-Object { Write-Host $_ }
    $evidenceText = ($evidenceOut -join "`n")
    $evidenceComplete = ($evidenceExit -eq 0 -and $evidenceText -match "GOAL_EVIDENCE_COMPLETE")
    $evidenceStatus = ""
    try {
        $evidenceJson = $evidenceText | ConvertFrom-Json
        $evidenceStatus = [string]$evidenceJson.status
    } catch {
        $evidenceStatus = if ($evidenceComplete) { "GOAL_EVIDENCE_COMPLETE" } else { "GOAL_EVIDENCE_NOT_COMPLETE" }
    }
    $report | Add-Member -Force -MemberType NoteProperty -Name final_evidence -Value ([pscustomobject]@{
        evidence_exit = $evidenceExit
        evidence_complete = $evidenceComplete
        status = $evidenceStatus
        output_tail = @($evidenceOut | Select-Object -Last 80)
    })
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    Write-Host "[batch] summary updated with final_evidence=$summaryPath"
    Write-Host "[batch] evidence exit=$evidenceExit complete=$evidenceComplete status=$evidenceStatus"
    if ($stablePass -and $goalComplete -and $evidenceComplete) {
        exit 0
    }
    if ($evidenceExit -ne 0) {
        exit $evidenceExit
    }
    if ($auditExit -ne 0) {
        exit $auditExit
    }
    exit $verifyExit
} else {
    Write-Host "[batch] no network logs collected; cannot verify stability."
    $report | Add-Member -Force -MemberType NoteProperty -Name final_gate -Value ([pscustomobject]@{
        verify_exit = 1
        diagnose_exit = $null
        audit_exit = 1
        stable_pass = $false
        goal_complete = $false
        error = "no network logs collected"
    })
    $report | Add-Member -Force -MemberType NoteProperty -Name final_evidence -Value ([pscustomobject]@{
        evidence_exit = 1
        evidence_complete = $false
        status = "GOAL_EVIDENCE_NOT_COMPLETE"
        error = "no network logs collected"
    })
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
    exit 1
}
