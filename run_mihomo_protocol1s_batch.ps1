param(
    [string]$AliveFile = "",
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$ProxyUrl = "http://127.0.0.1:17890",
    [string]$Filter = "^(Game|Web) ",
    [string]$ExcludeFilter = "",
    [switch]$UseControllerNodes,
    [int]$MaxNodes = 5,
    [int]$RunsPerNode = 1,
    [int]$RegisterTimeoutSec = 330,
    [int]$PauseBetweenRunsSec = 6,
    [int]$TargetSuccessCount = 0,
    [switch]$TargetFirstPass,
    [int]$WallMs = 1100,
    [int]$HoldMs = 13000,
    [int]$StopDelayMs = 900,
    [int]$PreDownDwellMs = 900,
    [double]$BotProtectionWaitSec = -1,
    [ValidateSet("outlook", "msal_authorize")]
    [string]$SignupEntryMode = "outlook",
    [ValidateSet("ui", "fast_dom", "semi_protocol", "protocol_assist", "protocol_takeover", "protocol_takeover_thin")]
    [string]$SignupFillMode = "ui",
    [int]$MinRuntimeHookReadyFrames = 6,
    [int]$MinKnpPrestartOk = 5,
    [int]$PreholdHookGuardRetries = 2,
    [int]$PreholdReadinessGateMs = 0,
    [int]$PreholdLoadedMinAgeMs = 0,
    [int]$RealTargetWaitMs = 12000,
    [string]$Config = ".\config.ctf.runtime.protocol1s-adssafe-stab-5-20260705_033428.manual.20260705_033428.json",
    [ValidateSet("none", "optimistic_w0", "defer_final_to_w0", "neutral_fetch_w0", "neutral_merge_w0_success", "neutral_cached_w0_success", "neutral_cached_rich_w0_success", "real_final_neutral_w0_success", "session_cached_rich_final_success", "session_cached_rich_w0_success", "session_cached_rich_final_and_w0_success", "warmup_neutral_then_rich_final_and_w0_success")]
    [string]$W0ResponseMode = "none",
    [int]$W0ResponseWaitMs = 2500,
    [int]$DelayCaptchaCloseMs = 0,
    [int]$CaptchaCloseGraceMs = 0,
    [int]$RiskVerifyGateMs = 0,
    [int]$RiskVerifyGateTimeoutMs = 1500,
    [int]$RiskVerifyHumanSuccessAgeMs = 0,
    [int]$RiskVerifyHumanSuccessTimeoutMs = 0,
    [string]$RiskBlockLedger = ".\.mihomo-isolated\riskblock_protocol1s.json",
    [string]$OutcomeLedger = ".\.mihomo-isolated\protocol1s_outcomes.jsonl",
    [string]$QuarantineVerdicts = "riskblock",
    [int]$RecentOutcomeWindowMinutes = 360,
    [int]$MaxRecentSuccessesPerIp = 0,
    [int]$TraceRetries = 2,
    [switch]$IgnoreRiskBlockLedger,
    [switch]$IgnoreOutcomeLedger,
    [switch]$ContinueNodeAfterRiskBlock,
    [switch]$PreserveFinalBfa,
    [switch]$OptimisticFinalSuccess,
    [switch]$RewriteFinalResultSuccess,
    [switch]$TriggerFinalSuccessSignals,
    [switch]$RiskVerifyChallengeToContinue,
    [switch]$AllowSecondAttempt,
    [switch]$ContinueAfterSuccess,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

$script:quarantineVerdictSet = @{}
foreach ($v in ($QuarantineVerdicts -split ",")) {
    $key = ([string]$v).Trim().ToLowerInvariant()
    if ($key) { $script:quarantineVerdictSet[$key] = $true }
}

$script:riskBlockedEntries = @()
if (-not $IgnoreRiskBlockLedger -and (Test-Path -LiteralPath $RiskBlockLedger)) {
    try {
        $loaded = Get-Content -LiteralPath $RiskBlockLedger -Raw -Encoding UTF8 | ConvertFrom-Json
        $script:riskBlockedEntries = @($loaded)
        Write-Host "[protocol1s-batch] loaded riskblock ledger=$RiskBlockLedger entries=$($script:riskBlockedEntries.Count)"
    } catch {
        Write-Host "[protocol1s-batch] failed to read riskblock ledger: $($_.Exception.Message)"
        $script:riskBlockedEntries = @()
    }
}

$script:outcomeEntries = @()
if (-not $IgnoreOutcomeLedger -and (Test-Path -LiteralPath $OutcomeLedger)) {
    try {
        $loadedOutcomes = @()
        foreach ($line in Get-Content -LiteralPath $OutcomeLedger -Encoding UTF8) {
            if (-not $line.Trim()) { continue }
            try { $loadedOutcomes += ($line | ConvertFrom-Json) } catch {}
        }
        $script:outcomeEntries = @($loadedOutcomes)
        Write-Host "[protocol1s-batch] loaded outcome ledger=$OutcomeLedger entries=$($script:outcomeEntries.Count)"
    } catch {
        Write-Host "[protocol1s-batch] failed to read outcome ledger: $($_.Exception.Message)"
        $script:outcomeEntries = @()
    }
}

function Test-RiskBlockedNode([string]$Name, [string]$Ip = "") {
    if ($IgnoreRiskBlockLedger) { return $false }
    foreach ($entry in @($script:riskBlockedEntries)) {
        $entryName = [string]($entry.name)
        $entryIp = [string]($entry.egress_ip)
        if ($entryName -and $entryName -eq $Name) { return $true }
        if ($Ip -and $entryIp -and $entryIp -eq $Ip) { return $true }
    }
    return $false
}

function Test-RecentSuccessLimitedNode([string]$Name, [string]$Ip = "") {
    if ($IgnoreOutcomeLedger -or $MaxRecentSuccessesPerIp -le 0) { return $false }
    $cutoff = (Get-Date).AddMinutes(-[Math]::Max(1, $RecentOutcomeWindowMinutes))
    $count = 0
    foreach ($entry in @($script:outcomeEntries)) {
        $saved = $null
        try { $saved = [datetime]::Parse([string]$entry.saved_at) } catch { $saved = $null }
        if ($saved -and $saved -lt $cutoff) { continue }
        $verdict = [string]($entry.verdict)
        if ($verdict -ne "create_account_200") { continue }
        $entryName = [string]($entry.name)
        $entryIp = [string]($entry.egress_ip)
        if ($entryName -and $entryName -eq $Name) { $count += 1; continue }
        if ($Ip -and $entryIp -and $entryIp -eq $Ip) { $count += 1; continue }
    }
    return ($count -ge $MaxRecentSuccessesPerIp)
}

function Add-RiskBlockLedgerEntry([string]$Name, $Trace, [string]$Reason) {
    if ($IgnoreRiskBlockLedger) { return }
    $ip = ""
    $loc = ""
    try {
        if ($Trace -and $Trace.ip) { $ip = [string]$Trace.ip }
        if ($Trace -and $Trace.loc) { $loc = [string]$Trace.loc }
    } catch {}
    if (Test-RiskBlockedNode $Name $ip) { return }
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
    Write-Host "[protocol1s-batch] recorded riskblock ledger name=$Name ip=$ip reason=$Reason"
}

function Add-OutcomeLedgerEntry([string]$Name, $Trace, [string]$Verdict, [bool]$FirstPassOk, [bool]$CaptchaProtocolOk, [int]$ExitCode, [string[]]$NetworkLogs) {
    if ($IgnoreOutcomeLedger -or -not $OutcomeLedger) { return }
    $ip = ""
    $loc = ""
    try {
        if ($Trace -and $Trace.ip) { $ip = [string]$Trace.ip }
        if ($Trace -and $Trace.loc) { $loc = [string]$Trace.loc }
    } catch {}
    $entry = [pscustomobject]@{
        saved_at = (Get-Date).ToString("o")
        name = $Name
        egress_ip = $ip
        loc = $loc
        verdict = $Verdict
        firstpass_ok = [bool]$FirstPassOk
        captcha_protocol_ok = [bool]$CaptchaProtocolOk
        exit = $ExitCode
        network_logs = @($NetworkLogs)
    }
    $dir = Split-Path -Parent $OutcomeLedger
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    ($entry | ConvertTo-Json -Depth 6 -Compress) | Add-Content -LiteralPath $OutcomeLedger -Encoding UTF8
    $script:outcomeEntries = @($script:outcomeEntries) + @($entry)
}

function Test-QuarantineVerdict([string]$Verdict) {
    $key = ([string]$Verdict).Trim().ToLowerInvariant()
    if (-not $key) { return $false }
    return $script:quarantineVerdictSet.ContainsKey($key)
}

function Get-LatestAliveFile {
    if ($AliveFile) {
        return Get-Item -LiteralPath $AliveFile -ErrorAction Stop
    }
    return Get-ChildItem -LiteralPath ".\.mihomo-isolated" -Filter "alive_*.json" -ErrorAction Stop |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1
}

function Get-AliveNodes {
    if ($UseControllerNodes) {
        Write-Host "[protocol1s-batch] source=controller controller=$Controller group=$Group"
        $groupObj = Invoke-RestMethod -Uri "$Controller/proxies/$([uri]::EscapeDataString($Group))" -Method Get
        $rx = [regex]::new($Filter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $excludeRx = if ($ExcludeFilter) { [regex]::new($ExcludeFilter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) } else { $null }
        $nodes = @()
        foreach ($nameObj in @($groupObj.all)) {
            $name = [string]$nameObj
            if (-not $name) { continue }
            if (-not $rx.IsMatch($name)) { continue }
            if ($excludeRx -and $excludeRx.IsMatch($name)) { continue }
            if (Test-RiskBlockedNode $name "") { continue }
            if (Test-RecentSuccessLimitedNode $name "") { continue }
            $nodes += [pscustomobject]@{ name=$name; delay=$null; ip=""; trace_ok=$true }
            if ($nodes.Count -ge [Math]::Max(1, $MaxNodes)) { break }
        }
        return @($nodes)
    }
    $file = Get-LatestAliveFile
    $data = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    Write-Host "[protocol1s-batch] alive_file=$($file.FullName) alive_count=$($data.alive_count)"
    $rx = [regex]::new($Filter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $excludeRx = if ($ExcludeFilter) { [regex]::new($ExcludeFilter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase) } else { $null }
    $seenIp = @{}
    $nodes = @()
    foreach ($n in @($data.alive | Sort-Object delay)) {
        $name = [string]$n.name
        $ip = [string]$n.ip
        if (-not $name -or -not $n.trace_ok) { continue }
        if (-not $rx.IsMatch($name)) { continue }
        if ($excludeRx -and $excludeRx.IsMatch($name)) { continue }
        if (Test-RiskBlockedNode $name $ip) { continue }
        if (Test-RecentSuccessLimitedNode $name $ip) { continue }
        if ($ip -and $seenIp.ContainsKey($ip)) { continue }
        if ($ip) { $seenIp[$ip] = $true }
        $nodes += $n
        if ($nodes.Count -ge [Math]::Max(1, $MaxNodes)) { break }
    }
    return @($nodes)
}

function Switch-Node([string]$Name) {
    $uri = "$Controller/proxies/$([uri]::EscapeDataString($Group))"
    $body = @{ name = $Name } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Put -Uri $uri -ContentType "application/json; charset=utf-8" -Body $body | Out-Null
}

function Invoke-TraceProbe {
    try {
        $py = @'
import json, re, sys, urllib.request
proxy = sys.argv[1]
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    req = urllib.request.Request("https://www.cloudflare.com/cdn-cgi/trace", headers={"User-Agent":"Mozilla/5.0"})
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
        return ($py | python - $ProxyUrl | ConvertFrom-Json)
    } catch {
        return [pscustomobject]@{ ok = $false; ip = ""; loc = ""; detail = $_.Exception.Message }
    }
}

function Get-RunClassification([string[]]$LogPaths) {
    if (-not $LogPaths -or $LogPaths.Count -eq 0) {
        return $null
    }
    try {
        # Use the newest network capture for this run.  A timed-out attempt can
        # leave multiple captures (for example result0 followed by re-challenge);
        # the machine-readable classifier pairs it with the nearest route/live
        # logs instead of grepping the whole console tail.
        $latest = $LogPaths |
            ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } |
            Where-Object { $_ } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if (-not $latest) { return $null }
        $raw = & python .\classify_protocol_run.py $latest.FullName 2>$null
        if (-not $raw) { return $null }
        return ($raw | ConvertFrom-Json)
    } catch {
        Write-Host "[protocol1s-batch] classify failed: $($_.Exception.Message)"
        return $null
    }
}

function Test-FirstPassOk([string]$Verdict, $Classification) {
    if ($Verdict -ne "create_account_200") { return $false }
    if (-not $Classification) { return $false }
    $merged = @()
    $finalShapes = @()
    $neutralCount = 0
    $humanLoaded = 0
    $humanSuccess = 0
    try { $merged = @($Classification.route_merged_results) } catch {}
    try { $finalShapes = @($Classification.final_shapes) } catch {}
    try { $neutralCount = [int]($Classification.real_final_neutral_w0) } catch {}
    try { $humanLoaded = [int]($Classification.human_loaded) } catch {}
    try { $humanSuccess = [int]($Classification.human_success) } catch {}
    $singleChallenge = ($humanLoaded -le 1 -and $humanSuccess -le 1)
    return (($merged -contains "oIIoIooo|0") -and ($neutralCount -gt 0) -and ($finalShapes.Count -gt 0) -and $singleChallenge)
}

function Test-CaptchaProtocolOk([string]$Verdict, $Classification) {
    if ($Verdict -ne "create_account_200") { return $false }
    if (-not $Classification) { return $false }
    $merged = @()
    $finalShapes = @()
    $neutralCount = 0
    try { $merged = @($Classification.route_merged_results) } catch {}
    try { $finalShapes = @($Classification.final_shapes) } catch {}
    try { $neutralCount = [int]($Classification.real_final_neutral_w0) } catch {}
    return (($merged -contains "oIIoIooo|0") -and ($neutralCount -gt 0) -and ($finalShapes.Count -gt 0))
}

$nodes = @(Get-AliveNodes)
if (-not $nodes -or $nodes.Count -eq 0) {
    throw "no alive nodes matched filter=$Filter exclude=$ExcludeFilter"
}

if ($SignupFillMode -in @("protocol_takeover", "protocol_takeover_thin")) {
    # V1 protocol takeover still uses the real hsprotect challenge.  The
    # successful semi-protocol baseline shows the host accepts the captcha path
    # most reliably when final stays neutral and the follow-up W0 carries
    # result|0, with risk/verify serialized behind that handoff.  Keep callers
    # overrideable, but make the safer baseline the default for V1 batches.
    if ($W0ResponseMode -eq "none") { $W0ResponseMode = "real_final_neutral_w0_success" }
    if ($DelayCaptchaCloseMs -le 0) { $DelayCaptchaCloseMs = 8000 }
    if ($PreholdReadinessGateMs -le 0) { $PreholdReadinessGateMs = 1800 }
    if ($RealTargetWaitMs -eq 12000) { $RealTargetWaitMs = 20000 }
    if (-not $PSBoundParameters.ContainsKey("RiskVerifyGateMs") -and $RiskVerifyGateMs -le 0) { $RiskVerifyGateMs = 1450 }
    if (-not $PSBoundParameters.ContainsKey("RiskVerifyGateTimeoutMs") -and $RiskVerifyGateTimeoutMs -le 1500) { $RiskVerifyGateTimeoutMs = 9000 }
    if (-not $PSBoundParameters.ContainsKey("RiskVerifyHumanSuccessAgeMs") -and $RiskVerifyHumanSuccessAgeMs -le 0) { $RiskVerifyHumanSuccessAgeMs = 650 }
    if (-not $PSBoundParameters.ContainsKey("RiskVerifyHumanSuccessTimeoutMs") -and $RiskVerifyHumanSuccessTimeoutMs -le 0) { $RiskVerifyHumanSuccessTimeoutMs = 3000 }
    if (-not $PreserveFinalBfa) { $PreserveFinalBfa = $true }
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$summaryPath = Join-Path "Results\protocol_runtime" "mihomo_protocol1s_batch_$stamp.json"
$results = @()
$successCount = 0
$firstPassCount = 0
$captchaProtocolOkCount = 0
$seenTraceIp = @{}

Write-Host "[protocol1s-batch] nodes=$($nodes.Count) runs_per_node=$RunsPerNode target_success=$TargetSuccessCount target_firstpass=$TargetFirstPass wall=$WallMs hold=$HoldMs entry=$SignupEntryMode fill=$SignupFillMode riskGate=$RiskVerifyGateMs/$RiskVerifyGateTimeoutMs humanSuccessGate=$RiskVerifyHumanSuccessAgeMs/$RiskVerifyHumanSuccessTimeoutMs quarantine=$QuarantineVerdicts maxRecentSuccessIp=$MaxRecentSuccessesPerIp/$RecentOutcomeWindowMinutes config=$Config"

$nodeOrdinal = 0
foreach ($node in $nodes) {
    $nodeOrdinal += 1
    $name = [string]$node.name
    Write-Host "`n[protocol1s-batch] switch node=$name delay=$($node.delay) ip=$($node.ip)"
    if (-not $DryRun) {
        Switch-Node $name
        Start-Sleep -Milliseconds 900
    }
    $trace = if ($DryRun) { [pscustomobject]@{ ok = $true; ip = [string]$node.ip; loc = [string]$node.loc; detail = "dryrun" } } else { $null }
    if (-not $DryRun) {
        $tries = [Math]::Max(1, $TraceRetries)
        for ($traceTry = 1; $traceTry -le $tries; $traceTry++) {
            $trace = Invoke-TraceProbe
            if ($trace.ok) { break }
            if ($traceTry -lt $tries) {
                Write-Host "[protocol1s-batch] trace retry $traceTry/$tries failed: $($trace.detail)"
                Start-Sleep -Milliseconds 800
            }
        }
    }
    Write-Host "[protocol1s-batch] trace ok=$($trace.ok) $($trace.detail)"
    if (-not $trace.ok) {
        $results += [pscustomobject]@{ name=$name; trace=$trace; verdict="trace_fail"; exit=$null; network_logs=@() }
        continue
    }
    if (Test-RiskBlockedNode $name ([string]$trace.ip)) {
        Write-Host "[protocol1s-batch] skip riskblocked node/ip name=$name ip=$($trace.ip)"
        $results += [pscustomobject]@{ name=$name; trace=$trace; verdict="riskblock_ledger_skip"; exit=$null; network_logs=@() }
        continue
    }
    if (Test-RecentSuccessLimitedNode $name ([string]$trace.ip)) {
        Write-Host "[protocol1s-batch] skip recent-success-limited node/ip name=$name ip=$($trace.ip)"
        $results += [pscustomobject]@{ name=$name; trace=$trace; verdict="recent_success_skip"; exit=$null; network_logs=@() }
        continue
    }
    if ($trace.ip -and $seenTraceIp.ContainsKey([string]$trace.ip)) {
        Write-Host "[protocol1s-batch] skip duplicate trace ip=$($trace.ip) previous=$($seenTraceIp[[string]$trace.ip])"
        $results += [pscustomobject]@{ name=$name; trace=$trace; verdict="trace_ip_duplicate_skip"; exit=$null; network_logs=@() }
        continue
    }
    if ($trace.ip) { $seenTraceIp[[string]$trace.ip] = $name }

    for ($run = 1; $run -le [Math]::Max(1, $RunsPerNode); $run++) {
        $profilePrefix = "protocol1s-adssafe-batch-$($stamp)-n$($nodeOrdinal)-r$run"
        $scriptArgs = @(
            "-ExecutionPolicy", "Bypass",
            "-File", ".\run_1s_protocol_restart_once.ps1",
            "-WallMs", "$WallMs",
            "-HoldMs", "$HoldMs",
            "-StopDelayMs", "$StopDelayMs",
            "-PreDownDwellMs", "$PreDownDwellMs",
            "-FinalProofNormalizer", "ads_safe",
            "-W0Policy", "after160",
            "-NoSyntheticU0",
            "-HybridLegacyDownCdpMoveUp",
            "-LegacyShortHoldSteps", "24",
            "-RequireChctxRuntimeReady",
            "-MinRuntimeHookReadyFrames", "$MinRuntimeHookReadyFrames",
            "-MinKnpPrestartOk", "$MinKnpPrestartOk",
            "-PreholdHookGuardRetries", "$PreholdHookGuardRetries",
            "-PreholdReadinessGateMs", "$PreholdReadinessGateMs",
            "-PreholdLoadedMinAgeMs", "$PreholdLoadedMinAgeMs",
            "-RealTargetWaitMs", "$RealTargetWaitMs",
            "-RetryAfterMs", "7000",
            "-FreshProfilePrefix", $profilePrefix,
            "-Config", $Config
        )
        if ($BotProtectionWaitSec -ge 0) { $scriptArgs += @("-BotProtectionWaitSec", "$BotProtectionWaitSec") }
        if ($SignupEntryMode -ne "outlook") { $scriptArgs += @("-SignupEntryMode", $SignupEntryMode) }
        if ($SignupFillMode -ne "ui") { $scriptArgs += @("-SignupFillMode", $SignupFillMode) }
        if ($W0ResponseMode -ne "none") { $scriptArgs += @("-W0ResponseMode", $W0ResponseMode, "-W0ResponseWaitMs", "$W0ResponseWaitMs") }
        if ($DelayCaptchaCloseMs -gt 0) { $scriptArgs += @("-DelayCaptchaCloseMs", "$DelayCaptchaCloseMs") }
        if ($CaptchaCloseGraceMs -gt 0) { $scriptArgs += @("-CaptchaCloseGraceMs", "$CaptchaCloseGraceMs") }
        if ($RiskVerifyGateMs -gt 0) { $scriptArgs += @("-RiskVerifyGateMs", "$RiskVerifyGateMs", "-RiskVerifyGateTimeoutMs", "$RiskVerifyGateTimeoutMs") }
        if ($RiskVerifyHumanSuccessAgeMs -gt 0) { $scriptArgs += @("-RiskVerifyHumanSuccessAgeMs", "$RiskVerifyHumanSuccessAgeMs", "-RiskVerifyHumanSuccessTimeoutMs", "$RiskVerifyHumanSuccessTimeoutMs") }
        if ($PreserveFinalBfa) { $scriptArgs += "-PreserveFinalBfa" }
        if ($OptimisticFinalSuccess) { $scriptArgs += "-OptimisticFinalSuccess" }
        if ($RewriteFinalResultSuccess) { $scriptArgs += "-RewriteFinalResultSuccess" }
        if ($TriggerFinalSuccessSignals) { $scriptArgs += "-TriggerFinalSuccessSignals" }
        if ($RiskVerifyChallengeToContinue) { $scriptArgs += "-RiskVerifyChallengeToContinue" }
        if ($AllowSecondAttempt) { $scriptArgs += "-AllowSecondAttempt" }
        Write-Host "[protocol1s-batch] run $run/$RunsPerNode powershell $($scriptArgs -join ' ')"
        if ($DryRun) { continue }

        $before = @(Get-ChildItem -LiteralPath "Results\network" -Filter "*.jsonl" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $job = Start-Job -ScriptBlock {
            param($WorkDir, $ArgsList)
            Set-Location -LiteralPath $WorkDir
            $env:PYTHONIOENCODING = "utf-8"
            $output = & powershell @ArgsList 2>&1 | Out-String
            [pscustomobject]@{ Output=$output; ExitCode=$LASTEXITCODE }
        } -ArgumentList (Get-Location).Path, $scriptArgs
        Wait-Job -Job $job -Timeout $RegisterTimeoutSec | Out-Null
        if ($job.State -eq "Running") {
            Stop-Job -Job $job | Out-Null
            $out = "[protocol1s-batch] timeout after ${RegisterTimeoutSec}s"
            $exitCode = 124
        } else {
            $jr = Receive-Job -Job $job
            $out = [string]$jr.Output
            $exitCode = [int]$jr.ExitCode
        }
        Remove-Job -Job $job -Force -ErrorAction SilentlyContinue | Out-Null
        $after = @(Get-ChildItem -LiteralPath "Results\network" -Filter "*.jsonl" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName)
        $newLogs = @($after | Where-Object { $before -notcontains $_ } | Sort-Object)

        $tail = ($out -split "`r?`n" | Select-Object -Last 70) -join "`n"
        Write-Host $tail

        $verdict = "failed"
        $classification = Get-RunClassification $newLogs
        if ($out -match "CloakBrowser launch failed|browser launch failed|Unsupported platform|object has no attribute 'new_page'") {
            $verdict = "browser_launch_error"
        } elseif ($out -match "\[Success: Email Registration\]") {
            $verdict = "create_account_200"
        } elseif ($out -match "signup\.live\.com/API/CreateAccount" -and $out -match "response POST status=200") {
            $verdict = "create_http_200_unverified"
        } elseif ($out -match "RiskBlock|status=403|state=blocked|Abuse|Enforcement") {
            $verdict = "riskblock"
        } elseif ($out -match "oIIoIooo\\|-1|collector_result=\\-1") {
            $verdict = "collector_minus1"
        } elseif ($out -match "collector_result=0|HumanCaptcha_Success|oIIoIooo\\|0") {
            $verdict = "result0_no_create"
        }
        if ($classification -and $classification.verdict) {
            $preciseVerdict = [string]$classification.verdict
            if ($preciseVerdict -ne $verdict) {
                Write-Host "[protocol1s-batch] precise_verdict=$preciseVerdict fallback_verdict=$verdict"
            }
            if (-not ($verdict -eq "create_account_200" -and $preciseVerdict -ne "create_account_200")) {
                $verdict = $preciseVerdict
            }
        }
        if ($verdict -eq "create_account_200") { $successCount += 1 }
        Write-Host "[protocol1s-batch] exit=$exitCode verdict=$verdict success_count=$successCount"
        $quarantineThisNode = Test-QuarantineVerdict $verdict
        if ($quarantineThisNode) {
            Add-RiskBlockLedgerEntry $name $trace $verdict
        }
        $firstPassOk = Test-FirstPassOk $verdict $classification
        if ($firstPassOk) { $firstPassCount += 1 }
        $captchaProtocolOk = Test-CaptchaProtocolOk $verdict $classification
        if ($captchaProtocolOk) { $captchaProtocolOkCount += 1 }
        Add-OutcomeLedgerEntry $name $trace $verdict $firstPassOk $captchaProtocolOk $exitCode $newLogs
        $results += [pscustomobject]@{
            name = $name
            run = $run
            trace = $trace
            exit = $exitCode
            verdict = $verdict
            firstpass_ok = $firstPassOk
            captcha_protocol_ok = $captchaProtocolOk
            network_logs = $newLogs
            classification = $classification
        }
        if ($quarantineThisNode -and -not $ContinueNodeAfterRiskBlock) {
            Write-Host "[protocol1s-batch] stop current node after quarantined verdict=$verdict; switching to next node/ip"
            break
        }
        if ($run -lt [Math]::Max(1, $RunsPerNode) -and $PauseBetweenRunsSec -gt 0) {
            Start-Sleep -Seconds $PauseBetweenRunsSec
        }
    }
    $targetMetric = if ($TargetFirstPass) { $firstPassCount } else { $successCount }
    if ($TargetSuccessCount -gt 0 -and $targetMetric -ge $TargetSuccessCount) { break }
    if ($successCount -gt 0 -and -not $ContinueAfterSuccess -and $TargetSuccessCount -le 0) { break }
}

$report = [pscustomobject]@{
    created_at = $stamp
    filter = $Filter
    exclude_filter = $ExcludeFilter
    controller = $Controller
    group = $Group
    proxy = $ProxyUrl
    quarantine_verdicts = $QuarantineVerdicts
    outcome_ledger = $OutcomeLedger
    recent_outcome_window_minutes = $RecentOutcomeWindowMinutes
    max_recent_successes_per_ip = $MaxRecentSuccessesPerIp
    success_count = $successCount
    firstpass_count = $firstPassCount
    captcha_protocol_ok_count = $captchaProtocolOkCount
    target_firstpass = [bool]$TargetFirstPass
    results = $results
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
Write-Host "`n[protocol1s-batch] summary=$summaryPath"
$results | ForEach-Object { Write-Host ("  {0} {1} {2}" -f $_.verdict, $_.trace.detail, $_.name) }
if ($DryRun) { exit 0 }
if ($TargetSuccessCount -gt 0) {
    $targetMetric = if ($TargetFirstPass) { $firstPassCount } else { $successCount }
    if ($targetMetric -ge $TargetSuccessCount) { exit 0 }
    exit 2
}
if ($successCount -gt 0) { exit 0 }
exit 1
