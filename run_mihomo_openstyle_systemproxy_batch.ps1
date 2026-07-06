param(
    [string]$AliveFile = "",
    [string]$Controller = "http://127.0.0.1:19090",
    [string]$Group = "AUTO_TEST",
    [string]$SystemProxyServer = "127.0.0.1:17890",
    [string]$Filter = "",
    [string]$ExcludeFilter = "",
    [int]$MaxNodes = 0,
    [switch]$NonRoFirst,
    [switch]$StopOnPromising,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$env:PYTHONIOENCODING = "utf-8"

function Get-LatestAliveFile {
    if ($AliveFile) {
        return (Get-Item -LiteralPath $AliveFile -ErrorAction Stop)
    }
    return (Get-ChildItem -LiteralPath ".\.mihomo-isolated" -Filter "alive_*.json" -ErrorAction Stop |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1)
}

function Invoke-MihomoSwitch([string]$Name) {
    $uri = "$Controller/proxies/$([uri]::EscapeDataString($Group))"
    $body = @{ name = $Name } | ConvertTo-Json -Compress
    Invoke-RestMethod -Method Put -Uri $uri -ContentType "application/json; charset=utf-8" -Body $body -TimeoutSec 8 | Out-Null
}

function Get-TzForLoc([string]$Loc) {
    switch -Regex ($Loc) {
        '^US$' { return "America/Los_Angeles" }
        '^HK$' { return "Asia/Hong_Kong" }
        '^TW$' { return "Asia/Taipei" }
        '^SG$' { return "Asia/Singapore" }
        '^JP$' { return "Asia/Tokyo" }
        '^NL$' { return "Europe/Amsterdam" }
        '^FR$' { return "Europe/Paris" }
        '^DE$' { return "Europe/Berlin" }
        '^GB$' { return "Europe/London" }
        '^CH$' { return "Europe/Zurich" }
        '^RO$' { return "Europe/Bucharest" }
        default { return "UTC" }
    }
}

function Get-ProxyState {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    $p = Get-ItemProperty -LiteralPath $key
    return [pscustomobject]@{
        ProxyEnable = $p.ProxyEnable
        ProxyServer = $p.ProxyServer
        ProxyOverride = $p.ProxyOverride
        AutoConfigURL = $p.AutoConfigURL
    }
}

function Set-SystemProxy([string]$Server) {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    Set-ItemProperty -LiteralPath $key -Name ProxyEnable -Type DWord -Value 1
    Set-ItemProperty -LiteralPath $key -Name ProxyServer -Type String -Value $Server
    Set-ItemProperty -LiteralPath $key -Name ProxyOverride -Type String -Value "<local>;localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*"
}

function Restore-SystemProxy($State) {
    $key = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    if ($null -ne $State.ProxyEnable) {
        Set-ItemProperty -LiteralPath $key -Name ProxyEnable -Type DWord -Value ([int]$State.ProxyEnable)
    }
    if ($State.ProxyServer) {
        Set-ItemProperty -LiteralPath $key -Name ProxyServer -Type String -Value ([string]$State.ProxyServer)
    } else {
        Remove-ItemProperty -LiteralPath $key -Name ProxyServer -ErrorAction SilentlyContinue
    }
    if ($State.ProxyOverride) {
        Set-ItemProperty -LiteralPath $key -Name ProxyOverride -Type String -Value ([string]$State.ProxyOverride)
    } else {
        Remove-ItemProperty -LiteralPath $key -Name ProxyOverride -ErrorAction SilentlyContinue
    }
    if ($State.AutoConfigURL) {
        Set-ItemProperty -LiteralPath $key -Name AutoConfigURL -Type String -Value ([string]$State.AutoConfigURL)
    }
}

function Classify-Output([string]$Text, [int]$Code) {
    if ($Text -match "Success: Email Registration|outlook_register result=True|CreateAccount.*status=200") {
        return "success_or_create200"
    }
    if ($Text -match "state=blocked|RiskBlock|当前IP注册频率过快|异常活动|阻止创建") {
        return "riskblock"
    }
    if ($Text -match "aborting during prewait because score\|1 detected") {
        return "score1_early_stop"
    }
    if ($Text -match "state=challenge|HumanCaptcha iframe|located hold button") {
        return "challenge_no_success"
    }
    if ($Code -ne 0) {
        return "failed"
    }
    return "unknown"
}

$aliveItem = Get-LatestAliveFile
$data = Get-Content -LiteralPath $aliveItem.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
$nodes = @($data.alive)
if ($Filter) {
    $rx = [regex]::new($Filter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $nodes = @($nodes | Where-Object { $rx.IsMatch([string]$_.name) -or $rx.IsMatch([string]$_.loc) -or $rx.IsMatch([string]$_.ip) })
}
if ($ExcludeFilter) {
    $erx = [regex]::new($ExcludeFilter, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    $nodes = @($nodes | Where-Object { -not ($erx.IsMatch([string]$_.name) -or $erx.IsMatch([string]$_.loc) -or $erx.IsMatch([string]$_.ip)) })
}
if ($NonRoFirst) {
    $nodes = @($nodes | Sort-Object @{Expression={ if ($_.loc -eq "RO") { 1 } else { 0 } }}, delay)
}
if ($MaxNodes -gt 0) {
    $nodes = @($nodes | Select-Object -First $MaxNodes)
}

$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
$summaryPath = Join-Path "Results\protocol_runtime" "mihomo_openstyle_systemproxy_batch_$stamp.json"
$logDir = Join-Path "Results\protocol_runtime" "mihomo_openstyle_systemproxy_$stamp"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

Write-Host "[sysproxy-batch] alive=$($aliveItem.FullName) total_selected=$($nodes.Count) proxy=$SystemProxyServer dry=$($DryRun.IsPresent)"
Write-Host "[sysproxy-batch] summary=$summaryPath"

if ($DryRun) {
    $nodes | Select-Object -First 30 | ForEach-Object {
        Write-Host ("  {0}ms {1} {2} {3}" -f $_.delay, $_.loc, $_.ip, $_.name)
    }
    exit 0
}

try {
    Invoke-RestMethod -Uri "$Controller/proxies" -TimeoutSec 5 | Out-Null
} catch {
    throw "mihomo controller not reachable: $($_.Exception.Message)"
}

$oldProxy = Get-ProxyState
$results = @()
try {
    Write-Host "[sysproxy-batch] enabling Windows system proxy: $SystemProxyServer"
    Set-SystemProxy $SystemProxyServer
    Start-Sleep -Milliseconds 800

    for ($i = 0; $i -lt $nodes.Count; $i++) {
        $node = $nodes[$i]
        $name = [string]$node.name
        $loc = [string]$node.loc
        $tz = Get-TzForLoc $loc
        Write-Host ""
        Write-Host ("[sysproxy-batch] [{0}/{1}] switch {2} {3} {4}" -f ($i + 1), $nodes.Count, $loc, $node.ip, $name)
        $verdict = "not_run"
        $exitCode = $null
        $outPath = Join-Path $logDir ("{0:D3}_{1}_{2}.log" -f ($i + 1), ($loc -replace '[^\w-]','_'), ((Get-Date).ToString("HHmmss")))
        try {
            Invoke-MihomoSwitch $name
            Start-Sleep -Milliseconds 1000
            $prefix = "cloak-openstyle-mihomo-$($loc.ToLower())-$stamp-$($i+1)"
            $cmdArgs = @(
                "-ExecutionPolicy", "Bypass",
                "-File", ".\run_protocol_cloak_openstyle_once.ps1",
                "-FreshProfilePrefix", $prefix,
                "-CloakHumanPreset", "default",
                "-TimezoneId", $tz
            )
            # CloakBrowser prints its "Update available" notice on stderr even
            # for normal runs.  Use Start-Process with redirected files so that
            # PowerShell does not convert native stderr into a terminating
            # error under $ErrorActionPreference=Stop.
            $stdoutPath = "$outPath.stdout"
            $stderrPath = "$outPath.stderr"
            $proc = Start-Process -FilePath "powershell" -ArgumentList $cmdArgs -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
            $exitCode = $proc.ExitCode
            $text = ""
            if (Test-Path -LiteralPath $stdoutPath) {
                $text += (Get-Content -LiteralPath $stdoutPath -Raw -Encoding UTF8)
            }
            if (Test-Path -LiteralPath $stderrPath) {
                $text += "`n[stderr]`n"
                $text += (Get-Content -LiteralPath $stderrPath -Raw -Encoding UTF8)
            }
            $text | Set-Content -LiteralPath $outPath -Encoding UTF8
            $verdict = Classify-Output $text $exitCode
            Write-Host ("[sysproxy-batch] verdict={0} exit={1} log={2}" -f $verdict, $exitCode, $outPath)
            if ($verdict -eq "success_or_create200" -and $StopOnPromising) {
                $results += [pscustomobject]@{ idx=$i+1; name=$name; loc=$loc; ip=[string]$node.ip; delay=$node.delay; timezone=$tz; exit=$exitCode; verdict=$verdict; log=$outPath }
                break
            }
        } catch {
            $verdict = "exception"
            $exitCode = -999
            $_.Exception.ToString() | Set-Content -LiteralPath $outPath -Encoding UTF8
            Write-Host "[sysproxy-batch] exception: $($_.Exception.Message)"
        }
        $results += [pscustomobject]@{ idx=$i+1; name=$name; loc=$loc; ip=[string]$node.ip; delay=$node.delay; timezone=$tz; exit=$exitCode; verdict=$verdict; log=$outPath }
        $results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
        Start-Sleep -Seconds 2
    }
} finally {
    Write-Host "[sysproxy-batch] restoring Windows system proxy"
    Restore-SystemProxy $oldProxy
    $results | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $summaryPath -Encoding UTF8
}

$counts = @{}
foreach ($r in $results) {
    if (-not $counts.ContainsKey($r.verdict)) { $counts[$r.verdict] = 0 }
    $counts[$r.verdict] += 1
}
Write-Host "[sysproxy-batch] done count=$($results.Count) summary=$summaryPath"
$counts.GetEnumerator() | Sort-Object Name | ForEach-Object { Write-Host ("  {0}: {1}" -f $_.Key, $_.Value) }
