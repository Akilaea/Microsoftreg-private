param(
    [string]$Email = "",
    [string]$Password = ""
)

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$argsList = @("main.py", "--config", "config.ctf.trace.json", "--max-tasks", "1", "--concurrent", "1")
if ($Email) {
    $argsList += @("--email", $Email)
}
if ($Password) {
    $argsList += @("--password", $Password)
}

python @argsList
