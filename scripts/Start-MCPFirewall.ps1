[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path (Split-Path $PSScriptRoot -Parent) "config\firewall.json"),
    [switch]$VerboseLogging
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) {
    $Python = $VenvPython
} else {
    $Python = "python"
}

$ResolvedConfig = (Resolve-Path $ConfigPath).Path
$env:PYTHONPATH = Join-Path $ProjectRoot "src"
$arguments = @("-m", "mcp_firewall", "--config", $ResolvedConfig)
if ($VerboseLogging) { $arguments += "--verbose" }

Write-Host "[MCP Firewall] Starting stdio proxy. Protocol traffic uses stdout; logs use stderr." -ForegroundColor Cyan
& $Python @arguments
exit $LASTEXITCODE
