[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"
if (Test-Path $VenvPython) { $Python = $VenvPython } else { $Python = "python" }
$env:PYTHONPATH = Join-Path $ProjectRoot "src"

Write-Host "[MCP Firewall] Running unit tests..." -ForegroundColor Cyan
Push-Location $ProjectRoot
try {
    & $Python -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "One or more tests failed." }
    & $Python -m mcp_firewall --config "config\firewall.json" --check-config
    if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }
} finally {
    Pop-Location
}
Write-Host "[MCP Firewall] All checks passed." -ForegroundColor Green
