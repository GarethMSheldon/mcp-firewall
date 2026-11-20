[CmdletBinding()]
param(
    [string]$PythonCommand = "python"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$VenvPython = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

Write-Host "[MCP Firewall] Checking Python..." -ForegroundColor Cyan
$versionText = & $PythonCommand -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
if ($LASTEXITCODE -ne 0) {
    throw "Python was not found. Install Python 3.11 or newer, then rerun this script."
}
$version = [version]$versionText
if ($version -lt [version]"3.11") {
    throw "Python 3.11 or newer is required. Detected $versionText."
}

if (-not (Test-Path $VenvPython)) {
    Write-Host "[MCP Firewall] Creating local virtual environment..." -ForegroundColor Cyan
    & $PythonCommand -m venv (Join-Path $ProjectRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
}

$env:PYTHONPATH = Join-Path $ProjectRoot "src"
Write-Host "[MCP Firewall] Validating example policy..." -ForegroundColor Cyan
& $VenvPython -m mcp_firewall --config (Join-Path $ProjectRoot "config\firewall.json") --check-config
if ($LASTEXITCODE -ne 0) { throw "Configuration validation failed." }

Write-Host "[MCP Firewall] Ready. No third-party Python packages are required." -ForegroundColor Green
