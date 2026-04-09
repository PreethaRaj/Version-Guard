$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Setting up VersionGuard..." -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    throw "Python is not installed or not in PATH."
}

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "Node.js/npm is not installed or not in PATH."
}

Write-Host "Setting up backend virtual environment..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\api"

if (-not (Test-Path ".venv")) {
    python -m venv .venv
}

& ".\.venv\Scripts\Activate.ps1"
python -m pip install --upgrade pip
pip install -r requirements.txt

Write-Host "Setting up frontend dependencies..." -ForegroundColor Yellow
Set-Location "$PSScriptRoot\ui"
npm install

Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Next run: powershell -ExecutionPolicy Bypass -File .\start-versionguard.ps1" -ForegroundColor Green