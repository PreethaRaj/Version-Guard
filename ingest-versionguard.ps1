$ErrorActionPreference = "Stop"
Set-Location "$PSScriptRoot\api"

if (-not (Test-Path ".venv\Scripts\Activate.ps1")) {
    throw "Backend virtual environment not found. Run setup-versionguard.ps1 first."
}

& ".\.venv\Scripts\Activate.ps1"

$env:OPEN_SEARCH_URL='http://localhost:9200'
$env:OPEN_SEARCH_INDEX='versionguard-cves'
$env:NVD_API_KEY=$env:NVD_API_KEY

Write-Host "Starting NVD ingestion..." -ForegroundColor Yellow
python -u -m versionguard_nvd.cli_ingest
Write-Host "NVD ingestion completed." -ForegroundColor Green