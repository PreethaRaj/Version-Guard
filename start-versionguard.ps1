$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

Write-Host "Starting VersionGuard..." -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker is not installed or not in PATH."
}

Write-Host "Starting Docker services..." -ForegroundColor Yellow
docker compose -f docker-compose.dev.yml up -d

Write-Host "Waiting for OpenSearch..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

Write-Host "Starting backend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", @"
Set-Location '$PSScriptRoot\api'
& '.\.venv\Scripts\Activate.ps1'
`$env:OPEN_SEARCH_URL='http://localhost:9200'
`$env:OPEN_SEARCH_INDEX='versionguard-cves'
`$env:OLLAMA_BASE_URL='http://localhost:11434'
`$env:API_KEY='changeme'
`$env:UI_ORIGIN='http://localhost:5173'
`$env:ENABLE_NVD_LIVE_FALLBACK='true'
uvicorn main:app --reload
"@

Write-Host "Starting frontend..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", @"
Set-Location '$PSScriptRoot\ui'
npm run dev
"@

Start-Sleep -Seconds 5
Start-Process "http://localhost:5173"

Write-Host "VersionGuard started." -ForegroundColor Green
Write-Host "UI: http://localhost:5173" -ForegroundColor Green
Write-Host "API docs: http://127.0.0.1:8000/docs" -ForegroundColor Green

Start-Sleep -Seconds 5
Write-Host "Next run : powershell -ExecutionPolicy Bypass -File .\ingest-versionguard.ps1" -ForegroundColor Green
Write-Host "This is a ONE-TIME CVE data ingestion from https://nvd.nist.gov/ to OpenSearch via NVD API. This will take around 20-30mts." -ForegroundColor Green