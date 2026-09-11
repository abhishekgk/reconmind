#Requires -Version 5.1
<#
.SYNOPSIS
  One-command update for ReconMind on Windows — pull latest code + refresh deps.
  Run:  powershell -ExecutionPolicy Bypass -File .\update.ps1
  Your ~/.reconmind data (scans, keys, findings) is untouched.
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

if (-not (Test-Path ".git")) {
  Write-Host "This copy isn't a git clone, so there's nothing to pull." -ForegroundColor Yellow
  Write-Host "Grab updates with:  git clone https://github.com/abhishekgk/reconmind"
  Write-Host "(or re-download the latest ZIP from the GitHub page)."
  exit 1
}

Write-Host "==> Pulling latest..." -ForegroundColor Green
git pull --ff-only

$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPy) {
  Write-Host "==> Refreshing Python deps..." -ForegroundColor Green
  & $venvPy -m pip install -q --upgrade -r requirements.txt
}

Write-Host "==> Done. Restart ReconMind:  python run.py"
