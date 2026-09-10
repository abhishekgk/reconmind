#Requires -Version 5.1
<#
.SYNOPSIS
  ReconMind installer for Windows (PowerShell).
.DESCRIPTION
  Creates a Python virtualenv, installs dependencies, and optionally installs the
  Go recon tools and Ollama. No API keys are touched — add those in the web UI.
  Run from an ordinary PowerShell prompt:
      powershell -ExecutionPolicy Bypass -File .\install.ps1
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

function Info($m) { Write-Host "==> $m" -ForegroundColor Green }
function Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "xx  $m" -ForegroundColor Red; exit 1 }
function Ask($m)  { $a = Read-Host "$m [y/N]"; return ($a -match '^[Yy]$') }

Write-Host "ReconMind installer - Windows" -ForegroundColor Cyan
Write-Host ""

# --- 1. Python -----------------------------------------------------------------
$py = $null
foreach ($cand in @('python','python3','py')) {
  $cmd = Get-Command $cand -ErrorAction SilentlyContinue
  if ($cmd) {
    try {
      $v = & $cand -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>$null
      if ($LASTEXITCODE -eq 0 -and $v) { $py = $cand; break }
    } catch { }
  }
}
if (-not $py) {
  Fail "Python 3.10+ not found. Install it from https://www.python.org/downloads/ (check 'Add python.exe to PATH'), or run: winget install Python.Python.3.12"
}
$ver = & $py -c 'import sys;print("%d.%d"%sys.version_info[:2])'
Info "Using Python $ver ($py)"
& $py -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)'
if ($LASTEXITCODE -ne 0) { Fail "Python 3.10+ required (found $ver)." }

# --- 2. Virtualenv + deps ------------------------------------------------------
if (-not (Test-Path ".venv")) {
  Info "Creating virtualenv (.venv)"
  & $py -m venv .venv
}
$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPy)) { Fail "virtualenv creation failed (missing $venvPy)" }
Info "Installing Python dependencies"
& $venvPy -m pip install --upgrade pip | Out-Null
& $venvPy -m pip install -r requirements.txt
Info "Core install complete - ReconMind will already run with keyless sources."

# --- 3. Optional Go recon tools ------------------------------------------------
Write-Host ""
if (Get-Command go -ErrorAction SilentlyContinue) {
  if (Ask "Install/upgrade the optional Go tools (subfinder, httpx, naabu, katana, + the ffuf & gobuster fuzzers ...)?") {
    $tools = @(
      "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
      "github.com/tomnomnom/assetfinder@latest",
      "github.com/projectdiscovery/httpx/cmd/httpx@latest",
      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
      "github.com/lc/gau/v2/cmd/gau@latest",
      "github.com/tomnomnom/waybackurls@latest",
      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
      "github.com/projectdiscovery/katana/cmd/katana@latest",
      "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
      "github.com/sensepost/gowitness@latest",
      # --- Fuzzer tab (content discovery) ---
      "github.com/ffuf/ffuf/v2@latest",
      "github.com/OJ/gobuster/v3@latest"
    )
    foreach ($t in $tools) { Info "go install $t"; try { go install $t } catch { Warn "failed: $t (skipping)" } }
    $gobin = Join-Path $env:USERPROFILE "go\bin"
    Write-Host "Tools installed to $gobin - ReconMind finds this automatically." -ForegroundColor DarkGray
    Warn "puredns/amass need extra native deps on Windows; WSL2 is recommended for full parity."
  }
} else {
  Warn "Go not found - skipping optional recon tools."
  Write-Host "   Install Go from https://go.dev/dl/ (or: winget install GoLang.Go) then re-run this script."
  Write-Host "   ReconMind still works without them via its built-in keyless sources."
}

# --- 3b. Optional extra fuzzer (feroxbuster) -----------------------------------
Write-Host ""
if (Ask "Install the feroxbuster fuzzer? (optional - ffuf + gobuster already cover most needs)") {
  if (Get-Command scoop -ErrorAction SilentlyContinue) {
    try { scoop install feroxbuster } catch { Warn "scoop install feroxbuster failed" }
  } elseif (Get-Command cargo -ErrorAction SilentlyContinue) {
    try { cargo install feroxbuster } catch { Warn "cargo install feroxbuster failed" }
  } else {
    Warn "Install feroxbuster via scoop (scoop install feroxbuster) or from its GitHub releases."
  }
  # wfuzz is a Python tool - install it into the venv we just made.
  try { & $venvPy -m pip install wfuzz | Out-Null; Info "wfuzz installed (in .venv)" } catch { Warn "wfuzz install skipped" }
  Write-Host "ReconMind's Fuzzer dropdown enables each tool automatically once it's on PATH." -ForegroundColor DarkGray
}

# --- 4. Wordlists for the Fuzzer -----------------------------------------------
Write-Host ""
$wldir = Join-Path $env:USERPROFILE ".reconmind\wordlists"
if (Ask "Download content-discovery wordlists for the Fuzzer (into ~/.reconmind/wordlists)?") {
  New-Item -ItemType Directory -Force -Path $wldir | Out-Null
  $base = "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
  $wlfiles = @(
    "Discovery/Web-Content/common.txt",
    "Discovery/Web-Content/big.txt",
    "Discovery/Web-Content/raft-medium-directories.txt",
    "Discovery/Web-Content/raft-medium-files.txt",
    "Discovery/Web-Content/raft-large-directories.txt",
    "Discovery/Web-Content/api/api-endpoints.txt",
    "Discovery/DNS/subdomains-top1million-5000.txt",
    "Discovery/DNS/subdomains-top1million-20000.txt"
  )
  foreach ($f in $wlfiles) {
    $out = Join-Path $wldir (Split-Path $f -Leaf)
    Info "fetch $(Split-Path $f -Leaf)"
    try { Invoke-WebRequest -Uri "$base/$f" -OutFile $out -UseBasicParsing } catch { Warn "failed: $f" }
  }
  if (Ask "Also clone the FULL SecLists (~1GB, needs git) for every wordlist?") {
    if (Get-Command git -ErrorAction SilentlyContinue) {
      Info "cloning SecLists (shallow)"
      try { git clone --depth 1 https://github.com/danielmiessler/SecLists.git (Join-Path $wldir "SecLists") } catch { Warn "clone failed" }
    } else { Warn "git not found - skipping full SecLists (the curated set above still works)." }
  }
  Write-Host "Wordlists in $wldir - they appear in the Fuzzer dropdown automatically." -ForegroundColor DarkGray
}

# --- 5. Optional Ollama --------------------------------------------------------
Write-Host ""
if (Get-Command ollama -ErrorAction SilentlyContinue) {
  Info "Ollama already installed."
} elseif (Ask "Install Ollama for the local-LLM mentor (optional; an Anthropic key also works)?") {
  if (Get-Command winget -ErrorAction SilentlyContinue) {
    winget install Ollama.Ollama
    Write-Host "Next: run 'ollama serve' then 'ollama pull llama3.1'" -ForegroundColor DarkGray
  } else {
    Warn "winget not available - download Ollama from https://ollama.com/download"
  }
}

# --- Done ----------------------------------------------------------------------
Write-Host ""
Info "Done. Start ReconMind with:"
Write-Host ""
Write-Host "    .\.venv\Scripts\Activate.ps1"
Write-Host "    python run.py"
Write-Host ""
Write-Host "Then open http://127.0.0.1:8710 and click the API keys panel to add your own keys."
