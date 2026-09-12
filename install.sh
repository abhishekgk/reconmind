#!/usr/bin/env bash
# ReconMind installer — macOS & Linux.
# Sets up a Python virtualenv, installs dependencies, and offers to install the
# optional external recon tools (Go binaries) and the Ollama local LLM.
# Safe to re-run. No API keys are touched — you add those later in the web UI.
set -euo pipefail

BOLD=$(tput bold 2>/dev/null || true); DIM=$(tput dim 2>/dev/null || true)
GREEN=$(tput setaf 2 2>/dev/null || true); YELLOW=$(tput setaf 3 2>/dev/null || true)
RED=$(tput setaf 1 2>/dev/null || true); RESET=$(tput sgr0 2>/dev/null || true)
info()  { echo "${GREEN}==>${RESET} $*"; }
warn()  { echo "${YELLOW}!! ${RESET} $*"; }
err()   { echo "${RED}xx ${RESET} $*" >&2; }
ask()   { local p="$1"; local a; read -r -p "$p [y/N] " a; [[ "$a" =~ ^[Yy]$ ]]; }

cd "$(dirname "$0")"
ROOT="$(pwd)"

echo "${BOLD}ReconMind installer${RESET} — $(uname -s)"
echo

# --- 1. Python -----------------------------------------------------------------
PY=""
for c in python3.12 python3.11 python3.10 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
if [ -z "$PY" ]; then
  err "Python 3.10+ not found. Install it first:"
  echo "   macOS:  brew install python"
  echo "   Debian/Ubuntu:  sudo apt install -y python3 python3-venv python3-pip"
  echo "   Fedora:  sudo dnf install -y python3 python3-pip"
  echo "   Arch:  sudo pacman -S python"
  exit 1
fi
PYVER="$($PY -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
info "Using Python $PYVER ($PY)"
if ! $PY -c 'import sys; raise SystemExit(0 if sys.version_info >= (3,10) else 1)'; then
  err "Python 3.10+ required (found $PYVER)."; exit 1
fi

# --- 2. Virtualenv + deps ------------------------------------------------------
if [ ! -d .venv ]; then
  info "Creating virtualenv (.venv)"
  $PY -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
info "Installing Python dependencies"
python -m pip install --upgrade pip >/dev/null
python -m pip install -r requirements.txt
info "Core install complete — ReconMind will already run with keyless sources."

# --- 3. Optional Go recon tools ------------------------------------------------
echo
if command -v go >/dev/null 2>&1; then
  if ask "Install/upgrade the optional Go tools (subfinder, httpx, katana, naabu, + the ffuf & gobuster fuzzers ...)?"; then
    GOTOOLS=(
      "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
      "github.com/tomnomnom/assetfinder@latest"
      "github.com/projectdiscovery/httpx/cmd/httpx@latest"
      "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
      "github.com/d3mondev/puredns/v2@latest"
      "github.com/lc/gau/v2/cmd/gau@latest"
      "github.com/tomnomnom/waybackurls@latest"
      "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
      "github.com/projectdiscovery/katana/cmd/katana@latest"
      "github.com/projectdiscovery/tlsx/cmd/tlsx@latest"
      "github.com/sensepost/gowitness@latest"
      # --- Fuzzer tab (content discovery) ---
      "github.com/ffuf/ffuf/v2@latest"
      "github.com/OJ/gobuster/v3@latest"
      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    )
    for t in "${GOTOOLS[@]}"; do
      info "go install $t"
      go install "$t" || warn "failed: $t (skipping)"
    done
    GOBIN="$(go env GOPATH)/bin"
    echo "${DIM}Tools installed to $GOBIN — ReconMind finds this automatically.${RESET}"
    case ":$PATH:" in *":$GOBIN:"*) :;; *) warn "Add $GOBIN to your PATH to run them from the shell too.";; esac
  fi
else
  warn "Go not found — skipping optional recon tools."
  echo "   Install Go from https://go.dev/dl/ then re-run this script to add them."
  echo "   (ReconMind still works without them via its built-in keyless sources.)"
fi

# --- 3b. Optional non-Go fuzzers (feroxbuster / dirb / wfuzz) ------------------
echo
if ask "Install extra fuzzers (feroxbuster, dirb, wfuzz)? (optional — ffuf + gobuster already cover most needs)"; then
  OS="$(uname -s)"
  if [ "$OS" = "Darwin" ]; then
    if command -v brew >/dev/null 2>&1; then
      brew install feroxbuster dirb || warn "brew install of feroxbuster/dirb had issues"
    else warn "Homebrew not found — install feroxbuster/dirb manually."; fi
  elif command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -qq && sudo apt-get install -y feroxbuster dirb || warn "apt install had issues (feroxbuster may need a newer distro)"
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y dirb || warn "dnf install had issues"
  elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -S --noconfirm feroxbuster dirb || warn "pacman install had issues"
  else
    warn "No known package manager — install feroxbuster/dirb from their project pages."
  fi
  # wfuzz is a Python tool — install it into the venv we just made.
  python -m pip install wfuzz >/dev/null 2>&1 && info "wfuzz installed (in .venv)" || warn "wfuzz install skipped"
  echo "${DIM}ReconMind's Fuzzer dropdown enables each tool automatically once it's on PATH.${RESET}"
fi

# --- 4. Wordlists for the Fuzzer -----------------------------------------------
echo
WLDIR="$HOME/.reconmind/wordlists"
if ask "Download content-discovery wordlists for the Fuzzer (into ~/.reconmind/wordlists)?"; then
  mkdir -p "$WLDIR"
  BASE="https://raw.githubusercontent.com/danielmiessler/SecLists/master"
  WLFILES=(
    "Discovery/Web-Content/common.txt"
    "Discovery/Web-Content/big.txt"
    "Discovery/Web-Content/raft-medium-directories.txt"
    "Discovery/Web-Content/raft-medium-files.txt"
    "Discovery/Web-Content/raft-large-directories.txt"
    "Discovery/Web-Content/api/api-endpoints.txt"
    "Discovery/DNS/subdomains-top1million-5000.txt"
    "Discovery/DNS/subdomains-top1million-20000.txt"
  )
  for f in "${WLFILES[@]}"; do
    out="$WLDIR/$(basename "$f")"
    info "fetch $(basename "$f")"
    curl -fsSL "$BASE/$f" -o "$out" || warn "failed: $f"
  done
  if ask "Also clone the FULL SecLists (~1GB, needs git) for every wordlist?"; then
    if command -v git >/dev/null 2>&1; then
      info "cloning SecLists (shallow) into $WLDIR/SecLists"
      git clone --depth 1 https://github.com/danielmiessler/SecLists.git "$WLDIR/SecLists" || warn "clone failed"
    else warn "git not found — skipping full SecLists (the curated set above still works)."; fi
  fi
  echo "${DIM}Wordlists in $WLDIR — they appear in the Fuzzer dropdown automatically.${RESET}"
fi

# --- 5. Optional Ollama (local LLM) --------------------------------------------
echo
if command -v ollama >/dev/null 2>&1; then
  info "Ollama already installed."
else
  if ask "Install Ollama for the local-LLM mentor (optional; you can also just use an Anthropic key)?"; then
    if [ "$(uname -s)" = "Darwin" ]; then
      if command -v brew >/dev/null 2>&1; then brew install ollama; else
        warn "Homebrew not found — download Ollama from https://ollama.com/download"; fi
    else
      curl -fsSL https://ollama.com/install.sh | sh || warn "Ollama install failed — see https://ollama.com/download"
    fi
    command -v ollama >/dev/null 2>&1 && echo "${DIM}Next: 'ollama serve &' then 'ollama pull llama3.1'${RESET}"
  fi
fi

# --- Done ----------------------------------------------------------------------
echo
info "${BOLD}Done.${RESET} Start ReconMind with:"
echo
echo "    source .venv/bin/activate"
echo "    python run.py"
echo
echo "Then open ${BOLD}http://127.0.0.1:8710${RESET} and click ${BOLD}⚙ API keys${RESET} to add your own keys."
