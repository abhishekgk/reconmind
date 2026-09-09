# ReconMind — Setup, Running & Migration Guide

Everything you need to run ReconMind yourself, install it fresh, or move it to
another machine. No prior context required.

---

## 0. What this is

ReconMind is a local, open-source recon orchestrator with a web UI. It discovers a
domain's assets (subdomains, IPs, ASNs/netblocks, ports/services, related domains)
and a local LLM explains the results. Everything runs on your machine.

Two locations matter — remember these:

| What | Where | Notes |
|------|-------|-------|
| **The code** | `reconmind/` project folder | Portable; move/copy freely |
| **Your keys + scan output** | `~/.reconmind/` (i.e. `$HOME/.reconmind`) | Created automatically on first run |

---

## 1. Requirements

- **Python 3.10 or newer** (`python3 --version`)
- **pip** (`pip3 --version`)
- Optional but recommended:
  - **Go** — to install the external recon tools (subfinder, httpx, etc.)
  - **Ollama** — for the LLM "Explain / Ask" features (recon works without it)

---

## 2. First-time install (fresh machine)

```bash
# 1. Go to the project folder
cd /path/to/reconmind          # wherever you cloned it

# 2. Install the Python dependencies
pip3 install -r requirements.txt
```

That's the minimum. The tool will already run using its keyless sources.

### 2a. (Recommended) Install the external recon tools

These make scans far more thorough. All free. The UI's **Toolbox** panel shows
which are installed and the exact command for any that are missing.

```bash
# Go-based tools (need Go installed)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/d3mondev/puredns/v2@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/alterx/cmd/alterx@latest
go install github.com/gwen001/github-subdomains@latest

# amass (deep mode)
brew install amass       # macOS. Linux/Windows: go install github.com/owasp-amass/amass/v4/...@master
```

> Go installs land in `~/go/bin`. ReconMind automatically looks there, so you do
> not need to add it to your PATH.

### 2b. (Optional) Install Ollama for the LLM mentor

```bash
brew install ollama          # macOS. Linux: curl -fsSL https://ollama.com/install.sh | sh  ·  Windows: winget install Ollama.Ollama
ollama serve &               # start the daemon (leave running)
ollama pull llama3.1         # or qwen2.5 / mistral — any chat model
```

---

## 3. Running it

```bash
cd /path/to/reconmind
python3 run.py
```

Then open **http://127.0.0.1:8710** in a browser.

- Stop the server with **Ctrl + C** in the terminal.
- For LLM features, make sure `ollama serve` is running in another terminal.

### Command-line alternative (no browser)

```bash
python3 -m reconmind.cli example.com            # fast scan
python3 -m reconmind.cli example.com --deep      # + amass/gau/github/reverse-DNS
python3 -m reconmind.cli example.com --active    # + bruteforce/permutations
python3 -m reconmind.cli example.com --explain   # + local LLM explanation
```

---

## 4. API keys

Click **⚙ API keys** (top-right of the UI). Add any keys you have, click
**Save & apply**. Each key is:

- stored in `~/.reconmind/keys.json` (permissions `600` — only you can read it),
- wired into subfinder's `~/.reconmind/subfinder-provider-config.yaml`,
- and exported as the right env var for CLI tools.

Notes:
- Keys **persist** — you enter each one once. A **✓ saved** badge confirms it.
- Saved keys show as blank in the fields (your secret is never sent back to the
  browser). Blank = "keep existing"; saving new keys never wipes old ones.
- Use the red **remove** link to delete a key.
- **GitHub:** use a **classic** token with **no scopes** and a short expiry —
  that's all the public code search needs, and it's the safest option.

---

## 5. Where your output is stored

```
~/.reconmind/
├── keys.json                        # your API keys (chmod 600)
├── subfinder-provider-config.yaml   # auto-generated — don't edit by hand
└── data/
    └── <domain>_<YYYYMMDD-HHMMSS>.json   # one file per scan, saved automatically
```

- Every scan is auto-saved to `~/.reconmind/data/` as timestamped JSON containing
  all subdomains, IPs, ASNs, ports and related domains.
- You can also download any scan from the UI with **Export JSON**.
- Deleting the project folder does **not** delete your keys/scans (they're in
  `~/.reconmind/`). To wipe everything, remove both locations.

---

## 6. Migrating to another machine

1. **Copy the code:** move the whole `reconmind/` project folder to the new
   machine (USB, git, scp — anything).
2. **Copy your keys + scans (optional):** copy `~/.reconmind/` from the old
   machine to `~/.reconmind/` on the new one to bring your saved API keys and past
   scan results along. Skip this if you want a clean start (you'll just re-enter
   keys in the UI).
3. **Install dependencies on the new machine:** follow **Section 2** (Python deps;
   optionally the Go tools and Ollama).
4. **Run:** `python3 run.py` — done.

> The subfinder config is regenerated from `keys.json` whenever you save keys, so
> if you copied `keys.json` but not the `.yaml`, just open ⚙ API keys and click
> **Save & apply** once to rebuild it.

---

## 7. Troubleshooting

| Symptom | Fix |
|---------|-----|
| `ModuleNotFoundError` on start | Re-run `pip3 install -r requirements.txt` |
| Port 8710 already in use | `RECONMIND_PORT=8720 python3 run.py` |
| UI button/layout looks stale after an update | Hard-refresh: **Cmd + Shift + R** (macOS) / **Ctrl + Shift + R** (Linux/Windows) |
| "LLM: offline" in UI | Start Ollama: `ollama serve`, then `ollama pull llama3.1` |
| A tool shows "missing" in Toolbox | Run the `go install` / `brew install` line it shows |
| Scans find few results | Add API keys (Section 4) and/or install more tools (2a) |

---

## 8. Environment variables (all optional)

Set these before `python3 run.py` to override defaults:

| Variable | Purpose | Default |
|----------|---------|---------|
| `RECONMIND_HOST` | Bind address | `127.0.0.1` |
| `RECONMIND_PORT` | Port | `8710` |
| `RECONMIND_MODEL` | Preferred Ollama model | first installed |
| `RECONMIND_WORDLIST` | DNS bruteforce wordlist (active mode) | small built-in |
| `RECONMIND_RESOLVERS` | Resolvers file for mass DNS | public fallback |
| `RECONMIND_DATA` | Where scans are saved | `~/.reconmind/data` |
| `OLLAMA_HOST` | Ollama API URL | `http://127.0.0.1:11434` |

---

## 9. Reminder on responsible use

Only scan assets you own or are explicitly authorized to test (e.g. a bug-bounty
program's in-scope targets). ReconMind spans DNS, IPs, ASNs and services — keep
everything in scope and follow each program's disclosure rules.
