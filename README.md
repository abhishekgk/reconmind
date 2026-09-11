# ReconMind

**An open-source, local-LLM recon orchestrator that helps you _learn_ security research.**

ReconMind is built for hunters who can't afford paid courses or cloud AI. It runs
entirely on your laptop: it drives the best free recon tools, aggregates
subdomains from a dozen public sources, and uses a **local** language model (via
[Ollama](https://ollama.com)) as a patient mentor that explains what the results
mean and what to study next. No API keys, no subscriptions, no data leaving your
machine.

> ⚖️ **Only scan assets you own or are explicitly authorized to test** — for
> example, the in-scope targets of a bug-bounty program. ReconMind queries public
> OSINT sources and performs DNS lookups; use it responsibly and follow each
> program's rules and responsible-disclosure policy.

---

## What it does

Give it a domain (e.g. `example.com`) and ReconMind discovers assets across
**every dimension**, not just subdomain names:

1. **Names** — subdomains from many sources at once:
   - Keyless HTTP OSINT: crt.sh, certspotter, hackertarget, rapiddns, urlscan,
     Wayback Machine, subdomain.center (AlienVault OTX and anubis are queried too
     but those providers now often gate anonymous access, so they may return
     nothing — no key, no problem, the others cover it).
   - Tools you already have: `subfinder`, `assetfinder`, `findomain` (fast);
     `amass`, `gau`, `github-subdomains` (deep mode).
   - **Keyed sources** you enable in the UI: Shodan, VirusTotal, SecurityTrails,
     Chaos, Censys, Netlas, LeakIX, FullHunt, BinaryEdge, BeVigil.
2. **Guessed** (active mode) — DNS bruteforce + permutation guessing (`api` →
   `api-dev`, `api-staging`, …), resolved with `puredns`/`dnsx` or pure Python.
3. **Resolve** every name to IPs.
4. **Live probe** — which hosts serve HTTP/HTTPS (status, title, server).
5. **Content mining** — pulls more names out of what live hosts serve: CSP
   headers, `robots.txt`, `sitemap.xml`, `security.txt`, linked JavaScript, and
   **TLS certificate SANs**.
6. **Network** — maps every IP to its **ASN, BGP netblock and owning org**
   (keyless, via Team Cymru), grabs PTR records, and — with a Shodan key — the
   **open ports and services** per IP. Deep mode adds a bounded reverse-DNS sweep
   of discovered netblocks to find sibling hosts.
7. **Related domains** — reverse-WHOIS (Whoxy key) and content links surface other
   root domains belonging to the target, ready to scan next.
8. **Deep enumeration** (crawl mode) — crawls every live host with several
   crawlers in parallel — `katana` (parses linked JS, follows robots/sitemap),
   `gospider` and `hakrawler` — plus passive URLs from `urlfinder`, `gau` and
   `waybackurls`, and lists the discovered **URLs/endpoints** with host,
   parameters, extension and source, filterable in its own tab. With **deep** on,
   the crawl goes deeper (higher depth, more hosts, longer budget). Discovery
   stays GET-based — forms are never auto-submitted.

Then the local LLM **explains** the whole surface — names, hosting, exposed
services — flags what to study first and why, and suggests safe next steps. It's a
teacher, not an autopilot.

The web UI shows it all in five filterable tabs: **Subdomains · IPs & Services ·
ASNs / Netblocks · Endpoints · Related domains**, with a live progress stream.
You can also **⬆ Import** an exported scan JSON to view/analyze it, and browse
every past scan under **🕘 History** (each loads back into the dashboard).

Everything degrades gracefully: missing tools are skipped, keyless sources always
run, a bad/expired key never sinks a scan, and the LLM panel shows setup help
instead of crashing if Ollama isn't running.

## API keys — bring your own

**This repository ships with zero API keys.** ReconMind never hardcodes secrets:
every key you use is *yours*, entered by you, and stored only on your own machine
in `~/.reconmind/keys.json` (`chmod 600`). Nothing is committed to git — the
`.gitignore` blocks `keys.json` and all scan data as a second line of defence.
It works out of the box with no keys at all (keyless sources); keys just unlock
more sources.

Click **⚙ API keys** in the UI. Add a key for any supported service, click **Save
& apply**, and ReconMind immediately:

- stores it locally (`~/.reconmind/keys.json`, `chmod 600` — nothing leaves your
  machine except the tool's own API calls),
- regenerates `subfinder`'s `provider-config.yaml` so subfinder starts using it,
- exports the right env vars (`SHODAN_API_KEY`, `GITHUB_TOKEN`, `PDCP_API_KEY`, …)
  for the CLI tools, and
- enables direct API calls for Shodan (ports/services), VirusTotal, SecurityTrails,
  Chaos, GitHub code search and Whoxy reverse-WHOIS.

Every service is optional. More keys → more sources → more assets. The panel shows
a "get a key" link and a configured/not-set badge for each.

## Choosing your model

The header has a **model dropdown**. Pick **Automatic** (Claude if you've added an
Anthropic key, otherwise your best local model), a specific **Claude** model
(Opus / Sonnet / Haiku — only shown once a key is set), or any **Ollama** model
installed on your machine. Your choice is saved to `~/.reconmind/settings.json` and
persists across restarts. No key and no Ollama? Recon still runs fully — only the
"Explain / Ask" mentor needs a model.

## Reports & diffing

- **Export → 📄 Markdown / 🌐 HTML report** turns the current scan into a clean,
  shareable attack-surface report (also `reconmind <target> --report md|html` on the
  CLI). Plus JSON, CSV, live-URL and nuclei-target exports.
- **🔀 Diff** compares the loaded scan against any earlier scan of the same target
  and shows what's **new** or **gone** — subdomains, live hosts, IPs, open ports,
  endpoints, related domains — and exports the delta as Markdown. New assets are
  where fresh bugs live.

## Screenshot of the flow

```
target: example.com   [ ] deep (amass)   [ ] active bruteforce   [Start recon]

 22 subdomains   2 resolved   2 live   38s
 ▸ Probing live hosts
 subfinder 20   rapiddns 2   certspotter 2   hackertarget 2   urlscan 2 …

 ★ = commonly interesting to study first
 Host                     Live  Status  Title            Server      Sources
 example.com              ●     200     Example Domain   cloudflare  crt.sh, subfinder…
 www.example.com          ●     200     Example Domain   cloudflare  rapiddns, subfinder…
```

## Install

ReconMind runs on **macOS, Linux and Windows**. Python 3.10+ is the only hard
requirement; every external tool is optional.

### Quick install (recommended)

The installer sets up a virtualenv, installs the Python deps, and *offers* to add
the optional Go recon tools and Ollama. It never touches API keys.

**macOS / Linux**
```bash
git clone https://github.com/<your-username>/reconmind.git && cd reconmind
./install.sh
```

**Windows (PowerShell)**
```powershell
git clone https://github.com/<your-username>/reconmind.git; cd reconmind
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### Manual install (any OS)

```bash
python3 -m venv .venv
# macOS/Linux:   source .venv/bin/activate
# Windows (PS):  .\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

That's the minimum — ReconMind already runs on its keyless sources.

### Optional external tools (all free)

The UI's **Toolbox** panel shows what's installed and the exact, OS-specific
install command for anything missing. The Go tools install identically everywhere
(Go must be present — [go.dev/dl](https://go.dev/dl/)):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest
# Deep crawl (the more of these you have, the deeper the Endpoints tab goes)
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/sensepost/gowitness@latest        # screenshots (needs Chrome)
# Fuzzer tab (content discovery) — pick your engine in the tool dropdown
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
```

Extra fuzzers (optional; ffuf + gobuster already cover most needs): `feroxbuster`
(`brew install feroxbuster` / `cargo install feroxbuster` / `scoop install feroxbuster`),
`dirb` (`brew install dirb` / `apt install dirb`), `wfuzz` (`pip install wfuzz`).

### Wordlists for the Fuzzer

The Fuzzer's **wordlist dropdown** auto-discovers `*.txt` lists from `~/.reconmind/wordlists`,
`/opt`, `/opt/SecLists/...`, `/usr/share/wordlists`, `~/wordlists`, and any dirs in
`RECONMIND_WORDLIST_DIRS`. The installer offers to download a curated set (raft, common,
big, api, subdomains) into `~/.reconmind/wordlists` — and optionally the full
[SecLists](https://github.com/danielmiessler/SecLists). Drop your own `.txt` lists in any
of those folders and they appear in the dropdown immediately (no restart).

| Tool | macOS | Linux | Windows |
|------|-------|-------|---------|
| **amass** | `brew install amass` | `go install github.com/owasp-amass/amass/v4/...@master` | `go install github.com/owasp-amass/amass/v4/...@master` |
| **puredns** | `go install github.com/d3mondev/puredns/v2@latest` (+ `brew install massdns`) | same (+ build [massdns](https://github.com/blechschmidt/massdns)) | use WSL2 |
| **Ollama** | `brew install ollama` | `curl -fsSL https://ollama.com/install.sh \| sh` | `winget install Ollama.Ollama` |

> Go binaries land in `~/go/bin` (`%USERPROFILE%\go\bin` on Windows). ReconMind
> looks there automatically — you don't have to touch your PATH. On Windows, a
> few native-heavy tools (`puredns`, `massdns`, `amass` active mode) are smoothest
> under **WSL2**; everything else, including all passive sources, runs natively.

## Run

```bash
# macOS/Linux:   source .venv/bin/activate
# Windows (PS):  .\.venv\Scripts\Activate.ps1
python run.py
# then open http://127.0.0.1:8710
```

## Configuration (all optional, via environment variables)

| Variable               | Purpose                                          | Default            |
|------------------------|--------------------------------------------------|--------------------|
| `RECONMIND_HOST`       | Bind address                                     | `127.0.0.1`        |
| `RECONMIND_PORT`       | Port                                             | `8710`             |
| `RECONMIND_MODEL`      | Preferred Ollama model                           | first installed    |
| `RECONMIND_WORDLIST`   | DNS bruteforce wordlist (for `active` mode)      | small built-in     |
| `RECONMIND_RESOLVERS`  | Resolvers file for mass DNS                      | public fallback    |
| `RECONMIND_DATA`       | Where scans are saved (JSON, one file per scan)  | `~/.reconmind/data`|
| `OLLAMA_HOST`          | Ollama API URL                                   | `http://127.0.0.1:11434` |
| `RECONMIND_WORDLIST_DIRS` | Extra dirs to scan for Fuzzer wordlists (`:`-separated) | built-in set |
| `RECONMIND_AUTH`       | Require login on every API route (for hosting)   | off (local, open)  |
| `RECONMIND_ALLOW_REGISTER` | Allow account registration                   | first account only |
| `RECONMIND_HTTPS`      | Mark the session cookie `Secure` (set behind TLS)| off                |

## Hosting it behind a login

ReconMind is a **localhost tool by default** — no auth, zero friction. If you want to host it
so only authorized users can run it, set `RECONMIND_AUTH=1`. Then:

- Every `/api/*` route requires a logged-in session; the UI shows a login/register overlay.
- The **first** account can be registered from the UI (bootstrap); after that, registration is
  closed unless you set `RECONMIND_ALLOW_REGISTER=1`. Accounts share one workspace (scans, keys,
  findings) — auth is a gate, not multi-tenancy.
- Passwords are hashed with `scrypt`; sessions are HTTP-only cookies. Put it behind HTTPS (a
  reverse proxy) and set `RECONMIND_HTTPS=1` so the cookie is marked `Secure`.

> ⚠️ **It's an active scanner.** Anyone who can log in can launch ffuf/nuclei from your server at
> any target. Always set a **Scope allow-list** (🎯 Scope in the header) so out-of-scope targets
> are refused, keep the box on a private network, and only expose it to people you trust.

## How it's organized

```
reconmind/
  config.py            # settings, tool-path discovery
  tools.py             # detect installed CLI tools + install hints
  keys.py              # API-key store + auto-wiring into tool configs
  llm.py               # Ollama client + the "mentor" prompts
  store.py             # save/load scans as JSON
  recon/
    sources.py         # keyless passive OSINT sources
    keyed_sources.py   # Shodan/VT/SecurityTrails/Chaos/GitHub/Whoxy (need keys)
    runners.py         # wrappers around subfinder/assetfinder/amass/gau/github-subdomains
    resolve.py         # DNS resolution + live HTTP probing
    bruteforce.py      # active DNS bruteforce
    permute.py         # permutation guessing + resolve
    content.py         # mine CSP/robots/sitemap/JS + TLS cert SANs
    network.py         # IP -> ASN/CIDR/org, Shodan ports, reverse-DNS sweep
    crawl.py           # deep crawl (katana/gospider/hakrawler/urlfinder/gau) -> endpoints
    orchestrator.py    # the scan engine that ties it together + streams progress
  server/
    app.py             # FastAPI backend + SSE progress stream
    static/            # single-page web UI (no build step)
```

Contributions welcome — every module is small and readable on purpose, so a
newcomer can add a new source or tool in a few lines. Good first issues: add a new
passive source to `recon/sources.py`, or a new tool wrapper to `recon/runners.py`.

## Roadmap

Already shipped: ✅ port scanning (`naabu`), ✅ endpoint discovery (`katana`/`gau`),
✅ subdomain-takeover detection, ✅ screenshots (`gowitness`), ✅ Anthropic Claude
as an optional mentor backend, ✅ **model picker** (choose any local Ollama model or
a Claude model from the header dropdown), ✅ **scan diff** (🔀 Diff — compare against
any earlier scan of the target: new/removed subdomains, live hosts, IPs, ports,
endpoints), ✅ **Markdown & HTML report export** (Export menu, or `--report md|html`).

Next up (contributions very welcome):

- **Continuous monitoring** — schedule a target and get notified on new assets.
- **Nuclei integration** — opt-in, template-scoped passive checks on live hosts.
- **Dockerfile** for zero-setup runs, and a `--quiet --json` CI mode.
- **More passive sources** — the easiest first PR (`recon/sources.py`).

See [`docs/ENHANCEMENTS.md`](docs/ENHANCEMENTS.md) for the full, prioritised idea list.

## License

MIT — free to use, learn from, and build on.
