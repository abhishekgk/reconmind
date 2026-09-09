# ReconMind — Enhancement Ideas

A prioritised backlog of things that would make ReconMind a stronger, more useful
tool, grouped by value-vs-effort. Everything here keeps the project's spirit: a
**learning-focused, local-first recon orchestrator** — it discovers and *explains*
attack surface; it never auto-exploits.

## Tier 1 — high value, contained (do these first)

1. **Scan diff / change tracking.** `reconmind diff <target>` (and a UI toggle)
   comparing the two most recent scans of a domain → new/removed subdomains, IPs,
   open ports, endpoints. New assets are where bugs live; this is the single most
   requested recon feature. Data is already timestamped JSON in `~/.reconmind/data`.
2. **Markdown / HTML report export.** One click → a clean attack-surface report
   (counts, live hosts table, notable ports/endpoints, LLM summary). `store.py`
   already holds everything; add `report.py` + a CLI `--report md` flag + UI button.
3. **Dockerfile + `docker run` path.** Ships subfinder/httpx/etc. preinstalled so a
   newcomer gets the full toolkit with zero Go/Homebrew setup. Huge for adoption.
4. **CI-friendly stdout mode.** `reconmind <target> --quiet --json` emitting only
   final JSON, so people can pipe ReconMind into their own pipelines.
5. **`pipx`/`pip install reconmind` packaging.** `pyproject.toml` already defines the
   `reconmind` entry point — publish to PyPI so install is one line.

## Tier 2 — high value, more work

6. **Continuous monitoring.** Schedule a target (cron/systemd/Task Scheduler helper)
   and diff each run, with a desktop/webhook notification on new assets. Natural
   pairing with #1.
7. **Opt-in nuclei pass.** Run `nuclei` (passive/`-severity info,low` templates) on
   live hosts and surface *informational* findings for the LLM to explain — framed
   as "here's what to study", not a vuln scanner. Keep it explicitly opt-in.
8. **Wordlist & resolver management in the UI.** Download/refresh a good resolvers
   list and a subdomain wordlist from the settings panel (today it's a manual drop
   into `~/.reconmind`). Lowers the barrier to a real active scan.
9. **Favicon-hash / technology fingerprinting** (wappalyzer-style or `httpx -favicon`)
   → cluster hosts by stack, which the LLM can reason about ("all these run the same
   old Jenkins").
10. **Cloud-asset discovery.** Detect S3/GCS/Azure buckets and cloud ranges from
    resolved IPs/CNAMEs and flag them for the user to review.

## Tier 3 — polish & robustness

11. **Tests + CI.** A small `pytest` suite over the pure-Python parsers
    (`_clean`, content mining, ASN parsing) + a GitHub Actions workflow. Makes
    outside contributions safe to merge — important for a public repo.
12. **Rate-limit / politeness controls.** Global concurrency + per-source rate knob
    in config, surfaced in the UI, so users stay within program rules.
13. **Structured audit log.** Append every outbound query (source, target, time) to
    `~/.reconmind/audit.jsonl` — useful evidence that scanning stayed in-scope.
14. **Better model routing for the mentor.** Let users pick the Claude model in the
    UI and show token/cost estimate; default the public build to a cheaper model
    (e.g. a Sonnet-class model) since new users may not have Opus access.
15. **Result search / global filter** across all tabs, and CSV export per tab.

## Tier 4 — bigger bets

16. **Plugin system for sources/tools.** A drop-in `~/.reconmind/plugins/*.py`
    interface so people add sources without forking. The codebase is already modular
    enough that this is mostly formalising the existing pattern.
17. **Multi-target / scope-file mode.** Feed a file of roots (a program's full scope),
    scan all, and dedupe/relate across them.
18. **Passive-vs-active safety gate.** A visible "this action sends traffic to the
    target" confirmation before bruteforce/port-scan/crawl phases, for beginners.

## Guardrails to keep as it grows

- Stay **local-first**: no telemetry, no phoning home, secrets only in `~/.reconmind`.
- Every external tool stays **optional** — keyless Python sources must always work.
- Keep it a **teacher, not an autopilot** — new features explain surface, they don't
  weaponise it.
- Keep modules **small and readable** so a newcomer can add a source in a few lines.
