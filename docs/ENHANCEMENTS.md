# ReconMind — Enhancement Ideas

A prioritised backlog of things that would make ReconMind a stronger, more useful
tool, grouped by value-vs-effort. Everything here keeps the project's spirit: a
**learning-focused, local-first recon orchestrator** — it discovers and *explains*
attack surface; it never auto-exploits.

## Tier 1 — high value, contained (do these first)

1. **✅ DONE — Scan diff / change tracking.** The 🔀 Diff button compares the loaded
   scan against any earlier scan of the target → new/removed subdomains, live hosts,
   IPs, open ports, endpoints and related domains, exportable as Markdown.
2. **✅ DONE — Markdown / HTML report export.** `report.py` renders both; wired into
   the Export menu and the CLI (`--report md|html`).
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
14. **Model routing for the mentor.** ✅ *Partly done* — a header dropdown now lets
    users pick any local Ollama model or a Claude model (Opus/Sonnet/Haiku), saved to
    `~/.reconmind/settings.json`. Still open: show a token/cost estimate per model.
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
