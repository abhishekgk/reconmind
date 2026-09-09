"""Command-line interface for ReconMind — for folks who prefer the terminal.

Usage:
  python -m reconmind.cli example.com            # fast passive scan
  python -m reconmind.cli example.com --deep      # + amass/gau
  python -m reconmind.cli example.com --active     # + DNS bruteforce
  python -m reconmind.cli example.com --explain    # ask the local LLM to explain
  python -m reconmind.cli --serve                  # launch the web UI instead
"""
from __future__ import annotations

import argparse
import asyncio
import json

from . import llm, store
from .recon.orchestrator import Scan, run_scan


def _print_progress(scan: Scan) -> None:
    async def pump():
        while True:
            ev = await scan.events.get()
            if ev["kind"] == "phase":
                print(f"  ▸ {ev['phase']}")
            elif ev["kind"] == "source_done":
                print(f"    {ev['source']:16} +{ev['new']:>4} (total {ev['total']})")
            elif ev["kind"] in ("done", "error"):
                break
    asyncio.create_task(pump())


async def _run(args) -> None:
    scan = Scan(domain=args.domain, active=args.active, deep=args.deep)
    print(f"\n  ReconMind scanning {scan.domain}\n")
    _print_progress(scan)
    await run_scan(scan)
    result = scan.to_dict()

    live = [h for h in result["hosts"] if h["live"]]
    print(f"\n  {result['counts']['total']} subdomains · "
          f"{result['counts']['resolved']} resolved · {len(live)} live\n")
    for h in sorted(live, key=lambda x: x["host"]):
        print(f"  {h['status']}  {h['host']:40} {h['title'][:40]}")

    path = store.save(result)
    print(f"\n  saved → {path}")

    if args.json:
        print(json.dumps(result, indent=2))

    if args.explain:
        print("\n  --- local LLM mentor ---\n")
        print(await llm.explain_scan(result))


def main() -> None:
    p = argparse.ArgumentParser(prog="reconmind", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    p.add_argument("--deep", action="store_true", help="add amass + gau (slower)")
    p.add_argument("--active", action="store_true", help="DNS bruteforce guessed names")
    p.add_argument("--explain", action="store_true", help="LLM explanation of results")
    p.add_argument("--json", action="store_true", help="print full JSON result")
    p.add_argument("--serve", action="store_true", help="launch the web UI instead")
    args = p.parse_args()

    if args.serve:
        from .server.app import main as serve
        serve()
        return
    if not args.domain:
        p.error("provide a domain, or use --serve for the web UI")
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
