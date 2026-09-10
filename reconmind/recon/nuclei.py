"""Nuclei integration — template-based vulnerability scanning, UI-driven.

Powers the **Nuclei** tab. Like the Fuzzer, everything is exposed as options:
  - target: a single URL, a pasted list, or every live host from a loaded scan;
  - what to run: module folders (http/cves, http/exposures, …), tags, severities,
    or a custom -t path — combinable, or leave all blank for a full bulk scan;
  - tuning: rate-limit, concurrency, bulk-size, timeout, retries.

Nuclei's ``-jsonl`` prints one JSON finding per line to stdout AS IT FINDS THEM,
so results stream live into the UI. A missing/old nuclei is reported, not fatal.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from pathlib import Path

from .. import config
from .runners import _env

RESULT_CAP = 5000
SEVERITIES = ["critical", "high", "medium", "low", "info", "unknown"]

# High-signal tags we suggest in the UI (users can type any others too).
SUGGESTED_TAGS = [
    "cve", "rce", "sqli", "xss", "ssrf", "lfi", "redirect", "exposure",
    "misconfig", "takeover", "default-login", "panel", "tech", "oauth",
    "auth-bypass", "disclosure", "config", "backup", "debug", "injection",
]

_META_CACHE: dict | None = None


def templates_dir() -> Path | None:
    """Resolve the nuclei-templates directory from nuclei's own config, with the
    conventional ~/nuclei-templates fallback."""
    cfg = Path.home() / ".config" / "nuclei" / ".templates-config.json"
    try:
        d = json.loads(cfg.read_text()).get("nuclei-templates-directory")
        if d and Path(d).is_dir():
            return Path(d)
    except (OSError, json.JSONDecodeError):
        pass
    for c in (Path.home() / "nuclei-templates",
              Path.home() / ".config" / "nuclei" / "nuclei-templates"):
        if c.is_dir():
            return c
    return None


def _version() -> str:
    import subprocess
    try:
        out = subprocess.run(["nuclei", "-version"], capture_output=True,
                             text=True, env=_env(), timeout=10)
        m = re.search(r"v[\d.]+", (out.stderr or "") + (out.stdout or ""))
        return m.group(0) if m else ""
    except Exception:
        return ""


def _discover_modules(td: Path) -> list[dict]:
    """Offer top-level template folders plus the http/* sub-modules (cves,
    exposures, …) — the granularity a hunter actually picks."""
    mods: list[dict] = []

    def add(rel: str):
        p = td / rel
        if not p.is_dir():
            return
        try:
            count = sum(1 for _ in p.rglob("*.yaml"))
        except OSError:
            count = 0
        if count:
            mods.append({"path": rel, "label": rel, "count": count})

    skip = {"helpers", "profiles", "global-matchers"}
    for d in sorted(td.iterdir(), key=lambda p: p.name):
        if d.is_dir() and d.name not in skip:
            add(d.name)
    http = td / "http"
    if http.is_dir():
        for d in sorted(http.iterdir(), key=lambda p: p.name):
            if d.is_dir():
                add(f"http/{d.name}")
    return mods


def nuclei_meta(refresh: bool = False) -> dict:
    global _META_CACHE
    if _META_CACHE is not None and not refresh:
        return _META_CACHE
    path = config.tool_path("nuclei")
    td = templates_dir()
    meta = {
        "installed": path is not None,
        "path": path,
        "version": _version() if path else "",
        "templates_dir": str(td) if td else "",
        "modules": _discover_modules(td) if td else [],
        "severities": SEVERITIES,
        "suggested_tags": SUGGESTED_TAGS,
        "install": "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    }
    _META_CACHE = meta
    return meta


def _allowed_module(rel: str, td: Path) -> bool:
    """Only allow module paths inside the templates dir (defence in depth)."""
    try:
        p = (td / rel).resolve()
        return p.is_dir() and str(p).startswith(str(td.resolve()))
    except OSError:
        return False


def _norm_targets(raw) -> list[str]:
    """Accept a string (possibly multi-line) or a list; return clean target URLs."""
    items: list[str] = []
    if isinstance(raw, str):
        items = re.split(r"[\s,]+", raw.strip())
    elif isinstance(raw, list):
        for x in raw:
            items += re.split(r"[\s,]+", str(x).strip())
    out, seen = [], set()
    for t in items:
        t = t.strip()
        if not t or t in seen:
            continue
        seen.add(t)
        out.append(t)
    return out


async def run_nuclei(opts: dict, on_result=None, on_progress=None) -> dict:
    """Run one nuclei scan. ``opts`` keys: targets (str|list), templates (list of
    module rel-paths), template_path (custom -t), tags (str), severity (list),
    rate_limit, concurrency, bulk_size, timeout, retries, deadline.

    ``on_result(finding)`` fires per finding (live); ``on_progress(msg)`` for phases.
    Returns {ok, count, findings, error}.
    """
    on_result = on_result or (lambda r: None)
    on_progress = on_progress or (lambda m: None)

    if not config.tool_path("nuclei"):
        return {"ok": False, "error": "nuclei is not installed — "
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"}

    targets = _norm_targets(opts.get("targets"))
    if not targets:
        return {"ok": False, "error": "no targets — enter a URL, paste a list, or "
                "load live hosts from a scan"}

    td = templates_dir()
    # -jsonl streams findings; -nc no color; -duc skips the update check so the
    # scan starts immediately and doesn't try to mutate templates mid-run.
    cmd = ["nuclei", "-jsonl", "-nc", "-duc"]

    # Targets: -u for a single one, a temp -l file for many.
    list_file = None
    if len(targets) == 1:
        cmd += ["-u", targets[0]]
    else:
        tf = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
        tf.write("\n".join(targets))
        tf.close()
        list_file = tf.name
        cmd += ["-l", list_file]

    # Template selection (all combinable).
    if td:
        for rel in opts.get("templates") or []:
            if _allowed_module(rel, td):
                cmd += ["-t", str(td / rel)]
    custom = (opts.get("template_path") or "").strip()
    if custom and Path(custom).exists():
        cmd += ["-t", custom]
    tags = (opts.get("tags") or "").strip()
    if tags:
        cmd += ["-tags", ",".join(re.split(r"[\s,]+", tags))]
    sev = [s for s in (opts.get("severity") or []) if s in SEVERITIES]
    if sev:
        cmd += ["-s", ",".join(sev)]

    # Tuning.
    cmd += ["-rl", str(int(opts.get("rate_limit") or 150))]
    cmd += ["-c", str(int(opts.get("concurrency") or 25))]
    cmd += ["-bs", str(int(opts.get("bulk_size") or 25))]
    cmd += ["-timeout", str(int(opts.get("timeout") or 10))]
    cmd += ["-retries", str(int(opts.get("retries") or 1))]

    deadline = float(opts.get("deadline") or 900)
    on_progress(f"nuclei → {len(targets)} target(s)"
                + (f", {len(opts.get('templates') or [])} module(s)" if opts.get("templates") else "")
                + (f", tags={tags}" if tags else "")
                + (f", severity={','.join(sev)}" if sev else ""))

    findings: list[dict] = []

    def on_line(line: str):
        line = line.strip()
        if not line or not line.startswith("{") or len(findings) >= RESULT_CAP:
            return
        try:
            o = json.loads(line)
        except json.JSONDecodeError:
            return
        # Skip the -stats-json progress objects (they have no template-id).
        tid = o.get("template-id") or o.get("templateID")
        if not tid:
            return
        info = o.get("info", {}) or {}
        row = {
            "template": tid,
            "name": info.get("name", ""),
            "severity": (info.get("severity") or "unknown").lower(),
            "tags": info.get("tags", []) or [],
            "type": o.get("type", ""),
            "url": o.get("matched-at") or o.get("matched") or o.get("host") or "",
            "matcher": o.get("matcher-name", "") or "",
            "extracted": o.get("extracted-results", []) or [],
        }
        findings.append(row)
        on_result(row)

    try:
        await _stream(cmd, deadline, on_line)
    except Exception as e:
        return {"ok": False, "error": str(e), "findings": findings,
                "count": len(findings)}
    finally:
        if list_file:
            Path(list_file).unlink(missing_ok=True)

    sev_rank = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda r: (sev_rank.get(r["severity"], 9), r["template"]))
    return {"ok": True, "count": len(findings), "findings": findings,
            "truncated": len(findings) >= RESULT_CAP}


async def _stream(cmd: list[str], deadline_s: float, on_line):
    """Run nuclei and hand each stdout line to on_line until a deadline; kill on
    timeout so a long scan can't hang the server."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL, env=_env())
    except (FileNotFoundError, OSError):
        return
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline_s
    try:
        while True:
            remaining = end - loop.time()
            if remaining <= 0:
                break
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            on_line(line.decode(errors="replace"))
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
