"""Deep enumeration: crawl live sites, parse JavaScript, and collect endpoints.

Once the asset surface (names/IPs) is known, the next step is *content depth*:
what URLs, API paths and parameters those live hosts actually expose. This module:
  - crawls live hosts with `katana` (with -jc it also parses linked JavaScript),
  - pulls historical URLs with `gau`/`waybackurls`,
and normalizes everything into endpoint rows the UI can filter (by host, params,
extension, source). All tools degrade gracefully when not installed.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from .. import config
from .runners import _env

# Static assets we don't care about as "endpoints".
SKIP_EXT = {"png", "jpg", "jpeg", "gif", "svg", "css", "woff", "woff2", "ttf",
            "ico", "mp4", "webp", "map", "avif", "otf", "eot"}


async def _run_lines(cmd: list[str], deadline_s: float,
                     input_text: str | None = None) -> list[str]:
    """Run a tool and collect stdout lines until a deadline, keeping partial output.

    Unlike a plain communicate()+timeout (which discards everything on timeout),
    this streams line-by-line so a long crawl still yields what it found so far.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_env(),
        )
    except (FileNotFoundError, OSError):
        return []
    if input_text is not None and proc.stdin:
        proc.stdin.write(input_text.encode())
        proc.stdin.close()

    loop = asyncio.get_running_loop()
    end = loop.time() + deadline_s
    lines: list[str] = []
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
            lines.append(line.decode(errors="replace").strip())
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
    return lines


def _ext(path: str) -> str:
    last = path.rsplit("/", 1)[-1]
    if "." in last:
        return last.rsplit(".", 1)[-1].lower()[:8]
    return ""


def _in_scope(host: str, domain: str) -> bool:
    return host == domain or host.endswith("." + domain)


def _rows(urls: set[str], domain: str, source: str, cap: int) -> list[dict]:
    rows = []
    for u in urls:
        try:
            p = urlparse(u)
        except ValueError:
            continue
        host = (p.hostname or "").lower()
        if not host or not _in_scope(host, domain):
            continue
        ext = _ext(p.path)
        if ext in SKIP_EXT:
            continue
        rows.append({
            "url": u,
            "host": host,
            "path": p.path or "/",
            "params": bool(p.query),
            "ext": ext,
            "source": source,
        })
        if len(rows) >= cap:
            break
    return rows


async def _katana(live_urls: list[str], deadline: int) -> set[str]:
    if not config.tool_path("katana") or not live_urls:
        return set()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(live_urls))
        list_file = f.name
    cmd = ["katana", "-list", list_file, "-jc", "-d", "2", "-silent",
           "-c", "15", "-rl", "150", "-timeout", "8",
           "-ef", ",".join(sorted(SKIP_EXT))]
    lines = await _run_lines(cmd, deadline)
    Path(list_file).unlink(missing_ok=True)
    return {l for l in lines if l.startswith("http")}


async def _historical(domain: str, deadline: int) -> set[str]:
    async def _gau():
        if not config.tool_path("gau"):
            return set()
        lines = await _run_lines(["gau", "--subs", "--threads", "5", domain], deadline)
        return {l for l in lines if l.startswith("http")}

    async def _wb():
        if not config.tool_path("waybackurls"):
            return set()
        lines = await _run_lines(["waybackurls", domain], deadline)
        return {l for l in lines if l.startswith("http")}

    # Run both archives concurrently so one slow/rate-limited tool can't double the wait.
    gau_urls, wb_urls = await asyncio.gather(_gau(), _wb())
    return gau_urls | wb_urls


async def crawl(domain: str, live: list[dict], deep: bool = False,
                on_progress=None) -> list[dict]:
    """Return a de-duplicated, in-scope list of endpoint rows.

    `live` is the scan's live-host records; we crawl their URLs. `deep` widens the
    host cap and time budget.
    """
    host_cap = 120 if deep else 40
    total_cap = 20000 if deep else 8000
    live_urls = [l["url"] for l in live if l.get("url")][:host_cap]

    kt_timeout = 240 if deep else 100
    hist_timeout = 150 if deep else 75

    if on_progress:
        on_progress("crawling live hosts + historical URLs")

    katana_urls, hist_urls = await asyncio.gather(
        _katana(live_urls, kt_timeout),
        _historical(domain, hist_timeout),
    )

    # Merge with source attribution, katana taking precedence for dupes.
    seen: dict[str, dict] = {}
    for row in _rows(katana_urls, domain, "katana", total_cap):
        seen[row["url"]] = row
    for row in _rows(hist_urls, domain, "archive", total_cap):
        seen.setdefault(row["url"], row)

    rows = list(seen.values())
    rows.sort(key=lambda r: (r["host"], not r["params"], r["path"]))
    return rows[:total_cap]
