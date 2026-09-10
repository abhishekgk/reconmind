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
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

import httpx

from .. import config
from .runners import _env

UA = "ReconMind/0.1 (+https://github.com/; educational recon)"

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


_URL_RE = re.compile(r"https?://[^\s'\"<>)\]]+")


def _extract_urls(lines: list[str]) -> set[str]:
    """Pull http(s) URLs out of arbitrary tool output (gospider/hakrawler prefix
    their lines, e.g. '[href] - https://…'), so one parser fits every crawler."""
    out: set[str] = set()
    for l in lines:
        for m in _URL_RE.findall(l):
            out.add(m.rstrip(".,);"))
    return out


async def _katana(live_urls: list[str], deadline: int, deep: bool) -> set[str]:
    if not config.tool_path("katana") or not live_urls:
        return set()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(live_urls))
        list_file = f.name
    depth = "4" if deep else "3"
    conc = "25" if deep else "15"
    rate = "250" if deep else "150"
    # -jc parses linked JS · -kf all fetches robots.txt/sitemap.xml (harmless GETs).
    # We deliberately do NOT auto-submit forms (-aff) — discovery stays GET-based.
    cmd = ["katana", "-list", list_file, "-jc", "-kf", "all", "-d", depth,
           "-silent", "-c", conc, "-rl", rate, "-timeout", "8",
           "-ef", ",".join(sorted(SKIP_EXT))]
    lines = await _run_lines(cmd, deadline)
    Path(list_file).unlink(missing_ok=True)
    urls = _extract_urls(lines)
    if not urls:
        # Older katana builds reject -kf; retry with the minimal flag set.
        cmd = ["katana", "-list", list_file, "-jc", "-d", depth, "-silent",
               "-c", conc, "-rl", rate, "-timeout", "8"]
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("\n".join(live_urls))
            list_file = f.name
        lines = await _run_lines(cmd, deadline)
        Path(list_file).unlink(missing_ok=True)
        urls = _extract_urls(lines)
    return urls


async def _gospider(live_urls: list[str], deadline: int, deep: bool) -> set[str]:
    if not config.tool_path("gospider") or not live_urls:
        return set()
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(live_urls))
        list_file = f.name
    depth = "4" if deep else "2"
    cmd = ["gospider", "-S", list_file, "-d", depth, "-c", "10", "-t", "20",
           "--js", "--sitemap", "--robots", "-q", "--no-redirect"]
    lines = await _run_lines(cmd, deadline)
    Path(list_file).unlink(missing_ok=True)
    return _extract_urls(lines)


async def _hakrawler(live_urls: list[str], deadline: int, deep: bool) -> set[str]:
    if not config.tool_path("hakrawler") or not live_urls:
        return set()
    depth = "3" if deep else "2"
    # hakrawler reads seed URLs from stdin and prints discovered URLs.
    lines = await _run_lines(["hakrawler", "-d", depth, "-subs", "-u"],
                             deadline, input_text="\n".join(live_urls))
    return _extract_urls(lines)


async def _urlfinder(domain: str, deadline: int) -> set[str]:
    """ProjectDiscovery urlfinder — passive URL discovery for the whole domain."""
    if not config.tool_path("urlfinder"):
        return set()
    lines = await _run_lines(["urlfinder", "-d", domain, "-silent"], deadline)
    return _extract_urls(lines)


async def _historical(domain: str, deadline: int) -> set[str]:
    async def _gau():
        if not config.tool_path("gau"):
            return set()
        lines = await _run_lines(["gau", "--subs", "--threads", "5", domain], deadline)
        return _extract_urls(lines)

    async def _wb():
        if not config.tool_path("waybackurls"):
            return set()
        lines = await _run_lines(["waybackurls", domain], deadline)
        return _extract_urls(lines)

    gau_urls, wb_urls, uf_urls = await asyncio.gather(
        _gau(), _wb(), _urlfinder(domain, deadline))
    return gau_urls | wb_urls | uf_urls


async def _probe_endpoints(rows: list[dict], deep: bool, on_progress=None) -> None:
    """Fetch an HTTP status for each endpoint so the UI can tell live from dead.

    Discovered URLs (especially from archives) are mostly 404/gone. We probe them
    with a HEAD (falling back to GET when HEAD is disallowed), capped and under a
    deadline so it stays fast; anything not probed keeps status=None ("unknown").
    Sets row["status"] in place.
    """
    for r in rows:
        r.setdefault("status", None)
    if not rows:
        return
    cap = 4000 if deep else 1500
    # Probe the most interesting first: URLs with params, then shorter paths.
    ordered = sorted(rows, key=lambda r: (not r["params"], len(r["url"])))
    targets = ordered[:cap]
    if on_progress:
        on_progress(f"probing {len(targets)} endpoints for HTTP status")

    results: dict[str, int | None] = {}
    sem = asyncio.Semaphore(80)

    async with httpx.AsyncClient(follow_redirects=False, verify=False, timeout=6,
                                 headers={"User-Agent": UA}) as client:
        async def probe(url: str) -> None:
            async with sem:
                try:
                    resp = await client.head(url)
                    if resp.status_code in (405, 501):  # HEAD not allowed → GET
                        async with client.stream("GET", url) as g:
                            results[url] = g.status_code
                    else:
                        results[url] = resp.status_code
                except Exception:
                    results[url] = None

        tasks = [asyncio.create_task(probe(r["url"])) for r in targets]
        deadline = 180 if deep else 90
        _, pending = await asyncio.wait(tasks, timeout=deadline)
        for t in pending:
            t.cancel()

    for r in rows:
        if r["url"] in results:
            r["status"] = results[r["url"]]


async def crawl(domain: str, live: list[dict], deep: bool = False,
                on_progress=None) -> list[dict]:
    """Return a de-duplicated, in-scope list of endpoint rows.

    `live` is the scan's live-host records; we crawl their URLs. `deep` widens the
    host cap and time budget.
    """
    host_cap = 200 if deep else 40
    total_cap = 40000 if deep else 8000
    live_urls = [l["url"] for l in live if l.get("url")][:host_cap]

    kt_timeout = 360 if deep else 120
    hist_timeout = 180 if deep else 75

    if on_progress:
        tools_present = [t for t in ("katana", "gospider", "hakrawler", "urlfinder",
                                     "gau", "waybackurls") if config.tool_path(t)]
        on_progress("crawling with " + (", ".join(tools_present) or "no crawlers installed")
                    + " (install katana/gospider/hakrawler for depth)")

    # Active crawlers (katana/gospider/hakrawler) + passive/historical URLs, all
    # concurrent. Each degrades to empty if its tool isn't installed.
    katana_urls, gospider_urls, hakrawler_urls, hist_urls = await asyncio.gather(
        _katana(live_urls, kt_timeout, deep),
        _gospider(live_urls, kt_timeout, deep),
        _hakrawler(live_urls, kt_timeout, deep),
        _historical(domain, hist_timeout),
    )

    # Merge with source attribution; active crawlers take precedence over archives.
    seen: dict[str, dict] = {}
    for urls, src in [(katana_urls, "katana"), (gospider_urls, "gospider"),
                      (hakrawler_urls, "hakrawler")]:
        for row in _rows(urls, domain, src, total_cap):
            seen.setdefault(row["url"], row)
    for row in _rows(hist_urls, domain, "archive", total_cap):
        seen.setdefault(row["url"], row)

    rows = list(seen.values())
    rows.sort(key=lambda r: (r["host"], not r["params"], r["path"]))
    rows = rows[:total_cap]

    # Probe each endpoint so the UI can show status (2xx live vs 404/dead).
    await _probe_endpoints(rows, deep, on_progress=on_progress)
    return rows
