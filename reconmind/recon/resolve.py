"""Resolve subdomains to IPs, filter DNS wildcards, and probe live HTTP services.

Prefers ProjectDiscovery's dnsx/httpx when installed (fast, rich); falls back to
pure-Python resolution/probing on a bare machine.

Wildcard handling matters: many targets resolve *.domain.com to a fixed IP set,
so guessed names (bruteforce/permutation) "resolve" as false positives. We detect
the wildcard IP set from random labels and drop names that only point there.
"""
from __future__ import annotations

import asyncio
import json
import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

import httpx

from .. import config

_RESOLVE_POOL = ThreadPoolExecutor(max_workers=256, thread_name_prefix="resolve")


def _getaddrinfo(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return sorted({info[4][0] for info in infos})
    except (socket.gaierror, OSError):
        return []


async def _resolve_one(host, sem, loop) -> tuple[str, list[str]]:
    async with sem:
        return host, await loop.run_in_executor(_RESOLVE_POOL, _getaddrinfo, host)


async def resolve_python(hosts: list[str], concurrency: int = 256) -> dict[str, list[str]]:
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(*(_resolve_one(h, sem, loop) for h in hosts))
    return {h: ips for h, ips in results if ips}


async def resolve_dnsx(hosts: list[str]) -> dict[str, list[str]]:
    cmd = ["dnsx", "-silent", "-a", "-resp", "-json"]
    if config.RESOLVERS_FILE:
        cmd += ["-r", config.RESOLVERS_FILE]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await proc.communicate("\n".join(hosts).encode())
    resolved: dict[str, list[str]] = {}
    for line in out.decode(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host, ips = row.get("host"), row.get("a") or []
        if host and ips:
            resolved[host] = ips
    return resolved


async def resolve(hosts: list[str]) -> dict[str, list[str]]:
    if not hosts:
        return {}
    if config.tool_path("dnsx"):
        try:
            return await resolve_dnsx(hosts)
        except Exception:
            pass
    return await resolve_python(hosts)


# --- Wildcard detection -------------------------------------------------------

async def detect_wildcard(domain: str, probes: int = 4) -> set[str]:
    """Return the set of IPs that random non-existent names resolve to (empty = none)."""
    randoms = [f"{secrets.token_hex(6)}-wildtest.{domain}" for _ in range(probes)]
    resolved = await resolve_python(randoms, concurrency=probes)
    ips: set[str] = set()
    for got in resolved.values():
        ips.update(got)
    return ips


async def resolve_filtered(candidates: list[str], domain: str) -> dict[str, list[str]]:
    """Resolve guessed names and drop wildcard false positives.

    A name is dropped when every IP it resolves to is part of the wildcard set
    (i.e. it points only at the catch-all, not a real distinct host).
    """
    if not candidates:
        return {}
    wildcard = await detect_wildcard(domain)
    resolved = await resolve(candidates)
    if not wildcard:
        return resolved
    return {h: ips for h, ips in resolved.items() if set(ips) - wildcard}


# --- Live HTTP probing --------------------------------------------------------

def _norm_row(host: str, url: str, status, title, server, clen, tech, cdn) -> dict:
    return {
        "host": host, "url": url, "status": status, "title": (title or "")[:200],
        "server": server or "", "content_length": clen or 0,
        "tech": tech or [], "cdn": cdn or "",
    }


async def probe_httpx(hosts: list[str]) -> list[dict]:
    """Probe with ProjectDiscovery httpx for status/title/tech/server/cdn."""
    cmd = ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect",
           "-web-server", "-content-length", "-cdn", "-follow-redirects",
           "-timeout", "8", "-retries", "0", "-no-color", "-threads", "60"]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await proc.communicate("\n".join(hosts).encode())
    seen: dict[str, dict] = {}
    for line in out.decode(errors="replace").splitlines():
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (r.get("input") or r.get("host") or "").split("://")[-1].split(":")[0]
        if not host:
            continue
        tech = r.get("tech") or r.get("technologies") or []
        row = _norm_row(host, r.get("url", ""), r.get("status_code"),
                        r.get("title", ""), r.get("webserver", ""),
                        r.get("content_length"), tech, r.get("cdn_name", ""))
        # Keep the https result if a host answers on both schemes.
        if host not in seen or row["url"].startswith("https"):
            seen[host] = row
    return list(seen.values())


async def _probe_one_py(host, client, sem) -> dict | None:
    async with sem:
        for scheme in ("https", "http"):
            try:
                r = await client.get(f"{scheme}://{host}", timeout=10)
            except Exception:
                continue
            title = ""
            if "text/html" in r.headers.get("content-type", ""):
                body, lo = r.text[:20000], r.text[:20000].lower()
                if "<title" in lo:
                    s = body.find(">", lo.find("<title")) + 1
                    e = lo.find("</title>", s)
                    if e != -1:
                        title = body[s:e].strip()[:200]
            return _norm_row(host, str(r.url), r.status_code, title,
                             r.headers.get("server", ""), len(r.content), [], "")
        return None


async def probe_python(hosts: list[str], concurrency: int = 60) -> list[dict]:
    sem = asyncio.Semaphore(concurrency)
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
        results = await asyncio.gather(*(_probe_one_py(h, client, sem) for h in hosts))
    return [r for r in results if r]


async def probe_live(hosts: list[str]) -> list[dict]:
    """Return metadata for hosts that answer over HTTP(S). Uses httpx if present."""
    if not hosts:
        return []
    if config.tool_path("httpx"):
        try:
            rows = await probe_httpx(hosts)
            if rows:
                return rows
        except Exception:
            pass
    return await probe_python(hosts)
