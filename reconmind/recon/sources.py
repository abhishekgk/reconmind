"""Passive subdomain sources reachable over plain HTTP (no API key required).

These are free, public OSINT endpoints that bug-bounty hunters use every day:
certificate transparency logs, passive DNS aggregators, and URL archives. They
return subdomains that were observed *publicly* — this is reconnaissance of
information that is already exposed on the internet, not intrusion.

Each source is a small async function returning a set of hostnames. Failures are
swallowed on purpose: one dead source should never sink a whole scan.
"""
from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable

import httpx

# Matches a hostname label chain. We validate against the target domain later.
_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-_.]{0,253}[A-Za-z0-9])?")

UA = "ReconMind/0.1 (+https://github.com/; educational recon)"


def _clean(hosts: set[str], domain: str) -> set[str]:
    """Keep only valid subdomains of `domain`, lowercased and wildcard-stripped."""
    out: set[str] = set()
    dom = domain.lower().lstrip(".")
    for h in hosts:
        if not h:
            continue
        h = h.strip().lower().rstrip(".")
        h = h.lstrip("*.")  # crt.sh returns *.example.com wildcards
        if h == dom or h.endswith("." + dom):
            if _HOST_RE.fullmatch(h):
                out.add(h)
    return out


async def _get(client: httpx.AsyncClient, url: str, timeout: float = 30,
               retries: int = 0, **kw) -> httpx.Response | None:
    for attempt in range(retries + 1):
        try:
            r = await client.get(url, timeout=timeout, headers={"User-Agent": UA}, **kw)
            if r.status_code == 200:
                return r
            # 429/502/503 from rate-limited sources (crt.sh especially) — back off.
        except Exception:
            pass
        if attempt < retries:
            await asyncio.sleep(3 * (attempt + 1))  # progressive: 3s, 6s, 9s…
    return None


async def crtsh(client, domain):
    # crt.sh is the richest source but aggressively rate-limits under concurrent
    # load (returns 502/503) — give it several progressive-backoff retries so a
    # full scan doesn't drop it to zero. Long timeout too (multi-MB JSON).
    r = await _get(client, f"https://crt.sh/?q=%25.{domain}&output=json",
                   timeout=90, retries=4)
    if not r:
        return set()
    hosts: set[str] = set()
    try:
        for row in r.json():
            for field in ("name_value", "common_name"):
                val = row.get(field, "")
                for line in str(val).splitlines():
                    hosts.add(line)
    except (json.JSONDecodeError, ValueError):
        pass
    return _clean(hosts, domain)


async def hackertarget(client, domain):
    r = await _get(client, f"https://api.hackertarget.com/hostsearch/?q={domain}")
    if not r or "error" in r.text.lower() or "api count" in r.text.lower():
        return set()
    hosts = {line.split(",")[0] for line in r.text.splitlines() if line}
    return _clean(hosts, domain)


async def rapiddns(client, domain):
    r = await _get(client, f"https://rapiddns.io/subdomain/{domain}?full=1")
    if not r:
        return set()
    hosts = set(re.findall(rf"[\w.\-]+\.{re.escape(domain)}", r.text))
    return _clean(hosts, domain)


async def alienvault(client, domain):
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    r = await _get(client, url, timeout=75)  # passive_dns can be huge/slow
    if not r:
        return set()
    hosts: set[str] = set()
    try:
        for row in r.json().get("passive_dns", []):
            hosts.add(row.get("hostname", ""))
    except (json.JSONDecodeError, ValueError):
        pass
    return _clean(hosts, domain)


async def anubis(client, domain):
    r = await _get(client, f"https://jldc.me/anubis/subdomains/{domain}")
    if not r:
        return set()
    try:
        return _clean(set(r.json()), domain)
    except (json.JSONDecodeError, ValueError):
        return set()


async def certspotter(client, domain):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    r = await _get(client, url)
    if not r:
        return set()
    hosts: set[str] = set()
    try:
        for row in r.json():
            hosts.update(row.get("dns_names", []))
    except (json.JSONDecodeError, ValueError):
        pass
    return _clean(hosts, domain)


async def urlscan(client, domain):
    r = await _get(client, f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000")
    if not r:
        return set()
    hosts: set[str] = set()
    try:
        for row in r.json().get("results", []):
            page = row.get("page", {})
            hosts.add(page.get("domain", ""))
            for link in row.get("task", {}).get("domain", "").splitlines():
                hosts.add(link)
    except (json.JSONDecodeError, ValueError):
        pass
    return _clean(hosts, domain)


async def wayback(client, domain):
    url = (f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           "&output=text&fl=original&collapse=urlkey&limit=50000")
    r = await _get(client, url, timeout=75)  # wayback CDX can return multi-MB
    if not r:
        return set()
    hosts = set(re.findall(rf"[\w.\-]+\.{re.escape(domain)}", r.text))
    return _clean(hosts, domain)


async def subdomain_center(client, domain):
    """api.subdomain.center — a keyless aggregator (crt.sh + passive DNS)."""
    r = await _get(client, f"https://api.subdomain.center/?domain={domain}", timeout=60)
    if not r:
        return set()
    try:
        return _clean(set(r.json()), domain)
    except (json.JSONDecodeError, ValueError):
        return set()


# name -> coroutine factory. Only keyless HTTP sources that are actually reachable
# and free live here. (Dropped: columbus [DNS gone], threatminer [origin 522],
# digitorus [Cloudflare-blocked] — all were dead keyless. AlienVault/anubis are
# kept but now often gate anonymous access, so they may return nothing.)
SOURCES: dict[str, Callable[[httpx.AsyncClient, str], Awaitable[set[str]]]] = {
    "crt.sh": crtsh,
    "hackertarget": hackertarget,
    "rapiddns": rapiddns,
    "alienvault-otx": alienvault,
    "anubis": anubis,
    "certspotter": certspotter,
    "urlscan": urlscan,
    "wayback": wayback,
    "subdomain.center": subdomain_center,
}


async def gather_passive(domain: str, on_source=None) -> dict[str, set[str]]:
    """Query every HTTP source concurrently. Returns {source_name: {hosts}}.

    `on_source(name, hosts)` is called as each source finishes, for live UI updates.
    """
    results: dict[str, set[str]] = {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        async def run(name, fn):
            hosts = await fn(client, domain)
            results[name] = hosts
            if on_source:
                on_source(name, hosts)

        await asyncio.gather(*(run(n, f) for n, f in SOURCES.items()))
    return results
