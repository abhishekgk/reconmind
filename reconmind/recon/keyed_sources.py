"""Passive sources that require an API key the user supplied in the UI.

subfinder already queries many of these when given a provider-config, but calling
them directly too adds redundancy (works even if subfinder's config fails) and
lets us pull data subfinder doesn't return — e.g. Shodan's IP/port/service data
and Whoxy's reverse-WHOIS related domains.

Each function is skipped automatically when its key is absent, so nothing here is
required. Failures are swallowed: a dead/expired key never sinks a scan.
"""
from __future__ import annotations

import asyncio
import json

import httpx

from .. import keys
from .sources import UA, _clean, _get


async def shodan_dns(client, domain, key) -> set[str]:
    r = await _get(client, f"https://api.shodan.io/dns/domain/{domain}?key={key}")
    if not r:
        return set()
    try:
        data = r.json()
        subs = {f"{s}.{domain}" if s not in ("", "@") else domain
                for s in data.get("subdomains", [])}
        return _clean(subs, domain)
    except (json.JSONDecodeError, ValueError):
        return set()


async def virustotal(client, domain, key) -> set[str]:
    # VT v3 caps the subdomains relationship at limit=40 (limit=1000 -> HTTP 400).
    # Paginate via links.next; break on any non-200 (e.g. free-tier 429).
    hosts: set[str] = set()
    headers = {"x-apikey": key, "User-Agent": UA}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    for _ in range(25):  # up to ~1000 subdomains
        try:
            r = await client.get(url, headers=headers, timeout=30)
            if r.status_code == 429:
                # Free tier is 4 req/min and subfinder is also spending the quota.
                # Back off once, then give up paginating if still limited.
                await asyncio.sleep(16)
                r = await client.get(url, headers=headers, timeout=30)
            if r.status_code != 200:
                break
            data = r.json()
        except Exception:
            break
        for item in data.get("data", []):
            hosts.add(item.get("id", ""))
        url = data.get("links", {}).get("next")
        if not url:
            break
    return _clean(hosts, domain)


async def securitytrails(client, domain, key) -> set[str]:
    url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
    try:
        r = await client.get(url, headers={"APIKEY": key, "User-Agent": UA},
                             params={"children_only": "false"}, timeout=30)
        if r.status_code != 200:
            return set()
        subs = {f"{s}.{domain}" for s in r.json().get("subdomains", [])}
    except Exception:
        return set()
    return _clean(subs, domain)


async def chaos(client, domain, key) -> set[str]:
    url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
    try:
        r = await client.get(url, headers={"Authorization": key, "User-Agent": UA},
                             timeout=30)
        if r.status_code != 200:
            return set()
        subs = {f"{s}.{domain}" if s else domain
                for s in r.json().get("subdomains", [])}
    except Exception:
        return set()
    return _clean(subs, domain)


async def github_api(client, domain, token) -> set[str]:
    """Search GitHub code for the domain, extracting subdomains from code snippets.

    The text-match media type is required — without it the API returns only file
    metadata (names/paths), not the matched code, so no subdomains can be found.
    """
    import re
    hosts: set[str] = set()
    headers = {"Authorization": f"token {token}",
               "Accept": "application/vnd.github.v3.text-match+json",
               "User-Agent": UA}
    pat = re.compile(rf"[\w.\-]+\.{re.escape(domain)}")
    try:
        for page in range(1, 6):  # up to 5 pages, be gentle with rate limits
            r = await client.get("https://api.github.com/search/code",
                                 headers=headers,
                                 params={"q": domain, "per_page": 50, "page": page},
                                 timeout=30)
            if r.status_code != 200:
                break
            items = r.json().get("items", [])
            for it in items:
                # text_matches carries the actual code fragments that matched.
                for m in it.get("text_matches", []):
                    hosts.update(pat.findall(m.get("fragment", "")))
            if len(items) < 50:
                break
            await asyncio.sleep(3)  # respect GitHub secondary rate limits
    except Exception:
        pass
    return _clean(hosts, domain)


async def whoxy_related(client, domain, key) -> set[str]:
    """Reverse WHOIS: other root domains registered by the same org/registrant."""
    related: set[str] = set()
    try:
        r = await client.get("https://api.whoxy.com/",
                             params={"key": key, "reverse": "whois", "domain": domain},
                             timeout=30)
        if r.status_code != 200:
            return set()
        data = r.json()
        for row in data.get("search_result", []):
            d = row.get("domain_name", "").strip().lower()
            if d and "." in d and d != domain:
                related.add(d)
    except Exception:
        return set()
    return related


# service_id -> (fn, field, kind)  where kind is "subdomains" or "related"
KEYED = {
    "shodan": (shodan_dns, "key", "subdomains"),
    "virustotal": (virustotal, "key", "subdomains"),
    "securitytrails": (securitytrails, "key", "subdomains"),
    "chaos": (chaos, "key", "subdomains"),
    "github": (github_api, "token", "subdomains"),
    "whoxy": (whoxy_related, "key", "related"),
}


async def gather_keyed(domain: str, on_source=None) -> dict:
    """Run every keyed source the user has configured.

    Returns {"subdomains": {source: {hosts}}, "related": {domains}}.
    """
    subs_by_source: dict[str, set[str]] = {}
    related: set[str] = set()

    async with httpx.AsyncClient(follow_redirects=True) as client:
        async def run(sid, fn, field, kind):
            key = keys.get_field(sid, field)
            if not key:
                return
            result = await fn(client, domain, key)
            if kind == "related":
                related.update(result)
                if on_source:
                    on_source(f"{sid} (related)", set())
            else:
                subs_by_source[sid] = result
                if on_source:
                    on_source(sid, result)

        await asyncio.gather(*(run(sid, *spec) for sid, spec in KEYED.items()))

    return {"subdomains": subs_by_source, "related": related}
