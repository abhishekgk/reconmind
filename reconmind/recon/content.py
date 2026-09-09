"""Content-derived discovery: mine hostnames from what live hosts actually serve.

Live sites leak their own infrastructure. This phase reads, per live host:
  - the Content-Security-Policy header (often lists many sibling domains),
  - robots.txt, sitemap.xml, /.well-known/security.txt,
  - linked JavaScript files (APIs and subdomains are hardcoded constantly),
and pulls the TLS certificate's Subject Alternative Names.

In-scope hostnames become new subdomains to resolve; out-of-scope ones are
collected as related-domain candidates. All keyless.
"""
from __future__ import annotations

import asyncio
import re
import ssl

import httpx

from .sources import UA, _clean

_HOST_ANY = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
_JS_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)


def _split(hosts: set[str], domain: str) -> tuple[set[str], set[str]]:
    """Partition hostnames into (in-scope subdomains, out-of-scope related)."""
    in_scope = _clean(hosts, domain)
    related: set[str] = set()
    dom = domain.lower()
    for h in hosts:
        h = h.strip().lower().rstrip(".")
        if h and h != dom and not h.endswith("." + dom):
            labels = h.split(".")
            if len(labels) >= 2:
                related.add(".".join(labels[-2:]))  # rough registrable root
    return in_scope, related


async def _mine_host(client, host, domain):
    hosts: set[str] = set()
    base = f"https://{host}"
    # Homepage + CSP header + linked JS.
    try:
        r = await client.get(base, timeout=12)
        hosts.update(_HOST_ANY.findall(r.headers.get("content-security-policy", "")))
        body = r.text[:200000]
        hosts.update(_HOST_ANY.findall(body))
        js_urls = _JS_SRC.findall(body)[:6]
        for ju in js_urls:
            if ju.startswith("//"):
                ju = "https:" + ju
            elif ju.startswith("/"):
                ju = base + ju
            elif not ju.startswith("http"):
                continue
            try:
                jr = await client.get(ju, timeout=10)
                hosts.update(_HOST_ANY.findall(jr.text[:300000]))
            except httpx.HTTPError:
                pass
    except httpx.HTTPError:
        pass

    # robots.txt, sitemap.xml, security.txt.
    for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
        try:
            r = await client.get(base + path, timeout=8)
            if r.status_code == 200:
                hosts.update(_HOST_ANY.findall(r.text[:200000]))
        except httpx.HTTPError:
            pass
    return hosts


async def mine_live(live_hosts: list[str], domain: str,
                    concurrency: int = 20) -> tuple[set[str], set[str]]:
    """Return (new in-scope subdomains, related-domain candidates)."""
    if not live_hosts:
        return set(), set()
    sem = asyncio.Semaphore(concurrency)
    all_hosts: set[str] = set()

    async with httpx.AsyncClient(follow_redirects=True, verify=False,
                                 headers={"User-Agent": UA}) as client:
        async def one(h):
            async with sem:
                all_hosts.update(await _mine_host(client, h, domain))
        await asyncio.gather(*(one(h) for h in live_hosts))

    return _split(all_hosts, domain)


def _cert_sans_blocking(host: str, port: int = 443, timeout: float = 6) -> set[str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(_connect(host, port, timeout), server_hostname=host) as s:
            cert = s.getpeercert()
    except (ssl.SSLError, OSError, ValueError):
        return set()
    sans = set()
    for typ, val in (cert or {}).get("subjectAltName", ()):
        if typ.lower() == "dns":
            sans.add(val.lower().lstrip("*.").rstrip("."))
    return sans


def _connect(host, port, timeout):
    import socket
    return socket.create_connection((host, port), timeout=timeout)


async def cert_sans(hosts: list[str], domain: str,
                    concurrency: int = 30) -> set[str]:
    """Pull TLS SAN hostnames belonging to the target from each host's cert."""
    if not hosts:
        return set()
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(concurrency)
    found: set[str] = set()

    async def one(h):
        async with sem:
            sans = await loop.run_in_executor(None, _cert_sans_blocking, h)
            found.update(sans)

    await asyncio.gather(*(one(h) for h in hosts))
    return _clean(found, domain)
