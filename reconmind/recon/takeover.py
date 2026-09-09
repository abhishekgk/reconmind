"""Subdomain takeover detection.

A dangling CNAME — a subdomain pointing (via CNAME) at a third-party service
resource that no longer exists — can often be claimed by an attacker. These are
real, reportable bug-bounty findings. We:
  1. bulk-resolve CNAMEs for every discovered name (dnsx if present, else dig),
  2. match the CNAME target against known takeover-able services,
  3. fetch the page and look for the service's "unclaimed" fingerprint.

Confidence:
  - "high"     — CNAME matches a service AND the page shows its takeover fingerprint
  - "review"   — CNAME matches a takeover-able service (verify manually before claiming)
"""
from __future__ import annotations

import asyncio
import json

import httpx

from .. import config
from .sources import UA

# service -> (list of CNAME substrings, list of body fingerprints)
SERVICES: dict[str, tuple[list[str], list[str]]] = {
    "AWS/S3": (["s3.amazonaws.com", "s3-website", "s3.", ".amazonaws.com"],
               ["NoSuchBucket", "The specified bucket does not exist"]),
    "GitHub Pages": (["github.io"],
                     ["There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index.html file"]),
    "Heroku": (["herokuapp.com", "herokudns.com", "herokussl.com"],
               ["No such app", "herokucdn.com/error-pages/no-such-app.html"]),
    "Fastly": (["fastly.net"], ["Fastly error: unknown domain"]),
    "Shopify": (["myshopify.com"], ["Sorry, this shop is currently unavailable"]),
    "Zendesk": (["zendesk.com"], ["Help Center Closed"]),
    "Unbounce": (["unbouncepages.com"], ["The requested URL was not found on this server"]),
    "Ghost": (["ghost.io"], ["The thing you were looking for is no longer here"]),
    "Surge.sh": (["surge.sh"], ["project not found"]),
    "Bitbucket": (["bitbucket.io"], ["Repository not found"]),
    "Cargo": (["cargocollective.com"], ["404 Not Found"]),
    "Webflow": (["proxy-ssl.webflow.com", "webflow.io"], ["The page you are looking for doesn't exist or has been moved"]),
    "Wordpress": (["wordpress.com"], ["Do you want to register"]),
    "Pantheon": (["pantheonsite.io"], ["The gods are wise", "404 error unknown site"]),
    "Tumblr": (["domains.tumblr.com"], ["Whatever you were looking for doesn't currently exist at this address"]),
    "Netlify": (["netlify.app", "netlify.com"], ["Not Found - Request ID"]),
    "Readthedocs": (["readthedocs.io"], ["unknown to Read the Docs"]),
    "Azure": ([".azurewebsites.net", ".cloudapp.net", ".trafficmanager.net",
               ".blob.core.windows.net", ".azureedge.net", ".azure-api.net"],
              ["404 Web Site not found", "The specified blob does not exist"]),
    "Desk": (["desk.com"], ["Please try again or try Desk.com free for 14 days"]),
    "Help Scout": (["helpscoutdocs.com"], ["No settings were found for this company"]),
}


def _match_service(cname: str) -> str | None:
    c = cname.lower()
    for service, (patterns, _) in SERVICES.items():
        if any(p in c for p in patterns):
            return service
    return None


async def _cnames_dnsx(hosts: list[str]) -> dict[str, str]:
    proc = await asyncio.create_subprocess_exec(
        "dnsx", "-silent", "-cname", "-json",
        stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    out, _ = await proc.communicate("\n".join(hosts).encode())
    result: dict[str, str] = {}
    for line in out.decode(errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        host, cnames = row.get("host"), row.get("cname") or []
        if host and cnames:
            result[host] = cnames[0].rstrip(".").lower()
    return result


async def _cname_dig(host: str, sem: asyncio.Semaphore) -> tuple[str, str]:
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "+time=3", "+tries=1", "CNAME", host,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=8)
        except (asyncio.TimeoutError, OSError):
            return host, ""
        lines = [l.strip().rstrip(".").lower() for l in out.decode().splitlines() if l.strip()]
        return host, (lines[0] if lines else "")


async def _get_cnames(hosts: list[str]) -> dict[str, str]:
    if config.tool_path("dnsx"):
        try:
            return await _cnames_dnsx(hosts)
        except Exception:
            pass
    sem = asyncio.Semaphore(40)
    pairs = await asyncio.gather(*(_cname_dig(h, sem) for h in hosts))
    return {h: c for h, c in pairs if c}


async def _verify(host: str, service: str, client) -> tuple[bool, str]:
    """Fetch the host and look for the service's unclaimed fingerprint."""
    fingerprints = SERVICES[service][1]
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}", timeout=10)
        except Exception:
            continue
        body = r.text[:60000]
        for fp in fingerprints:
            if fp.lower() in body.lower():
                return True, fp
        return False, ""
    return False, ""


async def find_takeovers(hosts: list[str], cap: int = 20000) -> list[dict]:
    """Return takeover candidates among the given hosts."""
    if not hosts:
        return []
    cnames = await _get_cnames(hosts[:cap])
    candidates = [(h, c, _match_service(c)) for h, c in cnames.items()]
    candidates = [(h, c, s) for h, c, s in candidates if s]
    if not candidates:
        return []

    findings: list[dict] = []
    sem = asyncio.Semaphore(30)
    async with httpx.AsyncClient(follow_redirects=True, verify=False,
                                 headers={"User-Agent": UA}) as client:
        async def check(host, cname, service):
            async with sem:
                matched, evidence = await _verify(host, service, client)
            findings.append({
                "host": host, "cname": cname, "service": service,
                "confidence": "high" if matched else "review",
                "evidence": evidence,
            })
        await asyncio.gather(*(check(h, c, s) for h, c, s in candidates))

    findings.sort(key=lambda f: (f["confidence"] != "high", f["host"]))
    return findings
