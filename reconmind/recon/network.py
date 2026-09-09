"""The network/infrastructure dimension: IPs -> ASNs/CIDRs -> ports & services.

A domain's assets aren't only DNS names. This module maps discovered IPs to the
owning ASN and BGP prefix (keyless, via Team Cymru's DNS service), grabs PTR
records, and — when a Shodan key is present — enriches each IP with open ports and
service banners plus any extra hostnames Shodan knows.

Optional reverse-DNS sweeps of a whole prefix can surface sibling hosts, but that
widens scope beyond the seed domain, so it is bounded and opt-in (deep mode).
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket

import httpx

from .. import keys


async def _dig_txt(name: str, timeout: int = 8) -> list[str]:
    """Resolve TXT records via `dig` (keyless, no extra dependency)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            "dig", "+short", "+time=3", "+tries=1", "TXT", name,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except (asyncio.TimeoutError, FileNotFoundError, OSError):
        return []
    return [line.strip().strip('"') for line in out.decode().splitlines() if line.strip()]


def _is_ipv4(ip: str) -> bool:
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False


async def cymru_asn(ip: str) -> dict | None:
    """Return {asn, prefix, cc, registry} for an IPv4 via Team Cymru DNS."""
    if not _is_ipv4(ip):
        return None
    rev = ".".join(reversed(ip.split(".")))
    txt = await _dig_txt(f"{rev}.origin.asn.cymru.com")
    if not txt:
        return None
    # Format: "15169 | 8.8.8.0/24 | US | arin | 2000-03-30"
    parts = [p.strip() for p in txt[0].split("|")]
    if len(parts) < 4:
        return None
    asn = parts[0].split()[0]  # first ASN if several
    return {"asn": asn, "prefix": parts[1], "cc": parts[2], "registry": parts[3]}


_org_cache: dict[str, str] = {}


async def asn_org(asn: str) -> str:
    if asn in _org_cache:
        return _org_cache[asn]
    txt = await _dig_txt(f"AS{asn}.asn.cymru.com")
    org = ""
    if txt:
        # "15169 | US | arin | 2000-03-30 | GOOGLE, US"
        parts = [p.strip() for p in txt[0].split("|")]
        if parts:
            org = parts[-1]
    _org_cache[asn] = org
    return org


async def map_ips(ips: list[str], concurrency: int = 20) -> tuple[dict, dict]:
    """Map each IP to ASN/prefix/org. Returns (ip_info, asn_summary)."""
    sem = asyncio.Semaphore(concurrency)
    ip_info: dict[str, dict] = {}

    async def one(ip):
        async with sem:
            info = await cymru_asn(ip)
            if info:
                info["org"] = await asn_org(info["asn"])
                info["ptr"] = await _reverse(ip)
                ip_info[ip] = info

    await asyncio.gather(*(one(ip) for ip in ips))

    asn_summary: dict[str, dict] = {}
    for ip, info in ip_info.items():
        a = info["asn"]
        entry = asn_summary.setdefault(a, {"asn": a, "org": info["org"],
                                           "prefixes": set(), "ips": []})
        entry["prefixes"].add(info["prefix"])
        entry["ips"].append(ip)
    for entry in asn_summary.values():
        entry["prefixes"] = sorted(entry["prefixes"])
    return ip_info, asn_summary


async def _reverse(ip: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return name.lower().rstrip(".")
    except (socket.herror, socket.gaierror, OSError):
        return ""


async def reverse_sweep(prefixes: list[str], domain: str,
                        cap: int = 512) -> dict[str, str]:
    """PTR-scan up to `cap` addresses across the given prefixes (bounded).

    Returns {ip: ptr_hostname}. Used to find sibling hosts on the same netblock.
    """
    targets: list[str] = []
    for pfx in prefixes:
        try:
            net = ipaddress.ip_network(pfx, strict=False)
        except ValueError:
            continue
        if net.version != 4 or net.num_addresses > 65536:
            continue  # skip huge/IPv6 ranges for safety and speed
        for host in net.hosts():
            targets.append(str(host))
            if len(targets) >= cap:
                break
        if len(targets) >= cap:
            break

    sem = asyncio.Semaphore(64)
    found: dict[str, str] = {}

    async def one(ip):
        async with sem:
            ptr = await _reverse(ip)
            if ptr:
                found[ip] = ptr

    await asyncio.gather(*(one(ip) for ip in targets))
    return found


async def shodan_hosts(ips: list[str]) -> dict[str, dict]:
    """Enrich IPs with Shodan data: open ports, service names, extra hostnames."""
    key = keys.get_field("shodan", "key")
    if not key or not ips:
        return {}
    result: dict[str, dict] = {}
    sem = asyncio.Semaphore(4)  # Shodan free tier is rate-limited

    async with httpx.AsyncClient() as client:
        async def one(ip):
            async with sem:
                try:
                    r = await client.get(f"https://api.shodan.io/shodan/host/{ip}",
                                        params={"key": key}, timeout=25)
                    if r.status_code != 200:
                        return
                    d = r.json()
                except (httpx.HTTPError, json.JSONDecodeError, ValueError):
                    return
                services = []
                for item in d.get("data", []):
                    services.append({
                        "port": item.get("port"),
                        "transport": item.get("transport", ""),
                        "product": item.get("product", "") or item.get("_shodan", {}).get("module", ""),
                    })
                result[ip] = {
                    "ports": sorted(d.get("ports", [])),
                    "hostnames": d.get("hostnames", []),
                    "org": d.get("org", ""),
                    "os": d.get("os", ""),
                    "services": services,
                }
        await asyncio.gather(*(one(ip) for ip in ips))
    return result
