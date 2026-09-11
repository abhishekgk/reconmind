"""The scan engine: runs every discovery dimension and reports progress.

Dimensions, in order:
  1. Names   — passive OSINT (keyless + keyed), subfinder/assetfinder (+deep tools)
  2. Guessed — DNS bruteforce and permutations of known names (active mode)
  3. Resolve — every name -> IPs
  4. Live    — probe which names serve HTTP(S)
  5. Content — mine live pages/JS/CSP/robots + TLS cert SANs for more names
  6. Network — IPs -> ASN/CIDR/org (+Shodan ports/services, +reverse-DNS in deep)

Progress streams through an asyncio.Queue so the web UI updates live.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from . import (bruteforce, content, crawl, keyed_sources, network, permute,
               ports, resolve, runners, screenshots, sources, takeover)


@dataclass
class Scan:
    domain: str
    active: bool = False          # DNS bruteforce + permutations
    deep: bool = False            # amass/gau/github + reverse-DNS sweep + bigger caps
    crawl: bool = False           # deep endpoint/JS crawling
    brute_limit: int = 2000

    # host -> set of source names that found it
    found: dict[str, set[str]] = field(default_factory=dict)
    resolved: dict[str, list[str]] = field(default_factory=dict)
    live: list[dict] = field(default_factory=list)
    ips: dict[str, dict] = field(default_factory=dict)      # ip -> asn/org/ports/...
    asns: dict[str, dict] = field(default_factory=dict)     # asn -> org/prefixes/ips
    related_domains: set = field(default_factory=set)
    endpoints: list[dict] = field(default_factory=list)     # crawled URLs/endpoints
    takeovers: list[dict] = field(default_factory=list)     # subdomain takeover candidates
    shots: dict[str, str] = field(default_factory=dict)     # host -> screenshot path
    per_source: dict[str, int] = field(default_factory=dict)
    # Findings attached by the Fuzzer/Nuclei tabs (persisted with the scan).
    findings: dict = field(default_factory=lambda: {"nuclei": [], "exposures": [], "fuzz": []})

    events: asyncio.Queue = field(default_factory=asyncio.Queue)
    status: str = "pending"
    started: float = field(default_factory=time.time)
    finished: float | None = None

    def emit(self, kind: str, **data: Any) -> None:
        self.events.put_nowait({"kind": kind, "t": time.time(), **data})

    def _record(self, source: str, hosts: set[str]) -> None:
        new = 0
        for h in hosts:
            bucket = self.found.setdefault(h, set())
            if not bucket:
                new += 1
            bucket.add(source)
        self.per_source[source] = len(hosts)
        self.emit("source_done", source=source, count=len(hosts),
                  new=new, total=len(self.found))

    @property
    def all_hosts(self) -> list[str]:
        return sorted(self.found)

    def to_dict(self) -> dict:
        live_by_host = {l["host"]: l for l in self.live}
        takeover_by_host = {t["host"]: t for t in self.takeovers}
        rows = []
        for host in self.all_hosts:
            live = live_by_host.get(host)
            t = takeover_by_host.get(host)
            rows.append({
                "host": host,
                "sources": sorted(self.found[host]),
                "ips": self.resolved.get(host, []),
                "live": bool(live),
                "status": live["status"] if live else None,
                "title": live["title"] if live else "",
                "server": live["server"] if live else "",
                "url": live["url"] if live else "",
                "tech": live.get("tech", []) if live else [],
                "cdn": live.get("cdn", "") if live else "",
                "content_length": live.get("content_length", 0) if live else 0,
                "screenshot": self.shots.get(host, ""),
                "takeover": {"service": t["service"], "confidence": t["confidence"]} if t else None,
            })
        ip_rows = []
        for ip in sorted(self.ips):
            info = self.ips[ip]
            ip_rows.append({
                "ip": ip,
                "asn": info.get("asn", ""),
                "org": info.get("org", ""),
                "prefix": info.get("prefix", ""),
                "ptr": info.get("ptr", ""),
                "ports": info.get("ports", []),
                "services": info.get("services", []),
            })
        asn_rows = [
            {"asn": a, "org": v.get("org", ""),
             "prefixes": v.get("prefixes", []), "ip_count": len(v.get("ips", []))}
            for a, v in sorted(self.asns.items())
        ]
        return {
            "domain": self.domain,
            "status": self.status,
            "started": self.started,
            "finished": self.finished,
            "counts": {
                "total": len(self.found),
                "resolved": len(self.resolved),
                "live": len(self.live),
                "ips": len(self.ips),
                "asns": len(self.asns),
                "related": len(self.related_domains),
                "endpoints": len(self.endpoints),
                "takeovers": len(self.takeovers),
                "findings": sum(len(v) for v in self.findings.values()),
            },
            "per_source": self.per_source,
            "hosts": rows,
            "ip_assets": ip_rows,
            "asn_assets": asn_rows,
            "related_domains": sorted(self.related_domains),
            "endpoints": self.endpoints,
            "takeovers": self.takeovers,
            "findings": self.findings,
        }


async def run_scan(scan: Scan) -> Scan:
    scan.status = "running"
    scan.emit("status", status="running")

    # --- 1. Names: passive OSINT (keyless + keyed) + tools -------------------
    scan.emit("phase", phase="Passive OSINT + tools + your API keys")
    keyed_holder: dict = {}

    async def run_keyed():
        keyed_holder.update(
            await keyed_sources.gather_keyed(scan.domain, on_source=scan._record))

    await asyncio.gather(
        sources.gather_passive(scan.domain, on_source=scan._record),
        runners.gather_tools(scan.domain, on_source=scan._record, deep=scan.deep),
        run_keyed(),
    )
    scan.related_domains |= keyed_holder.get("related", set())

    # --- 2. Guessed: bruteforce + permutations (active) ----------------------
    if scan.active:
        scan.emit("phase", phase="Active DNS bruteforce")
        scan._record("bruteforce",
                     await bruteforce.bruteforce(scan.domain, limit=scan.brute_limit))
        scan.emit("phase", phase="Permutation guessing")
        cap = 20000 if scan.deep else 8000
        scan._record("permutation",
                     await permute.permute_and_resolve(scan.all_hosts, scan.domain, cap))

    # --- 3. Resolve ----------------------------------------------------------
    scan.emit("phase", phase=f"Resolving {len(scan.all_hosts)} names")
    scan.resolved = await resolve.resolve(scan.all_hosts)
    scan.emit("resolved", count=len(scan.resolved))

    # --- 4. Live probe -------------------------------------------------------
    scan.emit("phase", phase="Probing live hosts")
    scan.live = await resolve.probe_live(list(scan.resolved.keys()))
    scan.emit("live", count=len(scan.live))

    # --- 5. Content mining + cert SANs (may reveal more names) ---------------
    scan.emit("phase", phase="Mining page content, JS & TLS certs")
    live_hosts = [l["host"] for l in scan.live]
    mine_cap = live_hosts if scan.deep else live_hosts[:75]
    (mined, related), sans = await asyncio.gather(
        content.mine_live(mine_cap, scan.domain),
        content.cert_sans(list(scan.resolved.keys())[:300], scan.domain),
    )
    scan.related_domains |= related
    before = len(scan.found)
    scan._record("content", mined)
    scan._record("cert-san", sans)
    new_names = [h for h in (mined | sans) if h not in scan.resolved]
    if new_names:
        newly = await resolve.resolve(new_names)
        scan.resolved.update(newly)
        fresh = await resolve.probe_live(list(newly.keys()))
        existing = {l["host"] for l in scan.live}
        scan.live.extend(f for f in fresh if f["host"] not in existing)
        scan.emit("resolved", count=len(scan.resolved))
        scan.emit("live", count=len(scan.live))
    scan.emit("phase", phase=f"Content phase found {len(scan.found) - before} new names")

    # --- 6. Screenshots (deep only; needs gowitness + Chrome) ----------------
    if scan.deep:
        scan.emit("phase", phase="Capturing screenshots")
        scan.shots = await screenshots.capture(
            scan.domain, scan.live, deep=scan.deep,
            on_progress=lambda m: scan.emit("phase", phase=m))
        if scan.shots:
            scan.emit("shots", count=len(scan.shots))

    # --- 7. Network: IP -> ASN/CIDR/org, Shodan, reverse DNS -----------------
    scan.emit("phase", phase="Mapping IPs to ASNs / networks")
    all_ips = sorted({ip for ips in scan.resolved.values() for ip in ips})
    ip_info, asn_summary = await network.map_ips(all_ips)
    scan.ips = ip_info
    scan.asns = asn_summary

    shodan = await network.shodan_hosts(all_ips)
    for ip, sh in shodan.items():
        scan.ips.setdefault(ip, {}).update(
            {"ports": sh["ports"], "services": sh["services"]})
        # Shodan often reports extra hostnames for an IP.
        scan._record("shodan-host", {h for h in sh.get("hostnames", [])
                                     if h.endswith("." + scan.domain) or h == scan.domain})
    scan.emit("network", ips=len(scan.ips), asns=len(scan.asns))

    if scan.deep and scan.asns:
        scan.emit("phase", phase="Reverse-DNS sweep of discovered netblocks")
        prefixes = sorted({p for v in scan.asns.values() for p in v["prefixes"]})
        ptrs = await network.reverse_sweep(prefixes, scan.domain, cap=1024)
        scan._record("reverse-dns", {n for n in ptrs.values()
                                     if n.endswith("." + scan.domain) or n == scan.domain})

    # --- 8. Port scan resolved IPs with naabu (deep) -------------------------
    if scan.deep:
        naabu_ports = await ports.scan_ports(
            all_ips, deep=scan.deep,
            on_progress=lambda m: scan.emit("phase", phase=m))
        for ip, plist in naabu_ports.items():
            info = scan.ips.setdefault(ip, {})
            merged = sorted(set(info.get("ports", [])) | set(plist))
            info["ports"] = merged
        if naabu_ports:
            scan.emit("network", ips=len(scan.ips), asns=len(scan.asns))

    # --- 9. Subdomain takeover detection -------------------------------------
    scan.emit("phase", phase="Checking for subdomain takeovers")
    scan.takeovers = await takeover.find_takeovers(scan.all_hosts)
    scan.emit("takeovers", count=len(scan.takeovers))

    # --- 10. Deep enumeration: crawl + JS endpoints --------------------------
    if scan.crawl:
        scan.emit("phase", phase="Crawling sites + parsing JavaScript for endpoints")
        scan.endpoints = await crawl.crawl(
            scan.domain, scan.live, deep=scan.deep,
            on_progress=lambda msg: scan.emit("phase", phase=msg))
        scan.emit("endpoints", count=len(scan.endpoints))

    scan.status = "done"
    scan.finished = time.time()
    scan.emit("done", **scan.to_dict()["counts"])
    return scan
