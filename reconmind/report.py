"""Turn a scan into a shareable report — Markdown or a self-contained HTML page.

Used by the UI's Export menu and the CLI's --report flag. Pure string building,
no dependencies, so it works everywhere the rest of the tool does.
"""
from __future__ import annotations

import html
import re
import time

# Hosts whose names commonly reward a closer look — mirrors the UI's ★ heuristic.
INTERESTING = re.compile(
    r"(^|[.\-])(dev|test|stage|staging|uat|qa|sandbox|internal|intranet|corp|admin|"
    r"api|graphql|gateway|auth|sso|login|jenkins|gitlab|git|jira|grafana|kibana|vpn|"
    r"legacy|old|beta|backup|s3|storage|preprod|demo)([.\-]|$)", re.I)


def _when(scan: dict) -> str:
    ts = scan.get("finished") or scan.get("started") or time.time()
    try:
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(ts))
    except (TypeError, ValueError):
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())


def _live(scan: dict) -> list[dict]:
    return [h for h in scan.get("hosts", []) if h.get("live")]


def _tech(h: dict) -> str:
    parts = list(h.get("tech", []) or [])
    if h.get("cdn"):
        parts.append(f"cdn:{h['cdn']}")
    if h.get("server"):
        parts.append(h["server"])
    return ", ".join(str(p) for p in parts)


# --- Markdown -----------------------------------------------------------------

def to_markdown(scan: dict) -> str:
    d = scan.get("domain", "target")
    c = scan.get("counts", {})
    L: list[str] = []
    L.append(f"# ReconMind report — {d}")
    L.append("")
    L.append(f"*Generated {_when(scan)} · authorized, in-scope testing only.*")
    L.append("")
    L.append("## Summary")
    L.append("")
    L.append("| Metric | Count |")
    L.append("|---|---|")
    for label, key in [("Subdomains", "total"), ("Live hosts", "live"),
                       ("IPs", "ips"), ("ASNs / netblocks", "asns"),
                       ("Endpoints", "endpoints"), ("Related domains", "related"),
                       ("Takeover candidates", "takeovers"), ("Findings", "findings")]:
        L.append(f"| {label} | {c.get(key, 0)} |")
    L.append("")

    findings = scan.get("findings", {}) or {}
    nuc, exp = findings.get("nuclei", []), findings.get("exposures", [])
    if nuc or exp:
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        L.append("## Findings")
        L.append("")
        if nuc:
            L.append(f"### Nuclei ({len(nuc)})")
            L.append("")
            L.append("| Severity | Template | Name | Matched URL |")
            L.append("|---|---|---|---|")
            for n in sorted(nuc, key=lambda r: _order.get(r.get("severity"), 9))[:300]:
                name = (n.get("name") or "").replace("|", "\\|")
                L.append(f"| {n.get('severity','')} | `{n.get('template','')}` | {name} | `{n.get('url','')}` |")
            L.append("")
        if exp:
            L.append(f"### Exposed files ({len(exp)})")
            L.append("")
            L.append("| Severity | Type | URL |")
            L.append("|---|---|---|")
            for e in sorted(exp, key=lambda r: _order.get(r.get("severity"), 9))[:200]:
                L.append(f"| {e.get('severity','')} | {e.get('type','')} | `{e.get('url','')}` |")
            L.append("")

    takeovers = scan.get("takeovers", [])
    if takeovers:
        L.append("## ⚠ Subdomain takeover candidates")
        L.append("")
        L.append("| Confidence | Host | Service | CNAME target |")
        L.append("|---|---|---|---|")
        for t in sorted(takeovers, key=lambda x: 0 if x.get("confidence") == "high" else 1):
            L.append(f"| {t.get('confidence','')} | `{t.get('host','')}` | "
                     f"{t.get('service','')} | `{t.get('cname','')}` |")
        L.append("")

    live = _live(scan)
    if live:
        L.append(f"## Live hosts ({len(live)})")
        L.append("")
        L.append("| Host | Status | Title | Tech / Server |")
        L.append("|---|---|---|---|")
        for h in sorted(live, key=lambda x: (not INTERESTING.search(x["host"]), x["host"])):
            star = "★ " if INTERESTING.search(h["host"]) else ""
            title = (h.get("title") or "").replace("|", "\\|")[:60]
            L.append(f"| {star}`{h['host']}` | {h.get('status','')} | {title} | {_tech(h)} |")
        L.append("")

    ports = [r for r in scan.get("ip_assets", []) if r.get("ports")]
    if ports:
        L.append("## Open ports")
        L.append("")
        L.append("| IP | ASN / Org | Open ports |")
        L.append("|---|---|---|")
        for r in ports:
            org = f"AS{r.get('asn','')} {r.get('org','')}".strip()
            L.append(f"| `{r['ip']}` | {org} | {', '.join(str(p) for p in r['ports'])} |")
        L.append("")

    asns = scan.get("asn_assets", [])
    if asns:
        L.append("## ASNs / netblocks")
        L.append("")
        L.append("| ASN | Organization | Netblocks | IPs seen |")
        L.append("|---|---|---|---|")
        for a in asns:
            L.append(f"| AS{a.get('asn','')} | {a.get('org','')} | "
                     f"{', '.join(a.get('prefixes', [])[:4])} | {a.get('ip_count', 0)} |")
        L.append("")

    eps = scan.get("endpoints", [])
    params = [e for e in eps if e.get("params")]
    if params:
        L.append(f"## Endpoints with parameters ({len(params)} of {len(eps)})")
        L.append("")
        for e in params[:200]:
            L.append(f"- `{e['url']}`")
        if len(params) > 200:
            L.append(f"- …and {len(params) - 200} more (see the full JSON export).")
        L.append("")

    rel = scan.get("related_domains", [])
    if rel:
        L.append("## Related domains")
        L.append("")
        L.append(", ".join(f"`{r}`" for r in rel))
        L.append("")

    L.append("---")
    L.append("")
    L.append("*Produced by [ReconMind](https://github.com/) — a learning-focused, "
             "local-first recon orchestrator. Discovery only; nothing here is a "
             "confirmed vulnerability.*")
    return "\n".join(L) + "\n"


# --- HTML ---------------------------------------------------------------------

_HTML_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--border:#2a3240;--text:#e6edf3;--dim:#8b949e;
--accent:#3fb950;--accent2:#58a6ff;--warn:#d29922;--bad:#f85149}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;padding:32px}
.wrap{max-width:1040px;margin:0 auto}
h1{font-size:26px;margin:0 0 4px} h2{font-size:18px;margin:30px 0 10px;
border-bottom:1px solid var(--border);padding-bottom:6px}
.meta{color:var(--dim);font-size:13px;margin-bottom:20px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;
padding:12px 18px;min-width:100px}
.card .n{font-size:26px;font-weight:700}.card .l{color:var(--dim);font-size:11px;
text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:13px;margin:8px 0}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.star{color:var(--warn)}
.tag{font-family:ui-monospace,monospace;font-size:11px;background:#1c2230;
border:1px solid var(--border);border-radius:4px;padding:1px 6px;margin:1px;
display:inline-block;color:var(--accent)}
.hi{color:var(--bad);font-weight:700}.med{color:var(--warn);font-weight:700}
footer{color:var(--dim);font-size:12px;margin-top:30px;border-top:1px solid var(--border);padding-top:12px}
a{color:var(--accent2)}
"""


def _e(s) -> str:
    return html.escape(str(s or ""))


def to_html(scan: dict) -> str:
    d = scan.get("domain", "target")
    c = scan.get("counts", {})
    P: list[str] = []
    P.append("<!doctype html><html lang=en><head><meta charset=utf-8>")
    P.append('<meta name=viewport content="width=device-width,initial-scale=1">')
    P.append(f"<title>ReconMind — {_e(d)}</title><style>{_HTML_CSS}</style></head><body><div class=wrap>")
    P.append(f"<h1>ReconMind report — {_e(d)}</h1>")
    P.append(f'<div class=meta>Generated {_e(_when(scan))} · authorized, in-scope testing only.</div>')

    cards = [("Subdomains", "total"), ("Live", "live"), ("IPs", "ips"),
             ("ASNs", "asns"), ("Endpoints", "endpoints"), ("Related", "related"),
             ("Takeovers", "takeovers"), ("Findings", "findings")]
    P.append('<div class=cards>')
    for label, key in cards:
        P.append(f'<div class=card><div class=n>{_e(c.get(key, 0))}</div>'
                 f'<div class=l>{_e(label)}</div></div>')
    P.append('</div>')

    takeovers = scan.get("takeovers", [])
    if takeovers:
        P.append("<h2>⚠ Subdomain takeover candidates</h2>")
        P.append("<table><thead><tr><th>Confidence</th><th>Host</th><th>Service</th>"
                 "<th>CNAME target</th></tr></thead><tbody>")
        for t in sorted(takeovers, key=lambda x: 0 if x.get("confidence") == "high" else 1):
            cls = "hi" if t.get("confidence") == "high" else "med"
            P.append(f'<tr><td class={cls}>{_e(t.get("confidence"))}</td>'
                     f'<td class=mono>{_e(t.get("host"))}</td><td>{_e(t.get("service"))}</td>'
                     f'<td class=mono>{_e(t.get("cname"))}</td></tr>')
        P.append("</tbody></table>")

    findings = scan.get("findings", {}) or {}
    nuc, exp = findings.get("nuclei", []), findings.get("exposures", [])
    if nuc or exp:
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
        _sc = {"critical": "hi", "high": "hi", "medium": "med"}
        P.append("<h2>Findings</h2>")
        if nuc:
            P.append(f"<h3>Nuclei ({len(nuc)})</h3>")
            P.append("<table><thead><tr><th>Severity</th><th>Template</th><th>Name</th>"
                     "<th>Matched URL</th></tr></thead><tbody>")
            for n in sorted(nuc, key=lambda r: _order.get(r.get("severity"), 9)):
                cls = _sc.get(n.get("severity"), "")
                P.append(f'<tr><td class={cls}>{_e(n.get("severity"))}</td>'
                         f'<td class=mono>{_e(n.get("template"))}</td><td>{_e(n.get("name"))}</td>'
                         f'<td class=mono><a href="{_e(n.get("url"))}" target=_blank rel=noopener>{_e(n.get("url"))}</a></td></tr>')
            P.append("</tbody></table>")
        if exp:
            P.append(f"<h3>Exposed files ({len(exp)})</h3>")
            P.append("<table><thead><tr><th>Severity</th><th>Type</th><th>URL</th>"
                     "</tr></thead><tbody>")
            for e in sorted(exp, key=lambda r: _order.get(r.get("severity"), 9)):
                cls = _sc.get(e.get("severity"), "")
                P.append(f'<tr><td class={cls}>{_e(e.get("severity"))}</td><td>{_e(e.get("type"))}</td>'
                         f'<td class=mono><a href="{_e(e.get("url"))}" target=_blank rel=noopener>{_e(e.get("url"))}</a></td></tr>')
            P.append("</tbody></table>")

    live = _live(scan)
    if live:
        P.append(f"<h2>Live hosts ({len(live)})</h2>")
        P.append("<table><thead><tr><th>Host</th><th>Status</th><th>Title</th>"
                 "<th>Tech / Server</th></tr></thead><tbody>")
        for h in sorted(live, key=lambda x: (not INTERESTING.search(x["host"]), x["host"])):
            star = '<span class=star>★</span> ' if INTERESTING.search(h["host"]) else ""
            P.append(f'<tr><td class=mono>{star}{_e(h["host"])}</td><td>{_e(h.get("status"))}</td>'
                     f'<td>{_e((h.get("title") or "")[:70])}</td><td>{_e(_tech(h))}</td></tr>')
        P.append("</tbody></table>")

    ports = [r for r in scan.get("ip_assets", []) if r.get("ports")]
    if ports:
        P.append("<h2>Open ports</h2>")
        P.append("<table><thead><tr><th>IP</th><th>ASN / Org</th><th>Open ports</th>"
                 "</tr></thead><tbody>")
        for r in ports:
            org = _e(f"AS{r.get('asn','')} {r.get('org','')}".strip())
            tags = "".join(f'<span class=tag>{_e(p)}</span>' for p in r["ports"])
            P.append(f'<tr><td class=mono>{_e(r["ip"])}</td><td>{org}</td><td>{tags}</td></tr>')
        P.append("</tbody></table>")

    asns = scan.get("asn_assets", [])
    if asns:
        P.append("<h2>ASNs / netblocks</h2>")
        P.append("<table><thead><tr><th>ASN</th><th>Organization</th><th>Netblocks</th>"
                 "<th>IPs</th></tr></thead><tbody>")
        for a in asns:
            pref = "<br>".join(_e(p) for p in a.get("prefixes", [])[:6])
            P.append(f'<tr><td class=mono>AS{_e(a.get("asn"))}</td><td>{_e(a.get("org"))}</td>'
                     f'<td class=mono>{pref}</td><td>{_e(a.get("ip_count", 0))}</td></tr>')
        P.append("</tbody></table>")

    eps = scan.get("endpoints", [])
    params = [e for e in eps if e.get("params")]
    if params:
        P.append(f"<h2>Endpoints with parameters ({len(params)} of {len(eps)})</h2><ul>")
        for e in params[:300]:
            P.append(f'<li class=mono><a href="{_e(e["url"])}" target=_blank '
                     f'rel=noopener>{_e(e["url"])}</a></li>')
        P.append("</ul>")

    rel = scan.get("related_domains", [])
    if rel:
        P.append("<h2>Related domains</h2><p class=mono>"
                 + ", ".join(_e(r) for r in rel) + "</p>")

    P.append("<footer>Produced by ReconMind — a learning-focused, local-first recon "
             "orchestrator. Discovery only; nothing here is a confirmed vulnerability.</footer>")
    P.append("</div></body></html>")
    return "".join(P)
