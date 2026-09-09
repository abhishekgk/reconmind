"""LLM integration — a mentor that answers *from the dashboard data*.

Two backends:
  - Anthropic Claude (via the official SDK) when an Anthropic API key is set —
    far better, and it actually reasons over the scan data you give it.
  - Local Ollama otherwise — private and free, but weaker.

The key to useful answers is grounding: we build a compact, *question-aware*
view of the scan (relevant subdomains, IPs, ASNs, ports, endpoints) and instruct
the model to answer ONLY from that data. This is what stops the hallucinations —
the old code fed the model almost none of the dashboard.
"""
from __future__ import annotations

import os
import re

import httpx

from . import config, keys

# --- Provider selection -------------------------------------------------------

CLAUDE_MODEL = os.environ.get("RECONMIND_CLAUDE_MODEL", "claude-opus-4-8")


def _anthropic_key() -> str | None:
    return keys.get_field("anthropic", "key")


def provider(prefer_local: bool = False) -> str:
    """Which backend to use: 'claude' if a key is set (and not overridden), else 'ollama'."""
    if not prefer_local and _anthropic_key():
        return "claude"
    return "ollama"


# --- Grounding: build data the model can actually reason over -----------------

STOPWORDS = {
    "the", "and", "for", "what", "which", "that", "this", "with", "are", "was",
    "how", "why", "does", "do", "is", "of", "to", "in", "on", "a", "an", "any",
    "all", "show", "me", "find", "list", "about", "there", "have", "has", "can",
    "you", "these", "those", "from", "into", "most", "more", "some", "give",
    "tell", "explain", "look", "see", "get", "whats", "who", "where",
}


def _tokens(question: str) -> list[str]:
    words = re.findall(r"[a-z0-9.\-]{3,}", question.lower())
    return [w for w in words if w not in STOPWORDS]


def _retrieve(question: str, scan: dict, cap: int = 40) -> str:
    """Pull the rows from the scan that match the question — the RAG step."""
    toks = _tokens(question)
    if not toks:
        return ""
    def hit(*fields) -> bool:
        blob = " ".join(str(f).lower() for f in fields)
        return any(t in blob for t in toks)

    out: list[str] = []

    hosts = [h for h in scan.get("hosts", [])
             if hit(h["host"], h.get("title", ""), h.get("server", ""),
                    " ".join(h.get("sources", [])))]
    if hosts:
        out.append(f"Matching subdomains ({len(hosts)}):")
        for h in hosts[:cap]:
            live = f"live {h['status']}" if h.get("live") else "not live"
            out.append(f"- {h['host']} [{live}] {h.get('title','')[:50]} {h.get('server','')}")

    eps = [e for e in scan.get("endpoints", [])
           if hit(e.get("url", ""), e.get("host", ""), e.get("ext", ""))]
    if eps:
        out.append(f"Matching endpoints ({len(eps)}):")
        for e in eps[:cap]:
            out.append(f"- {e['url']}" + ("  [has params]" if e.get("params") else ""))

    ips = [r for r in scan.get("ip_assets", [])
           if hit(r["ip"], r.get("org", ""), "as" + str(r.get("asn", "")),
                  r.get("ptr", ""), " ".join(str(p) for p in r.get("ports", [])))]
    if ips:
        out.append(f"Matching IPs ({len(ips)}):")
        for r in ips[:cap]:
            ports = ",".join(str(p) for p in r.get("ports", []))
            out.append(f"- {r['ip']} AS{r.get('asn','')} {r.get('org','')} ports:[{ports}]")

    rel = [d for d in scan.get("related_domains", []) if hit(d)]
    if rel:
        out.append(f"Matching related domains ({len(rel)}): " + ", ".join(rel[:cap]))

    return "\n".join(out)


def _surface_digest(scan: dict, live_cap: int = 60) -> str:
    c = scan.get("counts", {})
    lines = [
        f"TARGET: {scan.get('domain')}",
        f"Totals — subdomains: {c.get('total',0)}, resolved: {c.get('resolved',0)}, "
        f"live: {c.get('live',0)}, IPs: {c.get('ips',0)}, ASNs: {c.get('asns',0)}, "
        f"related domains: {c.get('related',0)}, endpoints: {c.get('endpoints',0)}",
    ]

    live = [h for h in scan.get("hosts", []) if h.get("live")]
    if live:
        lines.append(f"\nLive hosts (host | status | title | server) — {len(live)} total, showing {min(live_cap,len(live))}:")
        for h in live[:live_cap]:
            lines.append(f"- {h['host']} | {h['status']} | {h.get('title','')[:50]} | {h.get('server','')}")

    asns = scan.get("asn_assets", [])
    if asns:
        lines.append("\nASNs / netblocks:")
        for a in asns[:15]:
            lines.append(f"- AS{a['asn']} {a['org']} — {a['ip_count']} IPs, prefixes: {', '.join(a.get('prefixes',[])[:4])}")

    ips_ports = [r for r in scan.get("ip_assets", []) if r.get("ports")]
    if ips_ports:
        lines.append("\nOpen ports (from Shodan):")
        for r in ips_ports[:25]:
            lines.append(f"- {r['ip']}: {', '.join(str(p) for p in r['ports'])}")

    eps = scan.get("endpoints", [])
    if eps:
        params = [e for e in eps if e.get("params")]
        lines.append(f"\nEndpoints: {len(eps)} total, {len(params)} with query params. Sample with params:")
        for e in params[:20]:
            lines.append(f"- {e['url']}")

    rel = scan.get("related_domains", [])
    if rel:
        lines.append("\nRelated domains: " + ", ".join(rel[:20]))
    return "\n".join(lines)


TEACHER_SYSTEM = (
    "You are a security-research mentor helping a bug-bounty learner understand "
    "reconnaissance results. You are grounded: the user gives you DATA from an "
    "actual scan and you answer ONLY from that DATA.\n"
    "RULES:\n"
    "- Use only facts present in the DATA section. Never invent subdomains, IPs, "
    "ASNs, ports, endpoints, versions, or vulnerabilities.\n"
    "- If the answer isn't in the DATA, say plainly that it's not in this scan and "
    "suggest what scan option would surface it (e.g. enable 'crawl', add a Shodan key).\n"
    "- Quote exact hostnames/IPs/URLs from the DATA when relevant.\n"
    "- Only discuss authorized, in-scope testing and responsible disclosure. "
    "Explain concepts clearly for a beginner; define jargon.\n"
    "- Be concise and specific. Prefer short bullet points over generic advice."
)


# --- Backends -----------------------------------------------------------------

async def _ollama_status() -> dict:
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{config.OLLAMA_HOST}/api/tags", timeout=5)
            r.raise_for_status()
            models = [m["name"] for m in r.json().get("models", [])]
    except Exception as e:
        return {"available": False, "models": [], "model": None, "error": str(e)}
    return {"available": True, "models": models, "model": _pick_ollama(models), "error": None}


def _pick_ollama(models: list[str]) -> str | None:
    installed = {m.split(":")[0]: m for m in models}
    for pref in config.PREFERRED_MODELS:
        if not pref:
            continue
        base = pref.split(":")[0]
        if pref in models:
            return pref
        if base in installed:
            return installed[base]
    return models[0] if models else None


async def status(prefer_local: bool = False) -> dict:
    """Report which backend is active and whether it's ready."""
    p = provider(prefer_local)
    if p == "claude":
        return {"provider": "claude", "available": True,
                "model": CLAUDE_MODEL, "claude_configured": True, "error": None}
    st = await _ollama_status()
    st["provider"] = "ollama"
    st["claude_configured"] = bool(_anthropic_key())
    return st


async def _claude_generate(prompt: str, system: str) -> str:
    import anthropic
    key = _anthropic_key()
    if not key:
        return "⚠️ No Anthropic API key set. Add one in ⚙ API keys, or the tool uses the local model."
    client = anthropic.AsyncAnthropic(api_key=key)
    try:
        resp = await client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=2000,
            system=system,
            messages=[{"role": "user", "content": prompt}],
        )
    except anthropic.AuthenticationError:
        return "⚠️ Anthropic API key rejected (401). Check the key in ⚙ API keys."
    except anthropic.RateLimitError:
        return "⚠️ Anthropic rate limit hit — wait a moment and retry."
    except anthropic.APIStatusError as e:
        return f"⚠️ Anthropic API error {e.status_code}: {e.message}"
    except Exception as e:
        return f"⚠️ Claude request failed: {e}"
    if resp.stop_reason == "refusal":
        return "⚠️ Claude declined to answer this request."
    return "".join(b.text for b in resp.content if b.type == "text").strip()


async def _ollama_generate(prompt: str, system: str) -> str:
    st = await _ollama_status()
    if not st["available"]:
        return ("⚠️ No LLM available. Either add an Anthropic API key in ⚙ API keys "
                "for Claude, or start the local model: `ollama serve` then "
                "`ollama pull llama3.1`.")
    model = st["model"]
    if not model:
        return "⚠️ Ollama is running but no model is installed. Run `ollama pull llama3.1`."
    payload = {"model": model, "prompt": prompt, "system": system, "stream": False,
               "options": {"temperature": 0.2}}
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(f"{config.OLLAMA_HOST}/api/generate", json=payload, timeout=180)
            r.raise_for_status()
            return r.json().get("response", "").strip()
    except Exception as e:
        return f"⚠️ Local LLM request failed: {e}"


async def generate(prompt: str, system: str = "", prefer_local: bool = False) -> str:
    if provider(prefer_local) == "claude":
        return await _claude_generate(prompt, system)
    return await _ollama_generate(prompt, system)


# --- Public tasks -------------------------------------------------------------

async def explain_scan(scan_dict: dict, prefer_local: bool = False) -> str:
    digest = _surface_digest(scan_dict)
    prompt = (
        "DATA (recon results for an authorized bug-bounty target):\n"
        f"{digest}\n\n"
        "Using ONLY the DATA above, help me learn:\n"
        "1. Summarize this target's attack surface in plain language — names, "
        "hosting (ASNs/orgs), exposed services, endpoints.\n"
        "2. Point out the specific live subdomains and open ports/endpoints most "
        "worth studying first, naming each exactly, and say *why*.\n"
        "3. What do the ASN/netblock and related-domain data tell us about the org?\n"
        "4. Safe, in-scope next learning steps.\n"
        "Keep it under ~350 words, short bullets. Do not invent anything not in the DATA."
    )
    return await generate(prompt, system=TEACHER_SYSTEM, prefer_local=prefer_local)


async def ask(question: str, scan_dict: dict | None = None,
              prefer_local: bool = False) -> str:
    if scan_dict:
        digest = _surface_digest(scan_dict, live_cap=30)
        matches = _retrieve(question, scan_dict)
        data = f"DATA (overview):\n{digest}"
        if matches:
            data += f"\n\nDATA (rows matching your question):\n{matches}"
        prompt = (
            f"{data}\n\n"
            f"Question: {question}\n\n"
            "Answer using ONLY the DATA above. If it isn't there, say so and name the "
            "scan option that would surface it. Quote exact hosts/IPs/URLs when relevant."
        )
    else:
        prompt = (
            f"Question: {question}\n\n"
            "No scan is loaded, so answer as a general security-research teaching "
            "question (concepts, methodology, definitions). Keep it in-scope and educational."
        )
    return await generate(prompt, system=TEACHER_SYSTEM, prefer_local=prefer_local)
