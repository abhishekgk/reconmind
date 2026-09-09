"""Wrappers that drive external CLI recon tools as async subprocesses.

Each runner returns a set of subdomains. If the tool isn't installed, the runner
returns an empty set instead of raising, so scans degrade gracefully.
"""
from __future__ import annotations

import asyncio
import os
import re

from .. import config, keys

_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9\-_.]{0,253}[A-Za-z0-9])?")


def _env() -> dict:
    """Subprocess env with key-derived vars (GITHUB_TOKEN, SHODAN_API_KEY, ...)."""
    e = dict(os.environ)
    e.update(keys.env_overrides())
    return e


def _clean(lines: list[str], domain: str) -> set[str]:
    out: set[str] = set()
    dom = domain.lower().lstrip(".")
    for line in lines:
        h = line.strip().lower().rstrip(".").lstrip("*.")
        if not h:
            continue
        if (h == dom or h.endswith("." + dom)) and _HOST_RE.fullmatch(h):
            out.add(h)
    return out


async def _run(cmd: list[str], input_text: str | None = None,
               timeout: int = 300) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode). Never raises on tool error."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=_env(),
        )
    except FileNotFoundError:
        return "", "tool not found", 127
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input_text.encode() if input_text else None),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        proc.kill()
        return "", "timeout", -1
    return stdout.decode(errors="replace"), stderr.decode(errors="replace"), proc.returncode


async def subfinder(domain: str) -> set[str]:
    if not config.tool_path("subfinder"):
        return set()
    cmd = ["subfinder", "-d", domain, "-silent", "-all"]
    # Feed the user's saved API keys so subfinder queries every provider it can.
    if keys.SUBFINDER_CONFIG.is_file() and keys.SUBFINDER_CONFIG.stat().st_size > 0:
        cmd += ["-provider-config", str(keys.SUBFINDER_CONFIG)]
    out, _, _ = await _run(cmd, timeout=180)
    return _clean(out.splitlines(), domain)


async def github_subdomains(domain: str) -> set[str]:
    """github-subdomains mines subdomains from code. Needs a GitHub token (env)."""
    if not config.tool_path("github-subdomains"):
        return set()
    if "GITHUB_TOKEN" not in _env():
        return set()
    out, _, _ = await _run(["github-subdomains", "-d", domain], timeout=120)
    return _clean(out.splitlines(), domain)


async def alterx_resolve(domain: str, known: list[str]) -> set[str]:
    """Generate permutations with alterx (if installed). Resolution happens later."""
    if not config.tool_path("alterx") or not known:
        return set()
    out, _, _ = await _run(["alterx", "-silent"], input_text="\n".join(known), timeout=60)
    return _clean(out.splitlines(), domain)


async def findomain(domain: str) -> set[str]:
    """findomain — fast, keyless subdomain enumeration. -q prints hosts only."""
    if not config.tool_path("findomain"):
        return set()
    out, _, _ = await _run(["findomain", "-t", domain, "-q"], timeout=120)
    return _clean(out.splitlines(), domain)


async def assetfinder(domain: str) -> set[str]:
    if not config.tool_path("assetfinder"):
        return set()
    out, _, _ = await _run(["assetfinder", "--subs-only", domain], timeout=60)
    hosts = _clean(out.splitlines(), domain)
    if not hosts:
        # Likely throttled by shared upstreams (crt.sh/certspotter) mid-scan — retry.
        await asyncio.sleep(6)
        out, _, _ = await _run(["assetfinder", "--subs-only", domain], timeout=60)
        hosts = _clean(out.splitlines(), domain)
    return hosts


async def amass(domain: str) -> set[str]:
    if not config.tool_path("amass"):
        return set()
    # Passive only, but thorough and slow — hence gated behind "deep" mode.
    # -timeout is in minutes; we also hard-cap the subprocess as a backstop.
    out, _, _ = await _run(
        ["amass", "enum", "-passive", "-d", domain, "-nocolor", "-timeout", "3"],
        timeout=220,
    )
    hosts = []
    for line in out.splitlines():
        # amass prints "sub.example.com" possibly with extra graph text; extract hosts
        hosts.extend(re.findall(rf"[\w.\-]+\.{re.escape(domain)}", line))
    return _clean(hosts, domain)


async def gau_hosts(domain: str) -> set[str]:
    """Mine hostnames out of archived URLs (gau aggregates wayback/otx/commoncrawl)."""
    if not config.tool_path("gau"):
        return set()
    out, _, _ = await _run(["gau", "--subs", "--threads", "5", domain], timeout=90)
    hosts = re.findall(rf"https?://([\w.\-]+\.{re.escape(domain)})", out)
    return _clean(hosts, domain)


# Fast tools that run on every scan.
RUNNERS = {
    "subfinder": subfinder,
    "assetfinder": assetfinder,
    "findomain": findomain,
}

# Thorough but slow (or prone to rate-limit hangs); only run in "deep" mode.
DEEP_RUNNERS = {
    "amass": amass,
    "gau": gau_hosts,
    "github-subdomains": github_subdomains,
}


async def gather_tools(domain: str, on_source=None, deep: bool = False) -> dict[str, set[str]]:
    results: dict[str, set[str]] = {}
    active = dict(RUNNERS)
    if deep:
        active.update(DEEP_RUNNERS)

    async def run(name, fn):
        hosts = await fn(domain)
        results[name] = hosts
        if on_source:
            on_source(name, hosts)

    await asyncio.gather(*(run(n, f) for n, f in active.items()))
    return results
