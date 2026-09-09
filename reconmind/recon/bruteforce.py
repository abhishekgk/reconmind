"""Optional active enumeration: DNS bruteforce of candidate subdomains.

This is 'active' because it sends DNS queries for guessed names. It is still
non-intrusive (DNS lookups only), but it is off by default so passive scans stay
purely observational. Uses puredns+massdns when available for speed; otherwise
falls back to bounded pure-Python resolution.
"""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from .. import config
from . import resolve


def _candidates(domain: str, words: list[str]) -> list[str]:
    return [f"{w.strip()}.{domain}" for w in words if w.strip()]


def _load_words(limit: int | None) -> list[str]:
    if config.WORDLIST_FILE:
        words = Path(config.WORDLIST_FILE).read_text(errors="replace").splitlines()
    else:
        words = list(config.BUILTIN_SUBWORDS)
    if limit:
        words = words[:limit]
    return words


async def _puredns(candidates: list[str]) -> set[str]:
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(candidates))
        cand_file = f.name

    cmd = ["puredns", "resolve", cand_file, "--quiet"]
    if config.RESOLVERS_FILE:
        cmd += ["-r", config.RESOLVERS_FILE]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    out, _ = await proc.communicate()
    Path(cand_file).unlink(missing_ok=True)
    return {line.strip().lower() for line in out.decode().splitlines() if line.strip()}


async def bruteforce(domain: str, limit: int | None = 5000) -> set[str]:
    """Return subdomains discovered by DNS bruteforce.

    `limit` caps how many wordlist entries to try (keeps demo scans fast).
    """
    words = _load_words(limit)
    candidates = _candidates(domain, words)
    if not candidates:
        return set()

    if config.tool_path("puredns"):
        try:
            return await _puredns(candidates)
        except Exception:
            pass

    # Pure-python fallback: resolve candidates, dropping DNS-wildcard false positives.
    resolved = await resolve.resolve_filtered(candidates, domain)
    return set(resolved.keys())
