"""Permutation-based active discovery: guess sibling hostnames, then resolve.

Known hosts hint at unknown ones: `api` implies `api-dev`, `api2`, `api-staging`.
We generate permutations from the labels we've already found (plus common
affixes) and DNS-resolve them. Uses `alterx` when installed for richer patterns;
always falls back to a solid built-in generator.
"""
from __future__ import annotations

from .. import config
from . import resolve, runners

AFFIXES = [
    "dev", "test", "stage", "staging", "qa", "uat", "prod", "preprod", "sandbox",
    "demo", "beta", "alpha", "internal", "int", "admin", "api", "new", "old",
    "v1", "v2", "v3", "1", "2", "3", "app", "web", "gw", "corp", "eu", "us", "asia",
]


def _labels(host: str, domain: str) -> str:
    """The subdomain portion (everything left of the apex)."""
    if host == domain:
        return ""
    return host[: -(len(domain) + 1)]


def generate(known: list[str], domain: str, cap: int = 8000) -> set[str]:
    """Build candidate FQDNs by mutating the labels of known subdomains."""
    seeds = set()
    for h in known:
        sub = _labels(h, domain)
        if not sub:
            continue
        seeds.add(sub)
        # Focus on the left-most label (the most-mutated part).
        first = sub.split(".")[0]
        seeds.add(first)

    candidates: set[str] = set()
    for seed in seeds:
        for aff in AFFIXES:
            for pat in (f"{seed}-{aff}", f"{aff}-{seed}", f"{seed}{aff}",
                        f"{aff}.{seed}", f"{seed}.{aff}"):
                candidates.add(f"{pat}.{domain}")
                if len(candidates) >= cap:
                    return candidates
    return candidates


async def permute_and_resolve(known: list[str], domain: str,
                              cap: int = 8000) -> set[str]:
    candidates = generate(known, domain, cap)

    # Enrich with alterx patterns when available.
    if config.tool_path("alterx"):
        extra = await runners.alterx_resolve(domain, known)
        candidates.update(extra)

    if not candidates:
        return set()

    resolved = await resolve.resolve_filtered(sorted(candidates), domain)
    return set(resolved.keys())
