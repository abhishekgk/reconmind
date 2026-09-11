"""In-scope allow-list — a safety guard for active scanning.

When the allow-list is non-empty, the active tools (recon, Fuzzer, Nuclei) will
refuse targets that aren't in scope. Empty list = no restriction (default, so
local use is unaffected). This is the safety pair for the optional auth gate:
even an authorized user can't point a hosted ReconMind at arbitrary targets.

Matching is host-based: an entry ``example.com`` matches ``example.com`` and any
subdomain ``*.example.com``. Stored in ~/.reconmind/scope.json.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from . import config

SCOPE_FILE = config.DATA_DIR.parent / "scope.json"


def _normalize(entry: str) -> str:
    e = (entry or "").strip().lower()
    if "://" in e:
        e = urlparse(e).hostname or e
    e = e.split("/")[0].split(":")[0]
    return e.lstrip("*.").strip(".")


def get_scope() -> list[str]:
    try:
        items = json.loads(SCOPE_FILE.read_text()).get("in_scope", [])
        return [x for x in (_normalize(i) for i in items) if x]
    except (OSError, json.JSONDecodeError):
        return []


def set_scope(items: list[str]) -> list[str]:
    clean = []
    for i in items or []:
        n = _normalize(i)
        if n and n not in clean:
            clean.append(n)
    SCOPE_FILE.write_text(json.dumps({"in_scope": clean}, indent=2))
    return clean


def _host(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        t = urlparse(t).hostname or t
    else:
        t = t.split("/")[0].split(":")[0]
    return (t or "").lower().strip(".")


def in_scope(target: str) -> bool:
    scope = get_scope()
    if not scope:                     # empty allow-list = unrestricted
        return True
    h = _host(target)
    return any(h == s or h.endswith("." + s) for s in scope)


def out_of_scope(targets: list[str]) -> list[str]:
    """Return the targets that are NOT in scope (empty if scope is unrestricted
    or everything matches)."""
    if not get_scope():
        return []
    seen, out = set(), []
    for t in targets:
        if not in_scope(t) and t not in seen:
            seen.add(t)
            out.append(t)
    return out
