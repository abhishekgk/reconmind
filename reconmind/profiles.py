"""Saved scan profiles — named Fuzzer/Nuclei configurations you can reload.

Stored in ~/.reconmind/profiles.json as {"fuzz": {name: cfg}, "nuclei": {name: cfg}}.
Configs are whatever the UI snapshots (tool/wordlist/headers, or modules/tags/
severity, etc.) minus the per-run target — so you can re-run a setup in one click.
"""
from __future__ import annotations

import json

from . import config

PROFILES_FILE = config.DATA_DIR.parent / "profiles.json"
_KINDS = ("fuzz", "nuclei")


def _load() -> dict:
    try:
        d = json.loads(PROFILES_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        d = {}
    for k in _KINDS:
        d.setdefault(k, {})
    return d


def _save(d: dict) -> None:
    try:
        PROFILES_FILE.write_text(json.dumps(d, indent=2))
    except OSError:
        pass


def list_profiles() -> dict:
    d = _load()
    return {"fuzz": d.get("fuzz", {}), "nuclei": d.get("nuclei", {})}


def save_profile(kind: str, name: str, cfg: dict) -> tuple[bool, str]:
    name = (name or "").strip()
    if kind not in _KINDS:
        return False, "unknown profile kind"
    if not name or len(name) > 60:
        return False, "profile name required (<=60 chars)"
    d = _load()
    d[kind][name] = cfg or {}
    _save(d)
    return True, ""


def delete_profile(kind: str, name: str) -> bool:
    d = _load()
    if kind in _KINDS and name in d.get(kind, {}):
        d[kind].pop(name, None)
        _save(d)
        return True
    return False
