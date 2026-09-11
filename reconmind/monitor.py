"""Monitoring mode — scheduled re-scans + "what's new since last time".

A monitor watches a target domain and re-runs recon on an interval. After each
run it diffs against the previous saved scan of that domain and records the NEW
assets (subdomains, live hosts, endpoints, takeover candidates) — because new
attack surface is where fresh bugs appear. Alerts are surfaced in the UI's
Monitor panel (this is a local tool; no email/webhook by default).

State lives in ~/.reconmind/monitors.json. The scheduler loop itself runs in the
web server (see server/app.py); this module is just storage + diffing.
"""
from __future__ import annotations

import json
import time
import uuid

from . import config, store

MON_FILE = config.DATA_DIR.parent / "monitors.json"
_ITEM_CAP = 300


def _load() -> dict:
    try:
        return json.loads(MON_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {"monitors": []}


def _save(d: dict) -> None:
    MON_FILE.write_text(json.dumps(d, indent=2))


def list_monitors() -> list[dict]:
    return _load().get("monitors", [])


def get(mid: str) -> dict | None:
    return next((m for m in list_monitors() if m["id"] == mid), None)


def add(domain: str, interval_hours: float = 24, deep: bool = False,
        active: bool = True) -> dict:
    d = _load()
    m = {
        "id": uuid.uuid4().hex[:12],
        "domain": domain,
        "interval_hours": max(1, float(interval_hours or 24)),
        "deep": bool(deep),
        "active": bool(active),
        "created": time.time(),
        "last_run": None,
        "last_status": "pending",
        "last_file": None,
        "new_counts": {},
        "new_items": {},
        "error": None,
    }
    d.setdefault("monitors", []).append(m)
    _save(d)
    return m


def update(mid: str, **fields) -> dict | None:
    d = _load()
    for m in d.get("monitors", []):
        if m["id"] == mid:
            m.update(fields)
            _save(d)
            return m
    return None


def remove(mid: str) -> bool:
    d = _load()
    before = len(d.get("monitors", []))
    d["monitors"] = [m for m in d.get("monitors", []) if m["id"] != mid]
    _save(d)
    return len(d["monitors"]) < before


def set_active(mid: str, active: bool) -> dict | None:
    return update(mid, active=bool(active))


def due(m: dict, now: float | None = None) -> bool:
    if not m.get("active"):
        return False
    now = now or time.time()
    if not m.get("last_run"):
        return True
    return (now - m["last_run"]) >= m["interval_hours"] * 3600


def previous_file(domain: str, exclude: str | None = None) -> str | None:
    """Newest saved scan file for a domain (optionally excluding one filename)."""
    for s in store.list_scans():           # already newest-first
        if s.get("domain") == domain and s.get("file") != exclude:
            return s["file"]
    return None


def _sets(scan: dict) -> dict:
    hosts = scan.get("hosts", [])
    return {
        "subdomains": {h["host"] for h in hosts},
        "live": {h["host"] for h in hosts if h.get("live")},
        "endpoints": {e.get("url") for e in scan.get("endpoints", [])},
        "takeovers": {t.get("host") for t in scan.get("takeovers", [])},
    }


def diff_new(current: dict, previous: dict | None) -> tuple[dict, dict]:
    """Return (counts, items) of what's NEW in `current` vs `previous`.

    With no previous scan, nothing is 'new' (it's the baseline) — counts are 0."""
    cur = _sets(current)
    if not previous:
        return {k: 0 for k in cur}, {k: [] for k in cur}
    prev = _sets(previous)
    counts, items = {}, {}
    for k in cur:
        new = sorted(x for x in cur[k] if x and x not in prev[k])
        counts[k] = len(new)
        items[k] = new[:_ITEM_CAP]
    return counts, items
