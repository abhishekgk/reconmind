"""Tiny JSON-file store for scan results — no database to set up.

Each scan is saved as <data_dir>/<domain>_<timestamp>.json. Good enough for a
learning tool and trivially inspectable with `cat`/`jq`.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

from . import config


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", domain.lower())


def save(scan_dict: dict) -> Path:
    ts = time.strftime("%Y%m%d-%H%M%S")
    path = config.DATA_DIR / f"{_slug(scan_dict['domain'])}_{ts}.json"
    path.write_text(json.dumps(scan_dict, indent=2))
    return path


def list_scans() -> list[dict]:
    out = []
    for p in sorted(config.DATA_DIR.glob("*.json"), reverse=True):
        try:
            d = json.loads(p.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        out.append({
            "file": p.name,
            "domain": d.get("domain"),
            "counts": d.get("counts", {}),
            "finished": d.get("finished"),
        })
    return out


def load(filename: str) -> dict | None:
    # Prevent path traversal — only allow plain filenames in the data dir.
    if "/" in filename or ".." in filename:
        return None
    path = config.DATA_DIR / filename
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None
