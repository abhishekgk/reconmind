"""Screenshot live hosts with gowitness for fast visual triage.

Best-effort: needs gowitness + a Chrome/Chromium install. If either is missing or
the run fails, this returns {} and the rest of the scan is unaffected. Images are
written under ~/.reconmind/shots/<scan-slug>/ and served by the web app.
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

from .. import config

SHOTS_DIR = config.DATA_DIR.parent / "shots"


def _slug(domain: str) -> str:
    return re.sub(r"[^a-z0-9.-]", "_", domain.lower())


async def capture(domain: str, live: list[dict], deep: bool = False,
                  on_progress=None) -> dict[str, str]:
    """Screenshot each live host; return {host: relative_image_path}."""
    if not config.tool_path("gowitness") or not live:
        return {}
    cap = 200 if deep else 60
    urls = [l["url"] for l in live if l.get("url")][:cap]
    if not urls:
        return {}

    out_dir = SHOTS_DIR / _slug(domain)
    out_dir.mkdir(parents=True, exist_ok=True)
    targets = out_dir / "_targets.txt"
    targets.write_text("\n".join(urls))

    if on_progress:
        on_progress(f"screenshotting {len(urls)} live hosts")

    # gowitness v3 CLI. Fails cleanly if the binary is older or Chrome is absent.
    cmd = ["gowitness", "scan", "file", "-f", str(targets),
           "--screenshot-path", str(out_dir), "--write-none",
           "--timeout", "8", "--threads", "12"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
        await asyncio.wait_for(proc.communicate(), timeout=600 if deep else 300)
    except (asyncio.TimeoutError, OSError):
        if 'proc' in dir() and proc.returncode is None:
            proc.kill()

    # Map screenshot files back to hosts (gowitness embeds the host in the filename).
    images = [p for p in out_dir.iterdir()
              if p.suffix.lower() in (".jpeg", ".jpg", ".png") and not p.name.startswith("_")]
    shots: dict[str, str] = {}
    for l in live:
        host = l["host"]
        for img in images:
            if host in img.name:
                shots[host] = f"{_slug(domain)}/{img.name}"
                break
    return shots
