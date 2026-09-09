"""Port scanning with naabu — open ports on resolved IPs without a paid Shodan plan.

Uses a TCP connect scan (-s c) so it needs no root. Off by default; runs in deep
mode. Results merge into each IP's port list on the IPs & Services tab.
"""
from __future__ import annotations

import asyncio
import json
import tempfile
from pathlib import Path

from .. import config

# Curated web-ish + common service ports for the fast path; deep uses top-100.
COMMON_PORTS = ("80,443,8080,8443,8000,8888,8081,8008,3000,5000,9000,9200,"
                "7001,2375,10250,161,21,22,23,25,3389,5432,3306,6379,27017,"
                "9090,9443,4443,8834,15672,5601")


async def scan_ports(ips: list[str], deep: bool = False,
                     on_progress=None) -> dict[str, list[int]]:
    """Return {ip: sorted[ports]} for the given IPs.

    naabu emits results as it finds them but keeps running to time out filtered
    ports, so we stream its stdout under a deadline and keep whatever we've got.
    """
    if not ips or not config.tool_path("naabu"):
        return {}
    cap = 1500 if deep else 400
    ips = ips[:cap]
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(ips))
        list_file = f.name

    cmd = ["naabu", "-silent", "-json", "-s", "c", "-list", list_file,
           "-rate", "1000", "-c", "50", "-timeout", "1200", "-retries", "1"]
    cmd += ["-top-ports", "100"] if deep else ["-p", COMMON_PORTS]
    deadline = (600 if deep else 240)

    if on_progress:
        on_progress(f"port-scanning {len(ips)} IPs with naabu")

    result: dict[str, list[int]] = {}
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        Path(list_file).unlink(missing_ok=True)
        return result

    loop = asyncio.get_running_loop()
    end = loop.time() + deadline
    try:
        while True:
            remaining = end - loop.time()
            if remaining <= 0:
                break
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not line:
                break
            try:
                row = json.loads(line.decode(errors="replace"))
            except json.JSONDecodeError:
                continue
            ip, port = row.get("ip") or row.get("host"), row.get("port")
            if ip and port:
                result.setdefault(ip, [])
                if port not in result[ip]:
                    result[ip].append(port)
    finally:
        if proc.returncode is None:
            try:
                proc.kill(); await proc.wait()
            except ProcessLookupError:
                pass
        Path(list_file).unlink(missing_ok=True)

    for ip in result:
        result[ip].sort()
    return result
