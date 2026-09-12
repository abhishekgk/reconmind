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


# ---------------------------------------------------------------------------
# UI-driven port scanning (the 🔌 Ports panel): naabu / nmap / masscan,
# preset or custom ports, streamed results with optional service/version.
# ---------------------------------------------------------------------------

import re  # noqa: E402

WEB_PORTS = ("80,443,8080,8443,8000,8888,8081,8008,3000,5000,9000,9200,7001,"
             "8834,15672,5601,9443,4443,8090,8181")


def _spec(preset: str, custom: str) -> str | None:
    """Concrete port spec for engines without --top-ports (masscan) or for
    web/full/custom presets. Returns None for top100/top1000 (engine-native)."""
    if preset == "custom":
        return (custom or "").replace(" ", "") or "80,443"
    if preset == "web":
        return WEB_PORTS
    if preset == "full":
        return "1-65535"
    return None


async def _read_lines(proc, deadline, on_line):
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
            on_line(line.decode(errors="replace").rstrip("\n"))
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass


async def run_port_scan(opts: dict, on_result=None, on_progress=None) -> dict:
    """Scan ports on chosen targets. opts: targets[list], engine, preset
    (top100/top1000/web/full/custom), ports(custom spec), rate, concurrency,
    service(bool, nmap -sV), deadline. Returns {ip: {ports:[...], services:[...]}}.
    ``on_result(row)`` per open port (live)."""
    on_result = on_result or (lambda r: None)
    on_progress = on_progress or (lambda m: None)
    engine = (opts.get("engine") or "naabu").lower()
    targets = [t for t in (opts.get("targets") or []) if t]
    if not targets:
        return {}
    if not config.tool_path(engine):
        on_progress(f"{engine} is not installed")
        return {}
    preset = opts.get("preset") or "top100"
    custom = opts.get("ports") or ""
    rate = int(opts.get("rate") or 1000)
    conc = int(opts.get("concurrency") or 50)
    deadline = float(opts.get("deadline") or 300)
    results: dict[str, dict] = {}

    def add(ip, port, host=None, service="", product=""):
        try:
            port = int(port)
        except (TypeError, ValueError):
            return
        r = results.setdefault(ip, {"ports": set(), "services": []})
        r["ports"].add(port)
        prod = product or service
        if prod and not any(s.get("port") == port for s in r["services"]):
            r["services"].append({"port": port, "product": prod})
        on_result({"ip": ip, "host": host or ip, "port": port,
                   "service": service, "product": product, "source": engine})

    on_progress(f"{engine}: scanning {len(targets)} target(s) "
                f"({'custom '+custom if preset=='custom' else preset} ports)")

    if engine == "naabu":
        await _naabu_scan(targets, preset, custom, rate, conc, deadline, add)
    elif engine == "nmap":
        await _nmap_scan(targets, preset, custom, bool(opts.get("service")), deadline, add, on_progress)
    elif engine == "masscan":
        await _masscan_scan(targets, preset, custom, rate, deadline, add, on_progress)

    return {ip: {"ports": sorted(v["ports"]), "services": v["services"]}
            for ip, v in results.items()}


async def _naabu_scan(targets, preset, custom, rate, conc, deadline, add):
    flags = (["-top-ports", "100"] if preset == "top100" else
             ["-top-ports", "1000"] if preset == "top1000" else
             ["-p", _spec(preset, custom) or "80,443"])
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(targets))
        list_file = f.name
    cmd = ["naabu", "-silent", "-json", "-s", "c", "-list", list_file,
           "-rate", str(rate), "-c", str(conc), "-timeout", "1200", "-retries", "1"] + flags

    def on_line(line):
        line = line.strip()
        if not line.startswith("{"):
            return
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            return
        ip = row.get("ip") or row.get("host")
        if ip and row.get("port"):
            add(ip, row["port"], host=row.get("host"))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        Path(list_file).unlink(missing_ok=True)
        return
    try:
        await _read_lines(proc, deadline, on_line)
    finally:
        Path(list_file).unlink(missing_ok=True)


# nmap greppable port field: "80/open/tcp//http//" or with -sV "…//nginx 1.18/"
_NMAP_HOST = re.compile(r"^Host:\s+(\S+)")
_NMAP_PORTS = re.compile(r"Ports:\s*(.+)")


async def _nmap_scan(targets, preset, custom, service, deadline, add, on_progress):
    pf = (["--top-ports", "100"] if preset == "top100" else
          ["--top-ports", "1000"] if preset == "top1000" else
          ["-p", _spec(preset, custom) or "80,443"])
    cmd = ["nmap", "-Pn", "--open", "-T4"] + (["-sV"] if service else []) + pf + ["-oG", "-"] + targets

    def on_line(line):
        mh = _NMAP_HOST.match(line)
        mp = _NMAP_PORTS.search(line)
        if not (mh and mp):
            return
        ip = mh.group(1)
        for entry in mp.group(1).split(","):
            parts = entry.strip().split("/")
            if len(parts) < 5 or parts[1] != "open":
                continue
            port, svc = parts[0], parts[4]
            ver = parts[6] if len(parts) > 6 else ""
            add(ip, port, service=svc, product=(f"{svc} {ver}".strip() if ver else svc))

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    except OSError:
        on_progress("nmap failed to start")
        return
    await _read_lines(proc, deadline, on_line)


async def _masscan_scan(targets, preset, custom, rate, deadline, add, on_progress):
    spec = _spec(preset, custom) or WEB_PORTS   # masscan has no --top-ports
    cmd = ["masscan"] + targets + ["-p", spec, "--rate", str(rate), "-oL", "-"]
    # masscan -oL lines: "open tcp 80 1.2.3.4 <ts>"
    saw = [False]

    def on_line(line):
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            saw[0] = True
            add(parts[3], parts[2])

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except OSError:
        on_progress("masscan failed to start")
        return
    err_task = asyncio.ensure_future(proc.stderr.read())
    await _read_lines(proc, deadline, on_line)
    if not saw[0]:
        try:
            err = (await asyncio.wait_for(err_task, timeout=1)).decode(errors="replace")
        except Exception:
            err = ""
        if "permission" in err.lower() or "root" in err.lower() or "sudo" in err.lower():
            on_progress("masscan needs root — run the server with sudo, or use naabu/nmap")
