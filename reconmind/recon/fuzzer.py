"""Manual, Postman-style content fuzzing + high-signal exposure checks.

This module powers the UI's **Fuzzer** tab. Two capabilities:

  - ``run_fuzz`` drives a user-chosen content-discovery tool (ffuf / gobuster /
    dirb / wfuzz / feroxbuster) against a single URL, with full control over the
    wordlist, HTTP method, request headers, extensions and match/filter status
    codes.  Whatever tool runs, results are normalised into ONE row shape so the
    UI renders them identically.

  - ``quick_wins`` is a fast, *validated* probe for the highest-signal exposed
    files (.git, .env, swagger/openapi, actuator, backups, …).  Every hit is
    confirmed by a content fingerprint against a per-host soft-404 baseline, so
    there are no false positives.

Design notes (matching the rest of ReconMind):
  - external tools are optional — a missing tool is reported, never crashes;
  - subprocesses are run with an argv list (no shell), so user-supplied headers
    and URLs can't inject shell commands;
  - long runs are bounded by a deadline and a result cap so the UI stays snappy.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse, urlunparse

import httpx

from .. import config
from .runners import _env

UA = "ReconMind/0.1 (+educational content-discovery)"

# Cap on rows we keep/stream from a single fuzz run, so a huge wordlist against a
# permissive host can't flood the browser.
RESULT_CAP = 5000


# ---------------------------------------------------------------------------
# Wordlist discovery — feeds the UI dropdown
# ---------------------------------------------------------------------------

def _wordlist_dirs() -> list[Path]:
    """Directories we scan for wordlists, most-relevant first.

    Users can add their own via RECONMIND_WORDLIST_DIRS (os.pathsep-separated).
    Non-existent dirs are silently skipped.
    """
    dirs: list[Path] = []
    env = os.environ.get("RECONMIND_WORDLIST_DIRS", "")
    for p in env.split(os.pathsep):
        if p.strip():
            dirs.append(Path(p.strip()))
    wl_home = config.DATA_DIR.parent / "wordlists"   # where install.sh/.ps1 put them
    dirs += [
        config.DATA_DIR.parent,                                   # ~/.reconmind
        wl_home,                                                  # ~/.reconmind/wordlists (installer target)
        wl_home / "SecLists" / "Discovery" / "Web-Content",
        wl_home / "SecLists" / "Discovery" / "DNS",
        Path("/opt"),
        Path("/opt/SecLists/Discovery/Web-Content"),
        Path("/opt/SecLists/Discovery/DNS"),
        Path("/usr/share/seclists/Discovery/Web-Content"),
        Path("/usr/share/seclists/Discovery/DNS"),
        Path("/usr/share/wordlists"),
        Path.home() / "wordlists",
        Path.home() / "SecLists" / "Discovery" / "Web-Content",
        Path.home() / "SecLists" / "Discovery" / "DNS",
    ]
    # De-dup while preserving order.
    seen, out = set(), []
    for d in dirs:
        try:
            rp = d.resolve()
        except OSError:
            continue
        if rp in seen:
            continue
        seen.add(rp)
        out.append(d)
    return out


_LINECOUNT_CACHE: dict[str, tuple[float, int, int]] = {}  # path -> (mtime, size, lines)
_MAX_COUNT_BYTES = 60 * 1024 * 1024  # don't line-count files bigger than this


def _count_lines(path: Path, size: int, mtime: float) -> int:
    key = str(path)
    cached = _LINECOUNT_CACHE.get(key)
    if cached and cached[0] == mtime and cached[1] == size:
        return cached[2]
    if size > _MAX_COUNT_BYTES:
        lines = -1  # "large" — shown as size instead
    else:
        try:
            with open(path, "rb") as f:
                lines = sum(1 for _ in f)
        except OSError:
            lines = -1
    _LINECOUNT_CACHE[key] = (mtime, size, lines)
    return lines


def _human_size(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def discover_wordlists() -> list[dict]:
    """Return every readable ``*.txt`` wordlist under the known dirs.

    Each row: {path, name, dir, group, lines, size, human}. ``group`` is a short
    label the UI uses for <optgroup> headings.
    """
    out: list[dict] = []
    seen_paths: set[str] = set()
    for d in _wordlist_dirs():
        if not d.is_dir():
            continue
        group = _group_label(d)
        try:
            entries = sorted(d.iterdir(), key=lambda p: p.name.lower())
        except OSError:
            continue
        for p in entries:
            if not p.is_file():
                continue
            if p.suffix.lower() not in (".txt", ".list", ".words"):
                continue
            rp = str(p.resolve())
            if rp in seen_paths:
                continue
            try:
                stat = p.stat()
            except OSError:
                continue
            seen_paths.add(rp)
            lines = _count_lines(p, stat.st_size, stat.st_mtime)
            out.append({
                "path": str(p),
                "name": p.name,
                "dir": str(d),
                "group": group,
                "lines": lines,
                "size": stat.st_size,
                "human": _human_size(stat.st_size),
            })
    return out


def _group_label(d: Path) -> str:
    s = str(d)
    if s == str(config.DATA_DIR.parent):
        return "★ your ~/.reconmind"
    if s == str(config.DATA_DIR.parent / "wordlists"):
        return "★ downloaded (~/.reconmind/wordlists)"
    if "SecLists" in s or "seclists" in s:
        # e.g. ".../Discovery/Web-Content" -> "SecLists · Web-Content"
        tail = "/".join(d.parts[-1:])
        return f"SecLists · {tail}"
    return s


def _allowed_wordlist(path: str) -> bool:
    """Only allow wordlists that live under one of the configured dirs, so the
    endpoint can't be abused to feed a tool an arbitrary local file."""
    try:
        rp = Path(path).resolve()
    except OSError:
        return False
    if not rp.is_file():
        return False
    for d in _wordlist_dirs():
        try:
            if d.is_dir() and str(rp).startswith(str(d.resolve()) + os.sep):
                return True
        except OSError:
            continue
    return False


# ---------------------------------------------------------------------------
# Fuzzing-tool registry — feeds the UI dropdown
# ---------------------------------------------------------------------------

# name -> (purpose, install hint, capabilities). ``needs_fuzz`` = the tool wants a
# FUZZ keyword in the URL (ffuf/wfuzz); the others take a base URL and append.
FUZZ_TOOLS = {
    "ffuf": {
        "purpose": "Fast web fuzzer (JSON output, recursion, filters). Recommended.",
        "install": "go install github.com/ffuf/ffuf/v2@latest",
        "needs_fuzz": True, "method": True, "headers": True, "recursion": True,
    },
    "gobuster": {
        "purpose": "Directory/file brute-forcer (Go). Streams results live.",
        "install": "go install github.com/OJ/gobuster/v3@latest",
        "needs_fuzz": False, "method": True, "headers": True, "recursion": False,
    },
    "feroxbuster": {
        "purpose": "Recursive content discovery (Rust).",
        "install": "brew install feroxbuster",
        "needs_fuzz": False, "method": True, "headers": True, "recursion": True,
    },
    "wfuzz": {
        "purpose": "Classic web fuzzer with a FUZZ keyword.",
        "install": "pipx install wfuzz",
        "needs_fuzz": True, "method": True, "headers": True, "recursion": False,
    },
    "dirb": {
        "purpose": "Simple recursive directory scanner.",
        "install": "brew install dirb   # or apt install dirb",
        "needs_fuzz": False, "method": False, "headers": True, "recursion": True,
    },
}


def fuzz_tools_summary() -> dict:
    tools = []
    for name, meta in FUZZ_TOOLS.items():
        path = config.tool_path(name)
        tools.append({
            "name": name,
            "purpose": meta["purpose"],
            "install": meta["install"],
            "available": path is not None,
            "path": path,
            "needs_fuzz": meta["needs_fuzz"],
            "supports_method": meta["method"],
            "supports_headers": meta["headers"],
            "supports_recursion": meta["recursion"],
        })
    # Installed tools first, then alphabetical.
    tools.sort(key=lambda t: (not t["available"], t["name"]))
    return {"tools": tools, "default": _default_tool()}


def _default_tool() -> str:
    for name in ("ffuf", "gobuster", "feroxbuster", "wfuzz", "dirb"):
        if config.tool_path(name):
            return name
    return "ffuf"


# ---------------------------------------------------------------------------
# URL / option helpers
# ---------------------------------------------------------------------------

def _norm_exts(raw: str) -> list[str]:
    out = []
    for e in re.split(r"[,\s]+", (raw or "").strip()):
        if not e:
            continue
        out.append(e if e.startswith(".") else "." + e)
    return out


def _prep_url(url: str, tool: str) -> tuple[str, str]:
    """Return (fuzz_url, base_url).

    - fuzz_url always contains a FUZZ keyword (for ffuf/wfuzz). If the user didn't
      place one, we append '/FUZZ' to the path.
    - base_url has any FUZZ stripped (for gobuster/dirb/feroxbuster).
    """
    url = url.strip()
    if not re.match(r"^https?://", url, re.I):
        url = "http://" + url
    if "FUZZ" in url:
        fuzz_url = url
        base_url = url.replace("FUZZ", "").rstrip("/") or url
    else:
        p = urlparse(url)
        path = p.path or "/"
        if not path.endswith("/"):
            path += "/"
        fuzz_url = urlunparse(p._replace(path=path + "FUZZ"))
        base_url = url
    return fuzz_url, base_url


def _header_pairs(headers) -> list[tuple[str, str]]:
    """Accept either a dict or a list of {name,value} and return clean pairs."""
    pairs: list[tuple[str, str]] = []
    if isinstance(headers, dict):
        items = headers.items()
    elif isinstance(headers, list):
        items = [(h.get("name"), h.get("value")) for h in headers
                 if isinstance(h, dict)]
    else:
        items = []
    for name, value in items:
        name = (name or "").strip()
        value = (value or "").strip()
        if name:
            pairs.append((name, value))
    return pairs


def _row(path_or_url: str, base_url: str, status, size=None, words=None,
         lines=None, redirect="", source="") -> dict:
    """Normalise a hit into one shape. ``path_or_url`` may be a path or full URL."""
    if re.match(r"^https?://", path_or_url or "", re.I):
        url = path_or_url
        try:
            path = urlparse(url).path or "/"
        except ValueError:
            path = path_or_url
    else:
        path = path_or_url or "/"
        url = base_url.rstrip("/") + "/" + path.lstrip("/")
    return {
        "url": url, "path": path,
        "status": int(status) if status not in (None, "") else None,
        "size": int(size) if size not in (None, "") else None,
        "words": int(words) if words not in (None, "") else None,
        "lines": int(lines) if lines not in (None, "") else None,
        "redirect": redirect or "",
        "source": source,
    }


# ---------------------------------------------------------------------------
# Streaming subprocess helper (shared with the line-parsing tools)
# ---------------------------------------------------------------------------

async def _stream(cmd: list[str], deadline_s: float, on_line, input_text=None):
    """Run ``cmd`` and hand each stdout line to ``on_line`` until a deadline.

    Returns the number of lines seen. Kills the process on deadline so a runaway
    scan can't hang the server. Never raises if the tool is missing.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_text is not None else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            env=_env(),
        )
    except (FileNotFoundError, OSError):
        return 0
    if input_text is not None and proc.stdin:
        proc.stdin.write(input_text.encode())
        proc.stdin.close()
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline_s
    seen = 0
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
            seen += 1
            on_line(line.decode(errors="replace").rstrip("\n"))
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
                await proc.wait()
            except ProcessLookupError:
                pass
    return seen


# ---------------------------------------------------------------------------
# Per-tool runners
# ---------------------------------------------------------------------------

# Strip ANSI escapes (colors AND cursor controls like the "\x1b[2K" ffuf prints
# before each result line) so the result regex matches.
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
# ffuf's live stdout (non-silent) prints one line per hit:
#   admin   [Status: 200, Size: 1234, Words: 56, Lines: 7, Duration: 20ms]
_FFUF_RE = re.compile(
    r"^(?P<word>\S+)\s+\[Status:\s*(?P<st>\d+),\s*Size:\s*(?P<sz>\d+),"
    r"\s*Words:\s*(?P<wd>\d+),\s*Lines:\s*(?P<ln>\d+)")


async def _run_ffuf(opts, base_url, fuzz_url, wl, exts, headers,
                    on_result, on_progress) -> None:
    # Multi-FUZZ: a second wordlist bound to the FUZ2 keyword (needs FUZ2 in the
    # URL). With two keywords, stdout can't be parsed unambiguously, so we use
    # ffuf's JSON report (its 'url' field is fully substituted).
    wl2 = (opts.get("wordlist2") or "").strip()
    multi = bool(wl2) and _allowed_wordlist(wl2) and "FUZ2" in fuzz_url
    w_flags = ["-w", f"{wl}:FUZZ", "-w", f"{wl2}:FUZ2"] if multi else ["-w", wl]
    # No -s (single): ffuf prints each hit to stdout AS IT FINDS IT (live).
    cmd = ["ffuf", "-u", fuzz_url] + w_flags + ["-ac", "-t", str(opts["threads"]),
           "-maxtime", str(int(opts["deadline"])), "-mc",
           opts.get("match_codes") or "all"]
    if opts.get("filter_codes"):
        cmd += ["-fc", opts["filter_codes"]]
    if opts.get("rps"):
        cmd += ["-rate", str(opts["rps"])]
    if exts:
        cmd += ["-e", ",".join(exts)]
    if opts.get("method") and opts["method"].upper() != "GET":
        cmd += ["-X", opts["method"].upper()]
    if opts.get("data"):
        cmd += ["-d", opts["data"]]
    for name, value in headers:
        cmd += ["-H", f"{name}: {value}"]
    depth = int(opts.get("recursion") or 0)
    if depth > 0:
        cmd += ["-recursion", "-recursion-depth", str(depth)]

    if multi:
        on_progress(f"ffuf multi-FUZZ → {Path(wl).name} × {Path(wl2).name}")
        tmp = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False)
        tmp.close()
        cmd += ["-of", "json", "-o", tmp.name, "-s"]
        from .runners import _run
        await _run(cmd, timeout=int(opts["deadline"]) + 15)
        try:
            data = json.loads(Path(tmp.name).read_text())
        except (OSError, json.JSONDecodeError):
            data = {}
        finally:
            Path(tmp.name).unlink(missing_ok=True)
        for r in data.get("results", [])[:RESULT_CAP]:
            on_result(_row(r.get("url", ""), base_url, r.get("status"),
                           size=r.get("length"), words=r.get("words"),
                           lines=r.get("lines"), redirect=r.get("redirectlocation", ""),
                           source="ffuf"))
        return

    on_progress(f"ffuf → {fuzz_url}  (wordlist: {Path(wl).name})")
    count = [0]

    def on_line(line: str):
        m = _FFUF_RE.match(_ANSI_RE.sub("", line).strip())
        if not m or count[0] >= RESULT_CAP:
            return
        count[0] += 1
        # Reconstruct the URL by substituting the found word into the FUZZ slot.
        url = fuzz_url.replace("FUZZ", m.group("word"))
        on_result(_row(url, base_url, m.group("st"), size=m.group("sz"),
                       words=m.group("wd"), lines=m.group("ln"), source="ffuf"))

    await _stream(cmd, opts["deadline"] + 15, on_line)


# gobuster -q prints "<path-or-word>   (Status: 200) [Size: 1234] [--> /login]".
# The path may or may not have a leading slash depending on the gobuster version.
_GOBUSTER_RE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<st>\d+)\)(?:\s*\[Size:\s*(?P<sz>\d+)\])?"
    r"(?:\s*\[--> (?P<redir>[^\]]+)\])?")


async def _run_gobuster(opts, base_url, wl, exts, headers,
                        on_result, on_progress) -> None:
    cmd = ["gobuster", "dir", "-u", base_url, "-w", wl, "-q", "--no-progress",
           "-k", "-t", str(opts["threads"]), "-a", UA]
    if opts.get("method") and opts["method"].upper() != "GET":
        cmd += ["-m", opts["method"].upper()]
    if exts:
        cmd += ["-x", ",".join(e.lstrip(".") for e in exts)]
    for name, value in headers:
        cmd += ["-H", f"{name}: {value}"]
    on_progress(f"gobuster → {base_url}  (wordlist: {Path(wl).name})")
    count = [0]

    def on_line(line: str):
        m = _GOBUSTER_RE.match(line.strip())
        if not m or count[0] >= RESULT_CAP:
            return
        count[0] += 1
        on_result(_row(m.group("path"), base_url, m.group("st"),
                       size=m.group("sz"), redirect=m.group("redir") or "",
                       source="gobuster"))

    await _stream(cmd, opts["deadline"], on_line)


_FEROX_RE = re.compile(r"^(?P<st>\d{3})\s+\S+\s+\d+l\s+\d+w\s+(?P<sz>\d+)c\s+(?P<url>https?://\S+)")


async def _run_feroxbuster(opts, base_url, wl, exts, headers,
                           on_result, on_progress) -> None:
    cmd = ["feroxbuster", "-u", base_url, "-w", wl, "--silent", "-k",
           "-t", str(opts["threads"]), "-A"]
    depth = int(opts.get("recursion") or 0)
    cmd += ["-d", str(max(1, depth))] if depth else ["--no-recursion"]
    if exts:
        cmd += ["-x", ",".join(e.lstrip(".") for e in exts)]
    if opts.get("method") and opts["method"].upper() != "GET":
        cmd += ["-m", opts["method"].upper()]
    for name, value in headers:
        cmd += ["-H", f"{name}: {value}"]
    on_progress(f"feroxbuster → {base_url}")
    count = [0]

    def on_line(line: str):
        m = _FEROX_RE.search(line.strip())
        if not m or count[0] >= RESULT_CAP:
            return
        count[0] += 1
        on_result(_row(m.group("url"), base_url, m.group("st"),
                       size=m.group("sz"), source="feroxbuster"))

    await _stream(cmd, opts["deadline"], on_line)


async def _run_wfuzz(opts, base_url, fuzz_url, wl, headers,
                     on_result, on_progress) -> None:
    cmd = ["wfuzz", "-w", wl, "-u", fuzz_url, "--hc", "404", "-t", str(opts["threads"])]
    if opts.get("method") and opts["method"].upper() != "GET":
        cmd += ["-X", opts["method"].upper()]
    for name, value in headers:
        cmd += ["-H", f"{name}: {value}"]
    on_progress(f"wfuzz → {fuzz_url}")
    # wfuzz "word" lines look like: 000012:  C=200  120 L  ...  "admin"
    line_re = re.compile(r'C=(\d+).*?"([^"]+)"')
    count = [0]

    def on_line(line: str):
        m = line_re.search(line)
        if not m or count[0] >= RESULT_CAP:
            return
        count[0] += 1
        payload = m.group(2)
        on_result(_row(fuzz_url.replace("FUZZ", payload), base_url, m.group(1),
                       source="wfuzz"))

    await _stream(cmd, opts["deadline"], on_line)


async def _run_dirb(opts, base_url, wl, headers, on_result, on_progress) -> None:
    cmd = ["dirb", base_url, wl, "-S", "-r"]
    for name, value in headers:
        cmd += ["-H", f"{name}: {value}"]
    on_progress(f"dirb → {base_url}")
    line_re = re.compile(r"\+ (https?://\S+) \(CODE:(\d+)\|SIZE:(\d+)\)")
    count = [0]

    def on_line(line: str):
        m = line_re.search(line)
        if not m or count[0] >= RESULT_CAP:
            return
        count[0] += 1
        on_result(_row(m.group(1), base_url, m.group(2), size=m.group(3),
                       source="dirb"))

    await _stream(cmd, opts["deadline"], on_line)


# ---------------------------------------------------------------------------
# Public entry point for a single fuzz run
# ---------------------------------------------------------------------------

async def run_fuzz(opts: dict, on_result=None, on_progress=None) -> dict:
    """Run one content-discovery job. ``opts`` keys:

    url, tool, wordlist, method, headers, extensions, match_codes, filter_codes,
    threads, rps, recursion, data, deadline, quick_wins (bool).

    ``on_result(row)`` is called per hit (live); ``on_progress(msg)`` for phases.
    Returns {ok, tool, url, wordlist, count, rows, error}.
    """
    on_result = on_result or (lambda r: None)
    on_progress = on_progress or (lambda m: None)

    tool = (opts.get("tool") or _default_tool()).lower()
    if tool not in FUZZ_TOOLS:
        return {"ok": False, "error": f"unknown tool '{tool}'"}
    if not config.tool_path(tool):
        return {"ok": False, "error": f"{tool} is not installed — "
                f"{FUZZ_TOOLS[tool]['install']}"}

    wl = opts.get("wordlist") or ""
    if not _allowed_wordlist(wl):
        return {"ok": False, "error": "wordlist not found or not in an allowed "
                "directory (pick one from the dropdown, or drop it in ~/.reconmind)"}

    fuzz_url, base_url = _prep_url(opts.get("url", ""), tool)
    exts = _norm_exts(opts.get("extensions", ""))
    headers = _header_pairs(opts.get("headers"))
    opts.setdefault("threads", 40)
    opts.setdefault("deadline", 600)

    rows: list[dict] = []

    def collect(row: dict):
        if len(rows) < RESULT_CAP:
            rows.append(row)
            on_result(row)

    try:
        if tool == "ffuf":
            await _run_ffuf(opts, base_url, fuzz_url, wl, exts, headers,
                            collect, on_progress)
        elif tool == "gobuster":
            await _run_gobuster(opts, base_url, wl, exts, headers,
                                collect, on_progress)
        elif tool == "feroxbuster":
            await _run_feroxbuster(opts, base_url, wl, exts, headers,
                                   collect, on_progress)
        elif tool == "wfuzz":
            await _run_wfuzz(opts, base_url, fuzz_url, wl, headers,
                             collect, on_progress)
        elif tool == "dirb":
            await _run_dirb(opts, base_url, wl, headers, collect, on_progress)
    except Exception as e:  # never let a tool quirk kill the job
        return {"ok": False, "tool": tool, "url": base_url, "error": str(e),
                "rows": rows, "count": len(rows)}

    return {"ok": True, "tool": tool, "url": base_url, "wordlist": Path(wl).name,
            "count": len(rows), "rows": rows,
            "truncated": len(rows) >= RESULT_CAP}


# ---------------------------------------------------------------------------
# Quick-win exposure checks — validated, no false positives
# ---------------------------------------------------------------------------

# (path, type, severity, validator) — validator(body, ctype) -> bool.
def _has(*subs):
    def check(body: str, ctype: str) -> bool:
        low = body.lower()
        return any(s in low for s in subs)
    return check


def _json_with(*keys):
    def check(body: str, ctype: str) -> bool:
        b = body.lstrip()[:4000]
        if not (b.startswith("{") or b.startswith("[")):
            return False
        low = b.lower()
        return any(k in low for k in keys)
    return check


QUICK_WIN_CHECKS = [
    (".git/HEAD", "Exposed .git repo", "high",
     lambda b, c: b.strip().startswith("ref:") or re.match(r"^[0-9a-f]{40}", b.strip() or "")),
    (".git/config", "Exposed .git config", "high", _has("[core]", "repositoryformatversion")),
    (".env", "Exposed .env file", "high",
     lambda b, c: bool(re.search(r"^[A-Z0-9_]+\s*=", b, re.M)) and "html" not in c.lower()),
    (".DS_Store", ".DS_Store directory listing", "low",
     lambda b, c: b[:4] == "\x00\x00\x00\x01" or "Bud1" in b[:16]),
    (".svn/entries", "Exposed .svn metadata", "medium", _has("svn", "dir")),
    ("server-status", "Apache mod_status exposed", "medium", _has("apache server status")),
    ("actuator", "Spring Boot actuator index", "medium", _json_with("_links", "actuator")),
    ("actuator/env", "Spring actuator /env (secrets!)", "high", _json_with("propertysources", "systemenvironment")),
    ("actuator/health", "Spring actuator /health", "low", _json_with("status")),
    ("swagger.json", "Swagger/OpenAPI spec", "low", _json_with("swagger", "openapi")),
    ("openapi.json", "OpenAPI spec", "low", _json_with("openapi", "swagger")),
    ("api/swagger.json", "Swagger/OpenAPI spec", "low", _json_with("swagger", "openapi")),
    ("v2/api-docs", "Swagger v2 api-docs", "low", _json_with("swagger", "paths")),
    ("swagger-ui.html", "Swagger UI", "low", _has("swagger-ui", "swagger ui")),
    ("phpinfo.php", "phpinfo() exposed", "medium", _has("phpinfo()", "php version")),
    ("info.php", "phpinfo() exposed", "medium", _has("phpinfo()", "php version")),
    ("web.config", "IIS web.config exposed", "high", _has("<configuration", "<system.web")),
    (".aws/credentials", "AWS credentials file", "high", _has("aws_access_key_id")),
    ("config.json", "Exposed config.json", "medium", _json_with("password", "secret", "apikey", "api_key", "token")),
    ("wp-config.php.bak", "WordPress config backup", "high", _has("db_password", "define(")),
    ("backup.zip", "Backup archive exposed", "high", lambda b, c: b[:2] == "PK" or "zip" in c.lower()),
    ("backup.sql", "SQL backup exposed", "high", _has("insert into", "create table", "-- mysql dump")),
    ("db.sql", "SQL dump exposed", "high", _has("insert into", "create table")),
    (".well-known/security.txt", "security.txt present", "info", _has("contact:", "policy:")),
    ("robots.txt", "robots.txt (disallow hints)", "info", _has("disallow", "user-agent")),
]


async def quick_wins(bases: list[str], on_result=None, on_progress=None,
                     deadline: float = 120) -> list[dict]:
    """Probe each base URL for high-signal exposed files, validating every hit
    against a per-host soft-404 baseline. Returns a list of exposure rows."""
    on_result = on_result or (lambda r: None)
    on_progress = on_progress or (lambda m: None)
    found: list[dict] = []
    if not bases:
        return found
    on_progress(f"checking {len(bases)} host(s) for exposed files")
    loop = asyncio.get_running_loop()
    end = loop.time() + deadline
    sem = asyncio.Semaphore(30)

    async with httpx.AsyncClient(follow_redirects=False, verify=False, timeout=8,
                                 headers={"User-Agent": UA}) as client:
        for base in bases:
            if loop.time() > end:
                break
            base = base.rstrip("/")
            # Baseline: a path that should not exist. Records its status+size so a
            # catch-all 200 host doesn't produce false positives.
            baseline_status, baseline_len = None, None
            try:
                rnd = await client.get(base + "/reconmind_nope_" + os.urandom(4).hex())
                baseline_status, baseline_len = rnd.status_code, len(rnd.content)
            except Exception:
                pass

            async def probe(path, kind, sev, validator):
                async with sem:
                    url = base + "/" + path
                    try:
                        r = await client.get(url)
                    except Exception:
                        return
                    if r.status_code >= 400 or r.status_code in (301, 302):
                        return
                    body = r.text[:20000] if r.headers.get("content-type", "").startswith(
                        ("text", "application")) else ""
                    raw = body or r.content[:64].decode("latin-1", "replace")
                    # Soft-404 guard: same status AND near-identical size as baseline.
                    if (baseline_status == r.status_code and baseline_len is not None
                            and abs(len(r.content) - baseline_len) < 24):
                        return
                    try:
                        ok = validator(raw, r.headers.get("content-type", ""))
                    except Exception:
                        ok = False
                    if not ok:
                        return
                    row = {
                        "host": urlparse(base).hostname or base,
                        "url": url, "path": path, "type": kind, "severity": sev,
                        "status": r.status_code, "size": len(r.content),
                        "evidence": raw.strip().replace("\n", " ")[:120],
                    }
                    found.append(row)
                    on_result(row)

            await asyncio.gather(*(probe(p, k, s, v)
                                   for p, k, s, v in QUICK_WIN_CHECKS))
    sev_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    found.sort(key=lambda r: (sev_rank.get(r["severity"], 4), r["host"], r["path"]))
    return found


# ---------------------------------------------------------------------------
# Multi-host enumeration — directory brute across many hosts + param discovery
# ---------------------------------------------------------------------------

def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or url).lower()
    except ValueError:
        return url


async def param_discover(urls: list[str], on_result=None, on_progress=None,
                         deadline: float = 240) -> list[dict]:
    """Find hidden HTTP parameters with arjun. Returns rows
    {url, params:[...], method, source}. Degrades to [] if arjun is missing."""
    on_result = on_result or (lambda r: None)
    on_progress = on_progress or (lambda m: None)
    urls = [u for u in (urls or []) if u][:300]
    if not urls:
        return []
    if not config.tool_path("arjun"):
        on_progress("arjun not installed — skipping param discovery "
                    "(pip install arjun)")
        return []
    on_progress(f"arjun: hunting hidden params on {len(urls)} URL(s)")
    infile = tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False)
    infile.write("\n".join(urls))
    infile.close()
    out = tempfile.NamedTemporaryFile("r", suffix=".json", delete=False)
    out.close()
    from .runners import _run
    await _run(["arjun", "-i", infile.name, "-oJ", out.name, "-q", "-t", "10"],
               timeout=int(deadline))
    try:
        data = json.loads(Path(out.name).read_text())
    except (OSError, json.JSONDecodeError):
        data = {}
    finally:
        Path(infile.name).unlink(missing_ok=True)
        Path(out.name).unlink(missing_ok=True)

    rows: list[dict] = []

    def _emit(url, info):
        if isinstance(info, dict):
            params = info.get("params") or info.get("parameters") or []
            method = info.get("method") or "GET"
        elif isinstance(info, list):
            params, method = info, "GET"
        else:
            return
        if params:
            row = {"url": url, "params": params, "method": method, "source": "arjun"}
            rows.append(row)
            on_result(row)

    if isinstance(data, dict):
        for url, info in data.items():
            _emit(url, info)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("url"):
                _emit(item["url"], item)
    return rows


async def vhost_enum(target_url: str, base_domain: str, wordlist: str,
                     on_result=None, on_progress=None, deadline: float = 120,
                     threads: int = 40) -> list[dict]:
    """Find virtual hosts by fuzzing the Host header against one target with ffuf.

    Surfaces internal/staging sites (``FUZZ.<base_domain>``) served by the same
    box but not in DNS. ffuf's -ac auto-calibration filters the default page so a
    catch-all vhost doesn't produce noise. Returns rows {vhost, host, status,
    size, source}."""
    on_result = on_result or (lambda r: None)
    on_progress = on_progress or (lambda m: None)
    if not config.tool_path("ffuf"):
        on_progress("ffuf not installed — skipping vhost enum")
        return []
    if not _allowed_wordlist(wordlist):
        on_progress("vhost enum: pick a wordlist (a subdomain list works best)")
        return []
    t = target_url.strip()
    if not re.match(r"^https?://", t, re.I):
        t = "http://" + t
    host = _host_of(t)
    on_progress(f"vhost enum → {host}  (Host: FUZZ.{base_domain})")
    rows: list[dict] = []
    count = [0]

    def on_line(line: str):
        m = _FFUF_RE.match(_ANSI_RE.sub("", line).strip())
        if not m or count[0] >= 1000:
            return
        count[0] += 1
        row = {"vhost": f"{m.group('word')}.{base_domain}", "host": host,
               "status": int(m.group("st")), "size": int(m.group("sz")),
               "source": "vhost"}
        rows.append(row)
        on_result(row)

    cmd = ["ffuf", "-u", t, "-H", f"Host: FUZZ.{base_domain}", "-w", wordlist,
           "-ac", "-t", str(threads), "-maxtime", str(int(deadline)),
           "-mc", "all", "-fc", "404"]
    await _stream(cmd, deadline + 15, on_line)
    return rows


async def run_enumerate(opts: dict, on_result=None, on_progress=None) -> dict:
    """Run enumeration across many hosts at once.

    opts: hosts (list of URLs), capabilities {dir_brute, params}, wordlist, tool,
    extensions, filter_codes, threads, rps, per_host_deadline, host_concurrency,
    param_urls. ``on_result(bucket, row)`` fires per hit; ``on_progress(msg)``.
    Returns {content:[...], params:[...]}.
    """
    on_result = on_result or (lambda b, r: None)
    on_progress = on_progress or (lambda m: None)
    hosts = [h for h in (opts.get("hosts") or []) if h]
    caps = opts.get("capabilities") or {}
    out = {"content": [], "params": [], "vhosts": []}

    if caps.get("dir_brute") and hosts:
        sem = asyncio.Semaphore(int(opts.get("host_concurrency") or 3))
        done = [0]

        async def one(h):
            async with sem:
                on_progress(f"[{done[0]+1}/{len(hosts)}] dir-brute → {h}")
                host = _host_of(h)
                fo = {"url": h, "tool": opts.get("tool", "ffuf"),
                      "wordlist": opts.get("wordlist", ""),
                      "extensions": opts.get("extensions", ""),
                      "filter_codes": opts.get("filter_codes", "404"),
                      "threads": int(opts.get("threads") or 40),
                      "rps": int(opts.get("rps") or 0),
                      "deadline": int(opts.get("per_host_deadline") or 120),
                      "method": "GET"}
                await run_fuzz(fo, on_result=lambda r: (
                    out["content"].append(dict(r, host=host)),
                    on_result("content", dict(r, host=host))), on_progress=lambda m: None)
                done[0] += 1

        await asyncio.gather(*(one(h) for h in hosts))
        on_progress(f"dir-brute done — {len(out['content'])} hit(s) across {len(hosts)} host(s)")

    if caps.get("params"):
        out["params"] = await param_discover(
            opts.get("param_urls") or hosts,
            on_result=lambda r: on_result("params", r), on_progress=on_progress)

    if caps.get("vhosts") and hosts and opts.get("base_domain"):
        base = opts["base_domain"]
        wl = opts.get("vhost_wordlist") or opts.get("wordlist", "")
        sem = asyncio.Semaphore(int(opts.get("host_concurrency") or 3))

        async def vh(h):
            async with sem:
                rows = await vhost_enum(
                    h, base, wl, on_result=lambda r: on_result("vhost", r),
                    on_progress=on_progress,
                    deadline=int(opts.get("per_host_deadline") or 120),
                    threads=int(opts.get("threads") or 40))
                out["vhosts"].extend(rows)

        await asyncio.gather(*(vh(h) for h in hosts))

    return out
