"""FastAPI backend + local web UI for ReconMind.

Endpoints:
  GET  /                      -> web UI
  GET  /api/tools             -> which external tools are installed
  GET  /api/llm/status        -> Ollama availability + models
  GET  /api/scans             -> saved scans
  GET  /api/scans/{file}      -> load a saved scan
  POST /api/scan              -> start a scan, returns {id}
  GET  /api/scan/{id}         -> current scan snapshot
  GET  /api/scan/{id}/events  -> Server-Sent Events stream of live progress
  POST /api/llm/explain       -> LLM explanation of a scan
  POST /api/llm/ask           -> ask the mentor a question
"""
from __future__ import annotations

import asyncio
import json
import uuid
from pathlib import Path

from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from .. import config, keys, llm, report, store, tools
from ..recon import fuzzer, nuclei
from ..recon.crawl import crawl as run_crawl
from ..recon.orchestrator import Scan, run_scan

app = FastAPI(title="ReconMind")

STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")

# Serve gowitness screenshots (best-effort; dir may be empty).
SHOTS = config.DATA_DIR.parent / "shots"
SHOTS.mkdir(parents=True, exist_ok=True)
app.mount("/shots", StaticFiles(directory=SHOTS), name="shots")


@app.middleware("http")
async def no_cache(request, call_next):
    """Don't let browsers cache the UI — avoids stale HTML/JS after updates."""
    response = await call_next(request)
    if request.url.path == "/" or request.url.path.startswith("/static"):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    return response

# In-memory registry of live scans (id -> Scan). Finished scans are also on disk.
SCANS: dict[str, Scan] = {}

# Hold strong references to background tasks. Without this, asyncio may garbage-
# collect a running task ("Task was destroyed but it is pending!") mid-scan.
_BG_TASKS: set[asyncio.Task] = set()


def _spawn(coro) -> asyncio.Task:
    task = asyncio.create_task(coro)
    _BG_TASKS.add(task)
    task.add_done_callback(_BG_TASKS.discard)
    return task


class LoadedScan:
    """Wraps a saved/imported scan dict so LLM + snapshot endpoints can use it
    exactly like a live Scan (they only ever call .to_dict())."""

    def __init__(self, data: dict):
        self._data = data

    def to_dict(self) -> dict:
        return self._data


class ScanRequest(BaseModel):
    domain: str
    active: bool = False
    deep: bool = False
    crawl: bool = False
    brute_limit: int = 2000


class ExplainRequest(BaseModel):
    scan_id: str
    prefer_local: bool = False


class AskRequest(BaseModel):
    question: str
    scan_id: str | None = None
    prefer_local: bool = False


class KeysRequest(BaseModel):
    keys: dict[str, dict[str, str]] = {}
    remove: list[str] = []


class CrawlRequest(BaseModel):
    scan_id: str
    deep: bool = False


class FuzzRequest(BaseModel):
    """A single Postman-style content-fuzzing job (the Fuzzer tab)."""
    url: str
    tool: str = "ffuf"
    wordlist: str = ""
    method: str = "GET"
    headers: list[dict] = []          # [{name, value}, ...]
    extensions: str = ""              # "php,txt,bak" or ".php,.txt"
    match_codes: str = ""             # ffuf -mc (blank = all)
    filter_codes: str = "404"         # ffuf -fc / others' status filter
    threads: int = 40
    rps: int = 0                      # 0 = unlimited
    recursion: int = 0                # depth (0 = off)
    data: str = ""                    # request body for POST/PUT/…
    deadline: int = 600
    quick_wins: bool = False          # also probe .git/.env/swagger/backups


class NucleiRequest(BaseModel):
    """A UI-driven nuclei scan (the Nuclei tab)."""
    targets: str = ""                 # one URL, or many (newline/space/comma)
    scan_id: str | None = None        # pull live hosts from this loaded scan…
    use_scan: bool = False            # …when true
    templates: list[str] = []         # module rel-paths e.g. ["http/cves"]
    template_path: str = ""           # a custom -t path (file or dir)
    tags: str = ""                    # comma/space separated
    severity: list[str] = []          # info/low/medium/high/critical/unknown
    rate_limit: int = 150
    concurrency: int = 25
    bulk_size: int = 25
    timeout: int = 10
    retries: int = 1
    deadline: int = 900


# In-memory crawl jobs (id -> {queue, status}). A crawl runs against an already
# loaded scan (live, imported, or from history) and fills its Endpoints tab.
CRAWL_JOBS: dict[str, dict] = {}

# In-memory fuzz jobs (id -> {queue, status, rows}). A fuzz job is standalone —
# it targets a single URL the user typed in the Fuzzer tab, not a saved scan.
FUZZ_JOBS: dict[str, dict] = {}

# In-memory nuclei jobs (id -> {queue, status, findings}).
NUCLEI_JOBS: dict[str, dict] = {}


def _apply_endpoints(scan, endpoints: list) -> None:
    """Attach crawl results to either a live Scan or a LoadedScan dict."""
    if isinstance(scan, LoadedScan):
        scan._data["endpoints"] = endpoints
        scan._data.setdefault("counts", {})["endpoints"] = len(endpoints)
    else:
        scan.endpoints = endpoints


def _norm_domain(raw: str) -> str:
    d = raw.strip().lower()
    d = d.replace("https://", "").replace("http://", "").strip("/")
    d = d.split("/")[0].split(":")[0]
    return d


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


@app.get("/api/tools")
async def api_tools():
    return tools.summary()


@app.get("/api/llm/status")
async def api_llm_status():
    return await llm.status()


@app.get("/api/llm/models")
async def api_llm_models():
    """All models the user can pick on this machine (Claude + local Ollama)."""
    return await llm.list_models()


class ModelRequest(BaseModel):
    model: str = "auto"


@app.post("/api/llm/model")
async def api_llm_set_model(req: ModelRequest):
    """Persist the user's chosen LLM model ('auto' = let the tool decide)."""
    llm.set_model(req.model)
    return {"ok": True, "current": llm.selected_model()}


@app.get("/api/keys/specs")
async def api_key_specs():
    """Which services can be configured, and which currently are (no secrets)."""
    return {"services": keys.specs_for_ui()}


@app.post("/api/keys")
async def api_save_keys(req: KeysRequest):
    """Save API keys and regenerate tool configs (subfinder provider-config, env)."""
    result = keys.save_keys(req.keys, remove=req.remove)
    return {"ok": True, **result, "services": keys.specs_for_ui()}


@app.get("/api/scans")
async def api_scans():
    return {"scans": store.list_scans()}


@app.get("/api/scans/{filename}")
async def api_load_scan(filename: str):
    data = store.load(filename)
    if not data:
        raise HTTPException(404, "scan not found")
    return data


def _register_scan(data: dict) -> str:
    """Put a scan dict into the in-memory registry and return its id."""
    scan_id = uuid.uuid4().hex[:12]
    SCANS[scan_id] = LoadedScan(data)
    return scan_id


@app.delete("/api/scans/{filename}")
async def api_delete_scan(filename: str):
    """Delete a saved scan file from ~/.reconmind/data."""
    if not store.delete(filename):
        raise HTTPException(404, "scan not found")
    return {"ok": True}


@app.post("/api/scans/{filename}/load")
async def api_history_load(filename: str):
    """Load a saved scan back into the dashboard (registers it for LLM use)."""
    data = store.load(filename)
    if not data:
        raise HTTPException(404, "scan not found")
    return {"id": _register_scan(data), "data": data}


@app.post("/api/import")
async def api_import(payload: dict = Body(...)):
    """Import a ReconMind scan JSON (e.g. an exported file) into the dashboard."""
    if not isinstance(payload, dict) or "domain" not in payload or "hosts" not in payload:
        raise HTTPException(400, "That doesn't look like a ReconMind scan JSON "
                                 "(missing 'domain'/'hosts').")
    return {"id": _register_scan(payload), "data": payload}


@app.post("/api/scan")
async def api_start_scan(req: ScanRequest):
    domain = _norm_domain(req.domain)
    if not domain or "." not in domain:
        raise HTTPException(400, "Please provide a valid domain, e.g. example.com")
    scan = Scan(domain=domain, active=req.active, deep=req.deep,
                crawl=req.crawl, brute_limit=req.brute_limit)
    scan_id = uuid.uuid4().hex[:12]
    SCANS[scan_id] = scan

    async def _run():
        try:
            await run_scan(scan)
        except Exception as e:  # keep the server alive on unexpected errors
            import traceback
            traceback.print_exc()
            scan.status = "error"
            scan.emit("error", message=str(e))
        finally:
            try:
                store.save(scan.to_dict())
            except Exception:
                pass

    _spawn(_run())
    return {"id": scan_id, "domain": domain}


@app.get("/api/scan/{scan_id}")
async def api_scan(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan.to_dict()


@app.get("/api/scan/{scan_id}/report")
async def api_scan_report(scan_id: str, fmt: str = "md"):
    """Render the loaded scan as a Markdown or self-contained HTML report."""
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found — load or run a scan first")
    data = scan.to_dict()
    if fmt == "html":
        return Response(report.to_html(data), media_type="text/html; charset=utf-8")
    return Response(report.to_markdown(data), media_type="text/markdown; charset=utf-8")


@app.get("/api/scan/{scan_id}/events")
async def api_scan_events(scan_id: str):
    scan = SCANS.get(scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")

    async def stream():
        # Replay nothing; push new events as they arrive until the scan ends.
        while True:
            try:
                event = await asyncio.wait_for(scan.events.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"  # comment frame to keep connection open
                if scan.status in ("done", "error"):
                    break
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event["kind"] in ("done", "error"):
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/api/crawl")
async def api_crawl(req: CrawlRequest):
    """Run the deep crawl phase against an already-loaded scan (its live hosts)."""
    scan = SCANS.get(req.scan_id)
    if not scan:
        raise HTTPException(404, "scan not found — load or run a scan first")
    data = scan.to_dict()
    domain = data.get("domain")
    live = [{"url": h["url"]} for h in data.get("hosts", [])
            if h.get("live") and h.get("url")]
    if not domain:
        raise HTTPException(400, "scan has no domain")
    if not live:
        raise HTTPException(400, "this scan has no live hosts to crawl")

    job_id = uuid.uuid4().hex[:12]
    queue: asyncio.Queue = asyncio.Queue()
    CRAWL_JOBS[job_id] = {"queue": queue, "status": "running"}

    async def _run():
        try:
            endpoints = await run_crawl(
                domain, live, deep=req.deep,
                on_progress=lambda m: queue.put_nowait({"kind": "phase", "phase": m}))
            _apply_endpoints(scan, endpoints)
            queue.put_nowait({"kind": "endpoints", "count": len(endpoints)})
            queue.put_nowait({"kind": "done", "count": len(endpoints)})
        except Exception as e:
            import traceback
            traceback.print_exc()
            queue.put_nowait({"kind": "error", "message": str(e)})
        finally:
            CRAWL_JOBS[job_id]["status"] = "done"
            try:
                store.save(scan.to_dict())
            except Exception:
                pass

    _spawn(_run())
    return {"job_id": job_id}


@app.get("/api/crawl/{job_id}/events")
async def api_crawl_events(job_id: str):
    job = CRAWL_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "crawl job not found")
    queue = job["queue"]

    async def stream():
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                if job["status"] == "done":
                    break
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event["kind"] in ("done", "error"):
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/wordlists")
async def api_wordlists():
    """Wordlists discovered on this machine, for the Fuzzer dropdown."""
    return {"wordlists": fuzzer.discover_wordlists()}


@app.get("/api/fuzz/tools")
async def api_fuzz_tools():
    """Which content-fuzzing tools are installed (ffuf/gobuster/…)."""
    return fuzzer.fuzz_tools_summary()


@app.post("/api/fuzz")
async def api_fuzz(req: FuzzRequest):
    """Start a single fuzz job against one URL; returns {job_id}. Results stream
    over /api/fuzz/{job_id}/events."""
    url = (req.url or "").strip()
    if not url:
        raise HTTPException(400, "Enter a URL to fuzz, e.g. https://example.com/FUZZ")

    job_id = uuid.uuid4().hex[:12]
    queue: asyncio.Queue = asyncio.Queue()
    FUZZ_JOBS[job_id] = {"queue": queue, "status": "running", "rows": []}

    opts = req.model_dump()

    async def _run():
        try:
            def on_result(row):
                FUZZ_JOBS[job_id]["rows"].append(row)
                queue.put_nowait({"kind": "result", "row": row})

            def on_progress(msg):
                queue.put_nowait({"kind": "phase", "phase": msg})

            result = await fuzzer.run_fuzz(opts, on_result=on_result,
                                           on_progress=on_progress)
            exposures = []
            if req.quick_wins:
                on_progress("probing for exposed files (.git/.env/swagger/backups)")
                base = fuzzer._prep_url(url, req.tool)[1]
                exposures = await fuzzer.quick_wins(
                    [base],
                    on_result=lambda r: queue.put_nowait({"kind": "exposure", "row": r}),
                    on_progress=on_progress)
            if not result.get("ok") and result.get("error"):
                queue.put_nowait({"kind": "error", "message": result["error"]})
            else:
                queue.put_nowait({"kind": "done", "count": result.get("count", 0),
                                  "exposures": len(exposures),
                                  "truncated": result.get("truncated", False)})
        except Exception as e:
            import traceback
            traceback.print_exc()
            queue.put_nowait({"kind": "error", "message": str(e)})
        finally:
            FUZZ_JOBS[job_id]["status"] = "done"

    _spawn(_run())
    return {"job_id": job_id}


@app.get("/api/fuzz/{job_id}/events")
async def api_fuzz_events(job_id: str):
    job = FUZZ_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "fuzz job not found")
    queue = job["queue"]

    async def stream():
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                if job["status"] == "done":
                    break
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event["kind"] in ("done", "error"):
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.get("/api/nuclei/meta")
async def api_nuclei_meta():
    """Nuclei availability, templates dir, module folders, severities, tags."""
    return nuclei.nuclei_meta()


@app.post("/api/nuclei")
async def api_nuclei(req: NucleiRequest):
    """Start a nuclei scan; returns {job_id}. Findings stream over
    /api/nuclei/{job_id}/events."""
    targets = nuclei._norm_targets(req.targets)
    if req.use_scan and req.scan_id and req.scan_id in SCANS:
        data = SCANS[req.scan_id].to_dict()
        targets += [h["url"] for h in data.get("hosts", [])
                    if h.get("live") and h.get("url")]
    targets = list(dict.fromkeys(targets))  # de-dup, preserve order
    if not targets:
        raise HTTPException(400, "No targets — enter a URL, paste a list, or tick "
                                 "'use loaded scan' with a scan that has live hosts.")

    job_id = uuid.uuid4().hex[:12]
    queue: asyncio.Queue = asyncio.Queue()
    NUCLEI_JOBS[job_id] = {"queue": queue, "status": "running", "findings": []}
    opts = req.model_dump()
    opts["targets"] = targets

    async def _run():
        try:
            def on_result(row):
                NUCLEI_JOBS[job_id]["findings"].append(row)
                queue.put_nowait({"kind": "finding", "row": row})

            def on_progress(msg):
                queue.put_nowait({"kind": "phase", "phase": msg})

            result = await nuclei.run_nuclei(opts, on_result=on_result,
                                             on_progress=on_progress)
            if not result.get("ok") and result.get("error"):
                queue.put_nowait({"kind": "error", "message": result["error"]})
            else:
                queue.put_nowait({"kind": "done", "count": result.get("count", 0),
                                  "truncated": result.get("truncated", False)})
        except Exception as e:
            import traceback
            traceback.print_exc()
            queue.put_nowait({"kind": "error", "message": str(e)})
        finally:
            NUCLEI_JOBS[job_id]["status"] = "done"

    _spawn(_run())
    return {"job_id": job_id, "targets": len(targets)}


@app.get("/api/nuclei/{job_id}/events")
async def api_nuclei_events(job_id: str):
    job = NUCLEI_JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "nuclei job not found")
    queue = job["queue"]

    async def stream():
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=30)
            except asyncio.TimeoutError:
                yield ": keep-alive\n\n"
                if job["status"] == "done":
                    break
                continue
            yield f"data: {json.dumps(event)}\n\n"
            if event["kind"] in ("done", "error"):
                break

    return StreamingResponse(stream(), media_type="text/event-stream")


@app.post("/api/llm/explain")
async def api_llm_explain(req: ExplainRequest):
    scan = SCANS.get(req.scan_id)
    if not scan:
        raise HTTPException(404, "scan not found")
    text = await llm.explain_scan(scan.to_dict(), prefer_local=req.prefer_local)
    return {"text": text}


@app.post("/api/llm/ask")
async def api_llm_ask(req: AskRequest):
    scan_dict = None
    if req.scan_id and req.scan_id in SCANS:
        scan_dict = SCANS[req.scan_id].to_dict()
    text = await llm.ask(req.question, scan_dict, prefer_local=req.prefer_local)
    return {"text": text}


def main():
    import uvicorn
    print(f"\n  ReconMind → http://{config.HOST}:{config.PORT}\n")
    uvicorn.run(app, host=config.HOST, port=config.PORT, log_level="warning")


if __name__ == "__main__":
    main()
