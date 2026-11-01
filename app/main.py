import asyncio
import os
import secrets
import time
import uuid
from threading import Lock
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, File, Header, HTTPException, UploadFile, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .scope import LEVELS, parse_csv, public_host, target_url
from . import storage
from .jwtcheck import inspect_jwt
from .pipeline import katana, nuclei, gau, probe, in_host
from .review import ACTIVE_MODULES, review
from . import config


ZAP_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_URL = "http://127.0.0.1:8090"
app = FastAPI(title="ASFB Scanner API", version="0.1.0", docs_url="/docs")
assets = {}
accounts = {}
jobs = {}
scan_events = []
def log_event(job, event, **details):
    scan_events.append({"time": time.time(), "owner": job.get("owner"), "job_id": job.get("id"), "target": job.get("target"), "event": event, **details})
    if len(scan_events) > 10000: del scan_events[:1000]
queue = asyncio.Queue()
zap_lock = Lock()

sessions = set()
@app.middleware("http")
async def session_middleware(request: Request, call_next):
    old = request.headers.get("x-asfb-session") or request.cookies.get("asfb_session")
    sid = old if old in sessions else secrets.token_urlsafe(32)
    sessions.add(sid)
    request.state.sid = sid
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("origin")
        if origin and urlsplit(origin).netloc != request.headers.get("host"):
            from fastapi.responses import JSONResponse
            return JSONResponse({"detail": "Origin mismatch"}, status_code=403)
    response = await call_next(request)
    response.headers["X-ASFB-Session"] = sid
    response.headers["Cache-Control"] = "no-store"
    if sid != old:
        response.set_cookie("asfb_session", sid, httponly=True, secure=request.url.scheme == "https", samesite="strict", max_age=86400)
    return response

def authorize(request: Request):
    return request.state.sid

class Account(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    host: str = Field(min_length=4, max_length=253)
    cookie: str = Field(default="", max_length=8000)
    headers: dict[str, str] = Field(default_factory=dict)

class PipelineOptions(BaseModel):
    endpoint_limit: int = Field(default=config.ENDPOINT_LIMIT_DEFAULT, ge=1, le=config.ENDPOINT_LIMIT_MAX)
    httpx_limit: int = Field(default=config.HTTPX_LIMIT_DEFAULT, ge=1, le=config.HTTPX_LIMIT_MAX)
    katana_depth: int = Field(default=config.KATANA_DEPTH_DEFAULT, ge=1, le=config.KATANA_DEPTH_MAX)
    zap_endpoint_limit: int = Field(default=config.ZAP_ENDPOINT_LIMIT_DEFAULT, ge=1, le=config.ZAP_ENDPOINT_LIMIT_MAX)
    request_budget: int = Field(default=config.ZAP_REQUEST_BUDGET_DEFAULT, ge=1, le=config.ZAP_REQUEST_BUDGET_MAX)
    discovery_first: bool = True

class ScanRequest(BaseModel):
    asset_id: str
    policy_confirmed: bool = False
    user_agent: str = Field(default="ASFB-Research/0.1", max_length=300)
    max_requests: int = Field(default=1, ge=1, le=10)
    delay_seconds: float = Field(default=config.REQUEST_DELAY_DEFAULT, ge=config.REQUEST_DELAY_MIN, le=config.REQUEST_DELAY_MAX)
    options: PipelineOptions = Field(default_factory=PipelineOptions)
    active_confirmed: bool = False
    account_id: str | None = None
    modules: list[str] = Field(default_factory=lambda: ["zap-passive"])

@app.on_event("startup")
async def startup():
    if not ZAP_KEY:
        raise RuntimeError("Internal ZAP key missing")
    # Public browser sessions and secrets are not reloaded from disk.
    for job in jobs.values():
        if job["status"] in ("queued", "running"): job["status"] = "interrupted"
    app.state.worker = asyncio.create_task(worker())

@app.on_event("shutdown")
async def shutdown():
    app.state.worker.cancel()

@app.get("/")
async def index():
    return FileResponse("/app/app/index.html")

@app.get("/api/health")
async def health():
    return {"status": "ok", "zap": bool(ZAP_KEY)}

@app.post("/api/import", dependencies=[Depends(authorize)])
async def import_file(request: Request, file: UploadFile = File(...)):
    blob = await file.read(2_000_001)
    try:
        rows = parse_csv(blob)
    except (UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    prefix = str(uuid.uuid4())[:8]
    for r in rows:
        r["id"] = prefix + "-" + r["id"]
        r["owner"] = request.state.sid
        assets[r["id"]] = r
    # Keep public browser data ephemeral.
    return {"imported": len(rows), "web": sum(r["compatibility"] == "web" for r in rows)}

@app.get("/api/assets", dependencies=[Depends(authorize)])
def list_assets(request: Request, bounty_only: bool = False, severity: str = "all", compatible_only: bool = False, search: str = "", max_reports: int | None = None):
    rows = [a for a in assets.values() if a.get("owner") == request.state.sid]
    if bounty_only:
        rows = [r for r in rows if r["bounty"]]
    if severity != "all":
        if severity not in LEVELS:
            raise HTTPException(422, "Unsupported severity")
        rows = [r for r in rows if LEVELS.get(r["max_severity"], -1) >= LEVELS[severity]]
    if compatible_only:
        rows = [r for r in rows if r["compatibility"] == "web"]
    if search:
        rows = [r for r in rows if search.lower() in r["name"].lower() or search.lower() in r["description"].lower()]
    if max_reports is not None:
        rows = [r for r in rows if r["resolved_reports"] is not None and r["resolved_reports"] <= max_reports]
    return {"total": len(rows), "assets": rows}

@app.post("/api/accounts", dependencies=[Depends(authorize)])
def add_account(account: Account, request: Request):
    h = account.host.lower().rstrip(".")
    if urlsplit("https://" + h).hostname != h or any(c in h for c in "/:@*"):
        raise HTTPException(422, "Account must specify a single hostname")
    public_host(h, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
    if any(k.lower() in {"host", "cookie", "content-length", "authorization", "proxy-authorization"} for k in account.headers):
        raise HTTPException(422, "Use cookie field for cookies; protected headers cannot be overridden")
    identifier = uuid.uuid4().hex
    accounts[identifier] = account.model_dump() if hasattr(account, "model_dump") else account.dict()
    accounts[identifier]["host"] = h
    accounts[identifier]["owner"] = request.state.sid
    return {"id": identifier, "name": account.name, "host": h}

@app.get("/api/accounts", dependencies=[Depends(authorize)])
def list_accounts(request: Request):
    return [{"id": k, "name": v["name"], "host": v["host"]} for k, v in accounts.items() if v.get("owner") == request.state.sid]

@app.delete("/api/accounts/{account_id}", dependencies=[Depends(authorize)])
def remove_account(account_id: str, request: Request):
    if account_id in accounts and accounts[account_id].get("owner") != request.state.sid:
        raise HTTPException(404, "Account not found")
    accounts.pop(account_id, None)
    return {"removed": True}

@app.post("/api/scans", dependencies=[Depends(authorize)])
async def create_scan(spec: ScanRequest, request: Request):
    if not spec.modules or len(spec.modules) != len(set(spec.modules)) or not set(spec.modules).issubset(({"zap-passive","katana","nuclei","gau","httpx"} | ACTIVE_MODULES)):
        raise HTTPException(422, "Invalid or duplicate pipeline modules")
    if ACTIVE_MODULES.intersection(spec.modules):
        if not spec.active_confirmed:
            raise HTTPException(422, "Explicit permission for active single-target tests is required")
        if spec.account_id:
            raise HTTPException(422, "Active review stages do not use account profiles")
    if queue.qsize() >= 1000:
        raise HTTPException(429, "Scan queue full")
    if not spec.policy_confirmed:
        raise HTTPException(422, "You must explicitly confirm program automation policy")
    item = assets.get(spec.asset_id)
    if not item or item.get("owner") != request.state.sid:
        raise HTTPException(409, "Selected asset is no longer available in this session. Refresh assets or re-import the scope CSV.")
    try:
        url, host = target_url(item)
        public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if spec.account_id:
        profile = accounts.get(spec.account_id)
        if not profile or profile["host"] != host or profile.get("owner") != request.state.sid:
            raise HTTPException(422, "Account profile not found or host mismatch")
    for existing in jobs.values():
        if (existing.get("owner") == request.state.sid
                and existing.get("asset_id") == spec.asset_id
                and existing.get("status") in ("queued", "running")
                and existing.get("modules") == spec.modules):
            return {"id": existing["id"], "status": existing["status"], "reused": True}
    identifier = uuid.uuid4().hex
    jobs[identifier] = {"owner": request.state.sid, "id": identifier, "asset_id": spec.asset_id, "target": url,
                        "status": "queued", "alerts": [], "error": None, "created": time.time(),
                        "request_count": 0, "cancelled": False, "modules": spec.modules, "endpoints": [], "pipeline": {}, "reviews": [], "probes": [], "options": spec.options.model_dump(), "progress": 0, "stage": "queued"}
    log_event(jobs[identifier], "queued", modules=spec.modules)
    # Public scan results are ephemeral.
    await queue.put((identifier, spec))
    return {"id": identifier, "status": "queued"}

class BatchRequest(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=1000)
    policy_confirmed: bool = False
    user_agent: str = Field(default="ASFB-Research/0.1", max_length=300)
    delay_seconds: float = Field(default=config.REQUEST_DELAY_DEFAULT, ge=config.REQUEST_DELAY_MIN, le=config.REQUEST_DELAY_MAX)
    modules: list[str] = Field(default_factory=lambda: ["zap-passive"])
    options: PipelineOptions = Field(default_factory=PipelineOptions)
    active_confirmed: bool = False

@app.post("/api/scans/batch", dependencies=[Depends(authorize)])
async def batch_scans(payload: BatchRequest, request: Request):
    if ACTIVE_MODULES.intersection(payload.modules) and (len(payload.asset_ids) > config.ACTIVE_BATCH_LIMIT or not payload.active_confirmed):
        raise HTTPException(422, "Active review requires authorization and at most 100 targets")
    if not payload.policy_confirmed:
        raise HTTPException(422, "Program policy confirmation is required")
    if len(set(payload.asset_ids)) != len(payload.asset_ids) or queue.qsize() + len(payload.asset_ids) > 1000:
        raise HTTPException(422, "Duplicate assets or queue capacity exceeded")
    for asset_id in payload.asset_ids:
        item = assets.get(asset_id)
        if item is None or item.get("owner") != request.state.sid:
            raise HTTPException(409, "Selected scope is stale or belongs to another session. Refresh assets, re-import the CSV if necessary, and select targets again.")
        try:
            _, host = target_url(item)
            public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
        except ValueError as exc:
            raise HTTPException(422, str(exc))
    result = []
    for asset_id in payload.asset_ids:
        result.append(await create_scan(ScanRequest(asset_id=asset_id, policy_confirmed=True, user_agent=payload.user_agent,
                                                    delay_seconds=payload.delay_seconds, modules=payload.modules, options=payload.options, active_confirmed=payload.active_confirmed), request))
    return {"queued": sum(not item.get("reused", False) for item in result),
            "reused": sum(bool(item.get("reused")) for item in result), "scans": result}

class JWTInput(BaseModel):
    token: str = Field(min_length=10, max_length=16000)

@app.post("/api/tools/jwt/inspect", dependencies=[Depends(authorize)])
def jwt_inspect(payload: JWTInput):
    try:
        return inspect_jwt(payload.token)
    except ValueError as exc:
        raise HTTPException(422, str(exc))

@app.get("/api/scans", dependencies=[Depends(authorize)])
def scan_list(request: Request):
    return [v for v in jobs.values() if v.get("owner") == request.state.sid][-100:]

@app.delete("/api/findings", dependencies=[Depends(authorize)])
def clear_findings(request: Request):
    cleared = 0
    for job in jobs.values():
        if job.get("owner") == request.state.sid:
            cleared += len(job.get("alerts") or [])
            job["alerts"] = []
    return {"cleared": cleared}

@app.get("/api/logs", dependencies=[Depends(authorize)])
def scan_logs(request: Request):
    return {"events": [{k: v for k,v in row.items() if k != "owner"} for row in scan_events if row["owner"] == request.state.sid][-2000:]}

@app.get("/api/report", dependencies=[Depends(authorize)])
def full_report(request: Request):
    owned = [j for j in jobs.values() if j.get("owner") == request.state.sid]
    return {"version": 1, "generated": time.time(),
            "jobs": owned, "total_targets": len(owned),
            "total_alerts": sum(len(j.get("alerts") or []) for j in owned),
            "endpoints": sorted(set(url for j in owned for url in (j.get("endpoints") or [])))}

@app.get("/api/scans/{scan_id}", dependencies=[Depends(authorize)])
def scan_status(scan_id: str, request: Request):
    if scan_id not in jobs or jobs[scan_id].get("owner") != request.state.sid:
        raise HTTPException(404, "Scan not found")
    return jobs[scan_id]

@app.post("/api/scans/{scan_id}/cancel", dependencies=[Depends(authorize)])
def cancel_scan(scan_id: str, request: Request):
    if scan_id not in jobs or jobs[scan_id].get("owner") != request.state.sid:
        raise HTTPException(404, "Scan not found")
    jobs[scan_id]["cancelled"] = True
    # Ephemeral data
    return {"cancel_requested": True}

async def zap_call(client, component, action, params=None):
    response = await client.get(f"{ZAP_URL}/JSON/{component}/{action}/", params={**(params or {}), "apikey": ZAP_KEY})
    response.raise_for_status()
    data = response.json()
    if "code" in data:
        raise RuntimeError(str(data.get("message") or data["code"]))
    return data

async def worker():
    while True:
        identifier, spec = await queue.get()
        job = jobs[identifier]
        try:
            if job["cancelled"]:
                job["status"] = "cancelled"
                continue
            job["status"] = "running"
            log_event(job, "started")
            url, host = target_url(assets[spec.asset_id])
            endpoints = [url]
            endpoint_sources = {url: ["scope"]}
            # Modules execute in the user-selected order, sequentially, with bounded output.
            for position, module in enumerate(spec.modules):
                if job["cancelled"]:
                    break
                public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
                job["stage"] = module
                started_at = time.monotonic()
                log_event(job, "stage_started", module=module, position=position + 1, total=len(spec.modules), endpoints=len(endpoints))
                job["progress"] = round(position * 100 / len(spec.modules))
                job["pipeline"][module] = "running"
                if module == "gau":
                    result = await gau(url, host)
                    for discovered in result["endpoints"]:
                        endpoint_sources.setdefault(discovered, []).append("gau")
                    endpoints = list(dict.fromkeys(endpoints + result["endpoints"]))[:spec.options.endpoint_limit]
                    job["endpoints"] = endpoints[1:]
                elif module == "katana":
                    result = await katana(url, host, spec.user_agent, spec.options.katana_depth)
                    for discovered in result["endpoints"]:
                        endpoint_sources.setdefault(discovered, []).append("katana")
                    endpoints = list(dict.fromkeys(endpoints + result["endpoints"]))[:spec.options.endpoint_limit]
                    job["endpoints"] = endpoints[1:]
                elif module == "httpx":
                    result = await probe(endpoints, host, spec.user_agent, spec.options.httpx_limit)
                    job["probes"] = result["probes"]
                elif module == "zap-passive":
                    # Only the primary target is fetched through ZAP. Additional
                    # discovered URLs are not automatically crawled by ZAP.
                    headers = {"User-Agent": spec.user_agent}
                    profile = accounts.get(spec.account_id) if spec.account_id else None
                    if profile:
                        headers.update(profile["headers"])
                        if profile["cookie"]:
                            headers["Cookie"] = profile["cookie"]
                    async with httpx.AsyncClient(timeout=15, follow_redirects=False,
                                                 trust_env=False, proxy=ZAP_URL, verify=False) as client:
                        for candidate in endpoints[:spec.options.zap_endpoint_limit]:
                            if job["cancelled"] or job["request_count"] >= spec.options.request_budget:
                                break
                            if not in_host(candidate, host):
                                continue
                            for i in range(spec.max_requests):
                                if job["cancelled"] or job["request_count"] >= spec.options.request_budget:
                                    break
                                public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
                                try:
                                    response = await client.get(candidate, headers=headers)
                                    job["request_count"] += 1
                                    job["last_status"] = response.status_code
                                except httpx.HTTPError as exc:
                                    job["error"] = "Target fetch failed: " + exc.__class__.__name__
                                    break
                                await asyncio.sleep(spec.delay_seconds)
                    pending_records = 0
                    async with httpx.AsyncClient(timeout=20, trust_env=False) as z:
                        for _ in range(config.ZAP_PASSIVE_POLL_LIMIT):
                            queue_info = await zap_call(z, "pscan", "view/recordsToScan", {})
                            pending_records = int(queue_info.get("recordsToScan", 0))
                            if pending_records <= 0:
                                break
                            await asyncio.sleep(config.ZAP_PASSIVE_POLL_SECONDS)
                        info = await zap_call(z, "core", "view/alerts",
                                              {"baseurl": url, "start": "0", "count": "100"})
                    job["alerts"].extend([{
                        "source": "zap", "name": a.get("name"), "risk": a.get("risk"),
                        "confidence": a.get("confidence"), "url": a.get("url"),
                        "description": (a.get("description") or "")[:1000]
                    } for a in info.get("alerts", [])
                      if urlsplit(a.get("url") or "").hostname == host])
                    result = {
                        "status": "completed" if pending_records <= 0 else "partial",
                        "reason": (f"ZAP passive scan still has {pending_records} pending records"
                                   if pending_records else ""),
                        "pending_records": pending_records,
                    }
                elif module == "nuclei":
                    result = await nuclei(url, host, spec.user_agent)
                    job["alerts"].extend(result["alerts"])
                elif module in ACTIVE_MODULES:
                    result = await review(module, url, host)
                    job["reviews"].append(result)
                    if module == "arjun":
                        job["parameters"] = [
                            item for item in result.get("parameters", [])
                            if in_host(item.get("url", ""), host)
                        ]
                job["pipeline"][module] = result["status"]
                summary = str(result.get("output") or "")
                if not summary:
                    summary = ("Discovered " + str(len(result.get("endpoints", []))) +
                               " endpoints; " + str(len(result.get("probes", []))) +
                               " probes; " + str(len(result.get("alerts", []))) + " module alerts")
                if module == "zap-passive":
                    summary = ("ZAP-proxied requests: " + str(job["request_count"]) +
                               "; alerts: " + str(len(job["alerts"])) +
                               "; queued passive records: " + str(result["pending_records"]))
                summary = summary[:1200]
                elapsed_ms = round((time.monotonic() - started_at) * 1000)
                job.setdefault("stage_details", {})[module] = {"status": result["status"], "elapsed_ms": elapsed_ms, "reason": str(result.get("reason", ""))[:250], "summary": summary}
                log_event(job, "stage_finished", module=module, status=result["status"], elapsed_ms=elapsed_ms, reason=str(result.get("reason", ""))[:250], summary=summary[:350], alerts=len(job.get("alerts", [])), endpoints=len(job.get("endpoints", [])))
                job["endpoint_sources"] = {key: sorted(set(value)) for key, value in endpoint_sources.items() if key in endpoints}
                job["progress"] = round((position + 1) * 100 / len(spec.modules))
            stage_statuses = list(job["pipeline"].values())
            degraded = any(status in ("failed", "timeout", "unavailable", "partial") for status in stage_statuses)
            job["status"] = "cancelled" if job["cancelled"] else ("partial" if degraded else "completed")
            job["stage"] = job["status"]
            log_event(job, "finished", status=job["status"])
            if job["status"] in ("completed", "partial"):
                job["progress"] = 100
        except Exception as exc:
            job["status"] = "failed"
            job["stage"] = "failed"
            job["error"] = exc.__class__.__name__
            log_event(job, "failed", error_type=exc.__class__.__name__)
        finally:
            queue.task_done()
