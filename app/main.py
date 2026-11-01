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
from .pipeline import katana, nuclei


ZAP_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_URL = "http://127.0.0.1:8090"
app = FastAPI(title="ASFB Scanner API", version="0.1.0", docs_url="/docs")
assets = {}
accounts = {}
jobs = {}
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

class ScanRequest(BaseModel):
    asset_id: str
    policy_confirmed: bool = False
    user_agent: str = Field(default="ASFB-Research/0.1", max_length=300)
    max_requests: int = Field(default=1, ge=1, le=10)
    delay_seconds: float = Field(default=1.5, ge=1, le=30)
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
    if not spec.modules or not set(spec.modules).issubset({"zap-passive","katana","nuclei"}):
        raise HTTPException(422, "Only passive scanning is currently supported")
    if queue.qsize() >= 100:
        raise HTTPException(429, "Scan queue full")
    if not spec.policy_confirmed:
        raise HTTPException(422, "You must explicitly confirm program automation policy")
    item = assets.get(spec.asset_id)
    if not item or item.get("owner") != request.state.sid:
        raise HTTPException(404, "Asset not found")
    try:
        url, host = target_url(item)
        public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    if spec.account_id:
        profile = accounts.get(spec.account_id)
        if not profile or profile["host"] != host or profile.get("owner") != request.state.sid:
            raise HTTPException(422, "Account profile not found or host mismatch")
    identifier = uuid.uuid4().hex
    jobs[identifier] = {"owner": request.state.sid, "id": identifier, "asset_id": spec.asset_id, "target": url,
                        "status": "queued", "alerts": [], "error": None, "created": time.time(),
                        "request_count": 0, "cancelled": False, "modules": spec.modules, "endpoints": [], "pipeline": {}}
    # Public scan results are ephemeral.
    await queue.put((identifier, spec))
    return {"id": identifier, "status": "queued"}

class BatchRequest(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=40)
    policy_confirmed: bool = False
    user_agent: str = Field(default="ASFB-Research/0.1", max_length=300)
    delay_seconds: float = Field(default=1.5, ge=1, le=30)
    modules: list[str] = Field(default_factory=lambda: ["zap-passive"])

@app.post("/api/scans/batch", dependencies=[Depends(authorize)])
async def batch_scans(payload: BatchRequest, request: Request):
    if not payload.policy_confirmed:
        raise HTTPException(422, "Program policy confirmation is required")
    if len(set(payload.asset_ids)) != len(payload.asset_ids) or queue.qsize() + len(payload.asset_ids) > 100:
        raise HTTPException(422, "Duplicate assets or queue capacity exceeded")
    for asset_id in payload.asset_ids:
        item = assets.get(asset_id)
        if item is None or item.get("owner") != request.state.sid:
            raise HTTPException(404, f"Asset not found: {asset_id}")
        try:
            _, host = target_url(item)
            public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
        except ValueError as exc:
            raise HTTPException(422, str(exc))
    result = []
    for asset_id in payload.asset_ids:
        result.append(await create_scan(ScanRequest(asset_id=asset_id, policy_confirmed=True, user_agent=payload.user_agent,
                                                    delay_seconds=payload.delay_seconds, modules=payload.modules), request))
    return {"queued": len(result), "scans": result}

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
            url, host = target_url(assets[spec.asset_id])
            profile = accounts.get(spec.account_id) if spec.account_id else None
            headers = {"User-Agent": spec.user_agent}
            if profile:
                headers.update(profile["headers"])
                if profile["cookie"]:
                    headers["Cookie"] = profile["cookie"]
            # Every job uses ZAP's HTTP proxy to populate passive alerts. No active scanning.
            async with httpx.AsyncClient(timeout=15, follow_redirects=False, trust_env=False,
                                         proxy=ZAP_URL, verify=False) as client:
                for i in range(spec.max_requests if "zap-passive" in spec.modules else 0):
                    if job["cancelled"]:
                        break
                    # Re-check every request, including DNS answers. Egress firewall is still recommended.
                    public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
                    try:
                        response = await client.get(url, headers=headers)
                        job["request_count"] += 1
                        job["last_status"] = response.status_code
                    except httpx.HTTPError as exc:
                        job["error"] = f"Target fetch failed: {exc.__class__.__name__}"
                        break
                    if i + 1 < spec.max_requests:
                        await asyncio.sleep(spec.delay_seconds)
            if job["cancelled"]:
                job["status"] = "cancelled"
                continue
            if "zap-passive" in spec.modules:
              async with httpx.AsyncClient(timeout=20, trust_env=False) as z:
                  await asyncio.sleep(2)
                  # Filter results strictly to the requested URL/host, because ZAP session is shared.
                  info = await zap_call(z, "core", "view/alerts", {"baseurl": url, "start": "0", "count": "100"})
                  alerts = info.get("alerts", [])
                  job["alerts"] = [{
                      "name": a.get("name"), "risk": a.get("risk"),
                      "confidence": a.get("confidence"), "url": a.get("url"),
                      "description": (a.get("description") or "")[:1000]
                  } for a in alerts if urlsplit(a.get("url") or "").hostname == host]
            if "katana" in spec.modules and not job["cancelled"]:
                result = await katana(url, host, spec.user_agent)
                job["endpoints"] = result["endpoints"]
                job["pipeline"]["katana"] = result["status"]
            if "nuclei" in spec.modules and not job["cancelled"]:
                result = await nuclei(url, host, spec.user_agent)
                job["alerts"].extend(result["alerts"])
                job["pipeline"]["nuclei"] = result["status"]
            job["status"] = "completed"
        except Exception as exc:
            job["status"] = "failed"
            job["error"] = str(exc)[:250]
        finally:
            # Never retain authenticated headers in logs or job history.
            # Ephemeral data
            queue.task_done()
