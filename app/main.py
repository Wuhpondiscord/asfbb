import asyncio
import os
import secrets
import time
import uuid
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import FastAPI, File, Header, HTTPException, UploadFile, Depends, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .scope import LEVELS, parse_csv, public_host, target_url
from . import storage
from .jwtcheck import inspect_jwt
from .pipeline import katana, nuclei, gau, probe, in_host
from .review import ACTIVE_MODULES, review, choose_arjun_target, choose_dalfox_target, choose_sqlmap_target
from . import config
from .concurrency import dispatch, module_slot
from .module_inputs import ModuleInputs
from .target_import import parse_targets, target_key, MAX_TARGETS
from .planning import plan as build_pipeline_plan, page_target, assessed_urls
from .coverage import profile as coverage_settings
from .web_modules import MODULES as WEB_MODULES, run_web_module

from . import nuclei_catalog

ACTIVE_MODULES = ACTIVE_MODULES | WEB_MODULES


ZAP_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_URL = "http://127.0.0.1:8090"
app = FastAPI(title="ASFB Scanner API", version="0.1.0", docs_url="/docs")
assets = {}
accounts = {}
jobs = {}
scan_events = []
def log_event(job, event, **details):
    now = time.time()
    status = details.get("status", "")
    level = ("error" if event in ("failed", "stage_exception") or status == "failed"
             else "warning" if status in ("timeout", "unavailable", "partial", "skipped") or
             event in ("cancelled", "interrupted", "cancellation_requested") else "info")
    if event == "started":
        job["started"] = now
    if event in ("finished", "failed", "cancelled", "interrupted"):
        job["finished"] = now
        if job.get("started"):
            details.setdefault("elapsed_ms", round((now - job["started"]) * 1000))
    scan_events.append({"event_id": uuid.uuid4().hex, "time": now, "level": level,
                        "owner": job.get("owner"), "job_id": job.get("id"),
                        "target": job.get("target"), "event": event, **details})
    if len(scan_events) > 10000: del scan_events[:1000]
queue = asyncio.Queue()

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

class NucleiSettings(BaseModel):
    default_ids: list[str] = Field(
        default_factory=lambda: list(config.NUCLEI_DEFAULT_IDS), max_length=20)
    community_paths: list[str] = Field(default_factory=list, max_length=config.NUCLEI_COMMUNITY_MAX)
    custom_templates: list[str] = Field(default_factory=list, max_length=config.NUCLEI_CUSTOM_MAX)

class PipelineOptions(BaseModel):
    inputs: ModuleInputs = Field(default_factory=ModuleInputs)
    nuclei: NucleiSettings = Field(default_factory=NucleiSettings)
    gau_mode: Literal["balanced", "expanded"] = config.GAU_MODE_DEFAULT
    endpoint_limit: int = Field(default=config.ENDPOINT_LIMIT_DEFAULT, ge=1, le=config.ENDPOINT_LIMIT_MAX)
    httpx_limit: int = Field(default=config.HTTPX_LIMIT_DEFAULT, ge=1, le=config.HTTPX_LIMIT_MAX)
    katana_depth: int = Field(default=config.KATANA_DEPTH_DEFAULT, ge=1, le=config.KATANA_DEPTH_MAX)
    zap_endpoint_limit: int = Field(default=config.ZAP_ENDPOINT_LIMIT_DEFAULT, ge=1, le=config.ZAP_ENDPOINT_LIMIT_MAX)
    request_budget: int = Field(default=config.ZAP_REQUEST_BUDGET_DEFAULT, ge=1, le=config.ZAP_REQUEST_BUDGET_MAX)
    zap_wait_seconds: int = Field(default=config.ZAP_PASSIVE_WAIT_SECONDS_DEFAULT, ge=15, le=config.ZAP_PASSIVE_WAIT_SECONDS_MAX)
    discovery_first: bool = True
    order_mode: Literal["manual", "guided"] = "manual"
    reuse_discovery: bool = False
    coverage_profile: Literal["current", "quick", "balanced", "thorough"] = "current"
    parallel_jobs: int = Field(default=config.PARALLEL_JOBS_DEFAULT, ge=1, le=config.PARALLEL_JOBS_MAX)

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
    await asyncio.gather(app.state.worker, return_exceptions=True)

@app.get("/preferences.js")
async def preferences_script():
    return FileResponse("/app/app/preferences.js", media_type="text/javascript",
                        headers={"Cache-Control": "no-cache"})


@app.get("/")
async def index():
    return FileResponse("/app/app/index.html")

class PipelinePlanRequest(BaseModel):
    modules: list[str] = Field(min_length=1, max_length=30)
    order_mode: Literal["manual", "guided"] = "manual"
    reuse_discovery: bool = False
    coverage_profile: Literal["current", "quick", "balanced", "thorough"] = "current"


@app.post("/api/pipeline/plan", dependencies=[Depends(authorize)])
async def pipeline_plan(payload: PipelinePlanRequest):
    try:
        result = build_pipeline_plan(payload.modules, payload.order_mode, payload.reuse_discovery)
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    return {**result, "coverage_profile": payload.coverage_profile,
            "budgets": coverage_settings(payload.coverage_profile)}


@app.get("/api/nuclei/defaults", dependencies=[Depends(authorize)])
async def nuclei_template_defaults():
    return {
        "default_ids": list(config.NUCLEI_DEFAULT_IDS),
        "templates": [{"id": name, "optional": name in config.NUCLEI_OPTIONAL_TEMPLATE_PATHS}
                      for name in nuclei_catalog.builtins()],
        "max_community": config.NUCLEI_COMMUNITY_MAX,
        "max_custom": config.NUCLEI_CUSTOM_MAX,
        "max_custom_bytes": config.NUCLEI_CUSTOM_MAX_BYTES,
    }


class NucleiTemplateCheckRequest(BaseModel):
    paths: list[str] = Field(default_factory=list, max_length=config.NUCLEI_COMMUNITY_MAX)


@app.post("/api/nuclei/check", dependencies=[Depends(authorize)])
async def check_nuclei_community_templates(payload: NucleiTemplateCheckRequest):
    if not payload.paths or len(payload.paths) != len(set(payload.paths)):
        raise HTTPException(422, "Select distinct community template paths")
    try:
        nuclei_catalog.validate_selection([], payload.paths, [])
    except ValueError as exc:
        raise HTTPException(422, str(exc))
    compatible, rejected = [], []
    for path in payload.paths:
        try:
            await nuclei_catalog.community_files([path])
            compatible.append(path)
        except (ValueError, httpx.HTTPError) as exc:
            rejected.append({"path": path, "reason": str(exc)[:180]})
    return {"compatible": compatible, "rejected": rejected}


@app.post("/api/nuclei/validate", dependencies=[Depends(authorize)])
async def validate_nuclei_configuration(selection: NucleiSettings):
    """Preflight only: no scan traffic is sent to selected target hosts."""
    try:
        nuclei_catalog.validate_selection(
            selection.default_ids, selection.community_paths, selection.custom_templates)
        community = await nuclei_catalog.community_files(selection.community_paths)
        bundles = [(label, nuclei_catalog.bundled_content(label)) for label in selection.default_ids]
        sources = bundles + list(community.items()) + [
            (f"custom-{i+1}", content) for i, content in enumerate(selection.custom_templates)]
        if not sources:
            raise ValueError("Choose at least one Nuclei template")
        breakdown = [{"name": label, "estimated_requests_per_target":
                      nuclei_catalog.estimate_requests(content)} for label, content in sources]
        total = sum(x["estimated_requests_per_target"] for x in breakdown)
        permitted = total <= config.NUCLEI_MAX_REQUEST_BUDGET
        return {"valid": permitted, "per_target_requests": total,
                "max_job_requests": config.NUCLEI_MAX_REQUEST_BUDGET,
                "max_targets_within_budget": (
                    config.NUCLEI_MAX_REQUEST_BUDGET // total if permitted else 0),
                "templates": breakdown,
                "message": ("Configuration valid" if permitted
                            else "Selected templates exceed the request budget for even one target; remove templates")}
    except (ValueError, KeyError, OSError) as exc:
        raise HTTPException(422, str(exc)[:240])
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Community template retrieval failed: " + str(exc)[:140])


class TemplateDraftRequest(BaseModel):
    provider: Literal["keyless", "gemini"] = "keyless"
    name: str = Field(default="Observation", min_length=3, max_length=100)
    path: str = Field(default="/", min_length=1, max_length=120)
    word: str = Field(default="Example", min_length=1, max_length=200)
    description: str = Field(default="", max_length=2000)


@app.get("/api/nuclei/drafting", dependencies=[Depends(authorize)])
async def drafting_status():
    return {"keyless": True, "gemini": bool(os.environ.get("GEMINI_API_KEY") and os.environ.get("GEMINI_MODEL"))}


@app.post("/api/nuclei/draft", dependencies=[Depends(authorize)])
async def draft_template(spec: TemplateDraftRequest):
    from . import template_builder
    try:
        content = (await template_builder.gemini_draft(spec.description) if spec.provider == "gemini" else
                   template_builder.build_draft(spec.name, spec.path, spec.word))
        await template_builder.validate_draft(content)
        return {"yaml": content, "validated": True, "executed": False, "provider": spec.provider}
    except RuntimeError as exc:
        raise HTTPException(503, str(exc))
    except (ValueError, KeyError, TypeError, httpx.HTTPError):
        raise HTTPException(422, "Draft generation or validation failed; no template was executed")


@app.get("/api/nuclei/templates", dependencies=[Depends(authorize)])
async def search_nuclei_templates(q: str = "", page: int = 1):
    try:
        return await nuclei_catalog.catalog(q, page)
    except (httpx.HTTPError, ValueError) as exc:
        raise HTTPException(503, "Community template index unavailable: " + str(exc)[:180])


@app.get("/api/health")
async def health():
    return {"status": "ok", "zap": bool(ZAP_KEY),
            "parallel_jobs_default": config.PARALLEL_JOBS_DEFAULT,
            "parallel_jobs_max": config.PARALLEL_JOBS_MAX}

class TargetTextImport(BaseModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    format: Literal["auto", "text", "csv", "tsv", "json", "jsonl"] = "auto"


def import_targets_for_owner(parsed, owner):
    owned = {target_key(asset): asset for asset in assets.values() if asset.get("owner") == owner}
    selected, pending, duplicates = [], [], parsed["duplicates"]
    prefix = uuid.uuid4().hex[:12]
    for row in parsed["assets"]:
        key = target_key(row)
        if key in owned:
            duplicates += 1
            selected.append(owned[key])
            continue
        row = {**row, "id": prefix + "-" + row["id"], "owner": owner}
        pending.append(row)
        owned[key] = row
        selected.append(row)
    if len(owned) > MAX_TARGETS:
        raise HTTPException(422, "This session would exceed 3000 imported targets; clear unused targets first")
    for row in pending:
        assets[row["id"]] = row
    return {"imported": len(pending), "web": sum(row["compatibility"] == "web" for row in pending),
            "duplicates": duplicates, "format": parsed["format"],
            "asset_ids": [row["id"] for row in selected],
            "web_asset_ids": [row["id"] for row in selected if row["compatibility"] == "web"]}


@app.post("/api/import", dependencies=[Depends(authorize)])
async def import_file(request: Request, file: UploadFile = File(...),
                      format: Literal["auto", "text", "csv", "tsv", "json", "jsonl"] = "auto"):
    blob = await file.read(2_000_001)
    try:
        parsed = parse_targets(blob, file.filename or "", format)
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    return import_targets_for_owner(parsed, request.state.sid)


@app.post("/api/import/text", dependencies=[Depends(authorize)])
async def import_text(payload: TargetTextImport, request: Request):
    try:
        parsed = parse_targets(payload.text, format=payload.format)
    except (UnicodeError, ValueError) as exc:
        raise HTTPException(422, str(exc))
    return import_targets_for_owner(parsed, request.state.sid)


@app.delete("/api/assets", dependencies=[Depends(authorize)])
async def clear_scope(request: Request):
    """Clear imported scope for this session; keep historical jobs and findings."""
    owned_ids = {key for key, asset in assets.items()
                 if asset.get("owner") == request.state.sid}
    affected_jobs = {job["id"] for job in jobs.values()
                     if job.get("owner") == request.state.sid
                     and job.get("asset_id") in owned_ids
                     and job.get("status") in ("queued", "running")}
    cancellation = cancel_owned_jobs(request.state.sid, affected_jobs)
    for key in owned_ids:
        assets.pop(key, None)
    return {"cleared": len(owned_ids), **cancellation}


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
    execution_plan = build_pipeline_plan(spec.modules, spec.options.order_mode, spec.options.reuse_discovery)
    spec = spec.model_copy(update={"modules": execution_plan["effective"]})
    if "nuclei" in spec.modules:
        selection = spec.options.nuclei
        try:
            nuclei_catalog.validate_selection(
                selection.default_ids, selection.community_paths, selection.custom_templates)
        except ValueError as exc:
            raise HTTPException(422, str(exc))

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
                and existing.get("modules") == spec.modules
                and existing.get("options", {}).get("coverage_profile", "current") == spec.options.coverage_profile
                and existing.get("options", {}).get("reuse_discovery", False) == spec.options.reuse_discovery
                and existing.get("options", {}).get("zap_wait_seconds", config.ZAP_PASSIVE_WAIT_SECONDS_DEFAULT) == spec.options.zap_wait_seconds
                and not (spec.options.inputs.source_text or spec.options.inputs.sbom_text or spec.options.inputs.llm_path
                         or spec.options.inputs.idor_path or spec.options.inputs.idor_values)
                and existing.get("options", {}).get("inputs", {}).get("api_target", False) == spec.options.inputs.api_target):
            return {"id": existing["id"], "status": existing["status"], "reused": True}
    identifier = uuid.uuid4().hex
    recorded_options = spec.options.model_dump()
    recorded_options["inputs"] = spec.options.inputs.public_summary()
    recorded_options["nuclei"]["custom_templates"] = [
        "[inline template]" for _ in spec.options.nuclei.custom_templates]
    jobs[identifier] = {"owner": request.state.sid, "id": identifier, "asset_id": spec.asset_id, "target": url,
                        "status": "queued", "plan": execution_plan, "alerts": [], "error": None, "created": time.time(),
                        "request_count": 0, "cancelled": False, "modules": spec.modules, "endpoints": [], "pipeline": {}, "reviews": [], "probes": [], "options": recorded_options, "progress": 0, "stage": "queued"}
    log_event(jobs[identifier], "queued", modules=spec.modules, parallel_jobs=spec.options.parallel_jobs,
              order_mode=spec.options.order_mode, coverage_profile=spec.options.coverage_profile,
              requested_modules=execution_plan["requested"], plan_warnings=execution_plan["warnings"])
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
    if len(payload.asset_ids) > 1 and "idor-forge" in payload.modules and payload.options.inputs.idor_path:
        raise HTTPException(422, "Configure IDOR-Forge comparisons for one selected asset at a time")
    if len(payload.asset_ids) > 1 and (payload.options.inputs.source_text or payload.options.inputs.sbom_text):
        raise HTTPException(422, "Attach source/SBOM input to one selected asset per job")
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
    owned = [row for row in scan_events if row["owner"] == request.state.sid]
    return {"events": [{k: v for k, v in row.items() if k != "owner"} for row in owned[-2000:]],
            "total": len(owned), "returned": min(len(owned), 2000),
            "truncated": len(owned) > 2000, "storage": "session-memory"}

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

active_scan_tasks = {}

def cancel_owned_jobs(owner, ids=None):
    wanted = set(ids) if ids is not None else None
    queued = running = 0
    for job in jobs.values():
        if job.get("owner") != owner or (wanted is not None and job["id"] not in wanted):
            continue
        if job.get("status") not in ("queued", "running"):
            continue
        job["cancelled"] = True
        if job["status"] == "queued":
            job["status"] = job["stage"] = "cancelled"
            queued += 1
            log_event(job, "cancelled", reason="Cancelled before execution")
        else:
            running += 1
            log_event(job, "cancellation_requested", stage=job.get("stage"))
            task = active_scan_tasks.get(job["id"])
            if task and not task.done():
                task.cancel()
    # Queue and endpoint are on the same asyncio event loop; no await during the drain.
    for _ in range(queue.qsize()):
        item = queue.get_nowait()
        if jobs.get(item[0], {}).get("status") == "cancelled":
            queue.task_done()
        else:
            queue.put_nowait(item)
            queue.task_done()
    return {"cancelled_queued": queued, "cancellation_requested_running": running}

@app.post("/api/scans/cancel-all", dependencies=[Depends(authorize)])
async def cancel_all_scans(request: Request):
    return cancel_owned_jobs(request.state.sid)

@app.post("/api/scans/{scan_id}/cancel", dependencies=[Depends(authorize)])
async def cancel_scan(scan_id: str, request: Request):
    if scan_id not in jobs or jobs[scan_id].get("owner") != request.state.sid:
        raise HTTPException(404, "Scan not found")
    return {"cancel_requested": True, **cancel_owned_jobs(request.state.sid, {scan_id})}

async def zap_call(client, component, action, params=None):
    response = await client.get(f"{ZAP_URL}/JSON/{component}/{action}/", params={**(params or {}), "apikey": ZAP_KEY})
    response.raise_for_status()
    data = response.json()
    if "code" in data:
        raise RuntimeError(str(data.get("message") or data["code"]))
    return data

async def worker():
    await dispatch(queue, jobs, active_scan_tasks, run_scan_job, log_event)

async def run_scan_job(identifier, spec):
    job = jobs[identifier]
    try:
        if job["cancelled"]:
            job["status"] = job["stage"] = "cancelled"
            log_event(job, "cancelled", reason="Cancelled before execution")
            return
        job["status"] = "running"
        log_event(job, "started")
        url, host = target_url(assets[spec.asset_id])
        endpoints = [url]
        endpoint_sources = {url: ["scope"]}
        # Modules execute in the user-selected order, sequentially, with bounded output.
        for position, module in enumerate(spec.modules):
            if job["cancelled"]:
                break
            async with module_slot(module, job, log_event,
                                   enabled=module not in ('depscan', 'trivy') or bool(spec.options.inputs.sbom_text)):
                public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
                job["stage"] = module
                started_at = time.monotonic()
                log_event(job, "stage_started", module=module, position=position + 1, total=len(spec.modules), endpoints=len(endpoints))
                job["progress"] = round(position * 100 / len(spec.modules))
                job["pipeline"][module] = "running"
                try:
                    if module == "gau":
                        result = await gau(url, host, spec.options.endpoint_limit, spec.options.gau_mode)
                        for discovered in result["endpoints"]:
                            endpoint_sources.setdefault(discovered, []).append("gau")
                        endpoints = list(dict.fromkeys(endpoints + result["endpoints"]))[:spec.options.endpoint_limit]
                        job["endpoints"] = endpoints[1:]
                    elif module == "katana":
                        if spec.options.reuse_discovery:
                            log_event(job, "data_handoff", module=module, data="URL inventory to crawl seeds",
                                      available_urls=len(endpoints))
                            result = await katana(url, host, spec.user_agent, spec.options.katana_depth,
                                                  spec.options.endpoint_limit, seed_urls=endpoints,
                                                  coverage_profile=spec.options.coverage_profile)
                        else:
                            result = await katana(url, host, spec.user_agent, spec.options.katana_depth,
                                                  spec.options.endpoint_limit)
                        for discovered in result["endpoints"]:
                            endpoint_sources.setdefault(discovered, []).append("katana")
                        endpoints = list(dict.fromkeys(endpoints + result["endpoints"]))[:spec.options.endpoint_limit]
                        job["endpoints"] = endpoints[1:]
                    elif module == "httpx":
                        result = await probe(endpoints, host, spec.user_agent, spec.options.httpx_limit)
                        job["probes"] = result["probes"]
                    elif module == "zap-passive":
                        async with httpx.AsyncClient(timeout=20, trust_env=False) as control:
                            await zap_call(control, "core", "action/newSession", {})
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
                            zap_urls = (assessed_urls(url, endpoints, job.get("probes", []))
                                    if spec.options.reuse_discovery else endpoints)
                            for candidate in zap_urls[:spec.options.zap_endpoint_limit]:
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
                        # ZAP's passive scanner is asynchronous and its queue is global
                        # to this process, not specific to the current host.
                        pending_records = 0
                        wait_checks = 0
                        zap_alerts = []
                        async with httpx.AsyncClient(timeout=20, trust_env=False) as z:
                            from .zap_control import wait_for_passive_queue
                            queue_report = await wait_for_passive_queue(
                                z, zap_call, host,
                                limit=config.ZAP_PASSIVE_POLL_LIMIT,
                                interval=config.ZAP_PASSIVE_POLL_SECONDS,
                                stall_checks=config.ZAP_PASSIVE_STALL_CHECKS,
                                timeout_seconds=spec.options.zap_wait_seconds,
                                on_progress=lambda state: log_event(
                                    job, "passive_queue_wait", module=module,
                                    summary="Waiting for ZAP passive rules to finish", diagnostics=state))
                            pending_records = queue_report["remaining"]
                            wait_checks = queue_report["checks"]
                            origin_url = urlsplit(url)._replace(path="/", query="", fragment="").geturl()
                            for offset in range(0, config.ZAP_ALERT_FETCH_LIMIT, 100):
                                page = await zap_call(z, "core", "view/alerts", {
                                    "baseurl": origin_url, "start": str(offset), "count": "100"})
                                entries = page.get("alerts", [])
                                if not isinstance(entries, list):
                                    break
                                zap_alerts.extend(entries)
                                if len(entries) < 100:
                                    break
                        observed_keys = set()
                        captured = []
                        for a in zap_alerts:
                            if not isinstance(a, dict) or urlsplit(a.get("url") or "").hostname != host:
                                continue
                            key = (a.get("pluginId") or a.get("name"), a.get("url"),
                                   a.get("param") or "")
                            if key in observed_keys:
                                continue
                            observed_keys.add(key)
                            captured.append({
                                "source": "zap", "name": a.get("name"), "risk": a.get("risk"),
                                "confidence": a.get("confidence"), "url": a.get("url"),
                                "description": (a.get("description") or "")[:1000],
                                "plugin_id": a.get("pluginId"), "parameter": a.get("param"),
                            })
                        job["alerts"].extend(captured)
                        result = {
                            "status": "completed" if pending_records == 0 else "partial",
                            "reason": (queue_report["reason"] if pending_records else ""),
                            "pending_records": pending_records,
                            "queue_stalled": queue_report["stalled"],
                            "host_tasks_running": queue_report["host_tasks_running"],
                            "global_tasks_running": queue_report["global_tasks_running"],
                            "alerts": captured,
                            "alerts_collected": len(captured),
                            "queue_scope": "global",
                            "wait_checks": wait_checks,
                            "passive_wait": {key: value for key, value in queue_report.items() if key != "reason"},
                        }
                    elif module == "nuclei":
                        selection = spec.options.nuclei
                        try:
                            remote = await nuclei_catalog.community_files(selection.community_paths)
                        except (ValueError, httpx.HTTPError) as exc:
                            raise ValueError("Nuclei template download failed: " + str(exc)[:160])
                        result = await nuclei(
                            url, host, spec.user_agent,
                            assessed_urls(url, endpoints, job.get("probes", [])) if spec.options.reuse_discovery else endpoints,
                            selection.default_ids, remote, selection.custom_templates)
                        job["alerts"].extend(result["alerts"])
                    elif module in WEB_MODULES:
                        module_url = (page_target(url, job.get("probes", [])) if
                                      spec.options.reuse_discovery and module in ("nikto", "wpscan", "wapiti", "retirejs")
                                      else url)
                        if module_url != url:
                            log_event(job, "data_handoff", module=module, data="Observed live page",
                                      selected_url=module_url)
                        profile_kwargs = ({"profile": spec.options.coverage_profile}
                                          if spec.options.coverage_profile != "current" else {})
                        result = await run_web_module(
                            module, module_url, host, spec.user_agent, spec.delay_seconds,
                            endpoints, spec.options.inputs, **profile_kwargs)
                        job["reviews"].append(result)
                        job["alerts"].extend(result.get("alerts", []))
                        job["probes"].extend(result.get("probes", []))
                        if result.get("hosts"):
                            job.setdefault("discovered_hosts", []).extend(result["hosts"])
                        if result.get("endpoints"):
                            for candidate in result["endpoints"]:
                                if in_host(candidate, host):
                                    endpoint_sources.setdefault(candidate, []).append(module)
                                    if candidate not in endpoints:
                                        endpoints.append(candidate)
                            endpoints = endpoints[:spec.options.endpoint_limit]
                            job["endpoints"] = endpoints[1:]
                    elif module in ACTIVE_MODULES:
                        review_url = (choose_arjun_target(
                                          page_target(url, job.get("probes", [])) if spec.options.reuse_discovery else url,
                                          assessed_urls(url, endpoints, job.get("probes", [])) if spec.options.reuse_discovery else endpoints, host)
                                      if module == "arjun" else
                                      choose_dalfox_target(url, job.get("parameters", []), host)
                                      if module == "dalfox" else
                                      choose_sqlmap_target(url, endpoints, job.get("parameters", []), host)
                                      if module == "sqlmap" else url)
                        profile_kwargs = ({"profile": spec.options.coverage_profile}
                                          if spec.options.coverage_profile != "current" else {})
                        result = await review(module, review_url, host, **profile_kwargs)
                        job["reviews"].append(result)
                        if module == "dalfox":
                            job["alerts"].extend(result.get("findings", []))
                        if module == "ffuf":
                            discovered_urls = [
                                candidate for candidate in result.get("endpoints", [])
                                if in_host(candidate, host)
                            ]
                            for candidate in discovered_urls:
                                endpoint_sources.setdefault(candidate, []).append("ffuf")
                            endpoints = list(dict.fromkeys(
                                endpoints + discovered_urls))[:spec.options.endpoint_limit]
                            job["endpoints"] = endpoints[1:]
                        if module == "arjun":
                            job["parameters"] = [
                                item for item in result.get("parameters", [])
                                if in_host(item.get("url", ""), host)
                            ]
                except Exception as exc:
                    log_event(job, "stage_exception", module=module,
                              error_type=exc.__class__.__name__)
                    result = {"status":"failed", "reason":"Module exception: "+exc.__class__.__name__}
                job["pipeline"][module] = result["status"]
                summary = str(result.get("output") or "")
                if not summary:
                    summary = ("Discovered " + str(len(result.get("endpoints", []))) +
                               " endpoints; " + str(len(result.get("probes", []))) +
                               " probes; " + str(len(result.get("alerts", []))) + " module alerts")
                if module == "gau":
                    summary = str(result.get("summary") or summary)
                if module == "nuclei":
                    summary = ("Nuclei templates: " +
                               ", ".join(result.get("templates", ["unknown"])) +
                               "; URLs: " + str(result.get("targets_checked", 0)) +
                               "; matches: " + str(len(result.get("alerts", []))))
                if module == "arjun":
                    summary = (str(len(result.get("parameters", []))) +
                               " structured parameters. Target: " + str(result.get("target", url)) +
                               ". " + summary)
                if module == "dalfox":
                    summary = (str(len(result.get("findings", []))) +
                               " unverified Dalfox findings; " + summary)
                if module == "zap-passive":
                    # A failed ZAP API call has no queue report. Formatting its
                    # diagnostics must not raise and abort the remaining modules.
                    summary = ("ZAP-proxied requests: " + str(job["request_count"]) +
                               "; alerts: " + str(len(result.get("alerts", []))) +
                               "; global queued passive records: " + str(result.get("pending_records", "unknown")) +
                               "; wait checks: " + str(result.get("wait_checks", 0)) +
                               "; passive wait seconds: " + str(result.get("passive_wait", {}).get("elapsed_seconds", "unknown")) +
                               "; host tasks running: " + str(result.get("host_tasks_running", "unknown")) +
                               "; stalled: " + str(result.get("queue_stalled", "unknown")))
                    if result.get("reason") and not result.get("passive_wait"):
                        summary += "; " + str(result["reason"])
                summary = summary[:1200]
                counts = {
                    "new_endpoints": len(result.get("endpoints", [])),
                    "new_probes": len(result.get("probes", [])),
                    "new_alerts": len(result.get("alerts", [])) + len(result.get("findings", [])),
                    "new_parameters": len(result.get("parameters", [])),
                }
                elapsed_ms = round((time.monotonic() - started_at) * 1000)
                job.setdefault("stage_details", {})[module] = {"status": result["status"], "elapsed_ms": elapsed_ms, "reason": str(result.get("reason", ""))[:250], "summary": summary, "counts": counts}
                diagnostics = {}
                if module == "gau":
                    diagnostics = {"coverage": result.get("coverage"), "mode": result.get("mode"),
                                   "providers": result.get("providers", [])}
                if module == "dalfox":
                    diagnostics["coverage"] = result.get("metadata", {})
                if result.get("coverage") is not None and module != "gau":
                    diagnostics["coverage_budget" if module == "dalfox" else "coverage"] = result["coverage"]
                if result.get("seed_count") is not None:
                    diagnostics["crawl_seeds"] = result["seed_count"]
                if result.get("passive_wait") is not None:
                    diagnostics["passive_wait"] = result["passive_wait"]
                if result.get("verification") is not None:
                    diagnostics["verification"] = result["verification"]
                diagnostics["coverage_profile"] = spec.options.coverage_profile
                if result.get("deadline_seconds") is not None:
                    diagnostics["deadline_seconds"] = result["deadline_seconds"]
                if result.get("target") and module in ("dalfox", "arjun", "sqlmap"):
                    diagnostics["review_target"] = result["target"]
                if result.get("exit_code") is not None:
                    diagnostics["exit_code"] = result["exit_code"]
                if result.get("requests") is not None:
                    diagnostics["module_requests"] = result["requests"]
                log_event(job, "stage_finished", module=module, status=result["status"], elapsed_ms=elapsed_ms, reason=str(result.get("reason", ""))[:250], summary=summary[:1200], counts=counts, alerts=len(job.get("alerts", [])), endpoints=len(job.get("endpoints", [])), diagnostics=diagnostics)
                job["endpoint_sources"] = {key: sorted(set(value)) for key, value in endpoint_sources.items() if key in endpoints}
                job["progress"] = round((position + 1) * 100 / len(spec.modules))
        stage_statuses = list(job["pipeline"].values())
        degraded = any(status in ("failed", "timeout", "unavailable", "partial") for status in stage_statuses)
        job["status"] = "cancelled" if job["cancelled"] else ("partial" if degraded else "completed")
        job["stage"] = job["status"]
        log_event(job, "finished", status=job["status"])
        if job["status"] in ("completed", "partial"):
            job["progress"] = 100
    except asyncio.CancelledError:
        job["status"] = job["stage"] = ("cancelled" if job.get("cancelled") else "interrupted")
        log_event(job, job["status"], reason="Active scan interrupted")
        raise
    except Exception as exc:
        job["status"] = "failed"
        job["stage"] = "failed"
        job["error"] = exc.__class__.__name__
        log_event(job, "failed", error_type=exc.__class__.__name__)
