"""Public bbcollect discovery, evidence-based rule hints and session-owned scope bindings."""
import asyncio
import hashlib
import html
import json
import re
import secrets
import time
import weakref
from html.parser import HTMLParser
from fnmatch import fnmatchcase
from urllib.parse import quote, unquote, urlsplit

import httpx
from fastapi import Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field

from .scope import asset_from_row, classify, target_url

BASE = "https://wuhp-bbconnectapi.hf.space/api/v1"
PLATFORMS = {"hackerone", "bugcrowd", "intigriti", "yeswehack"}
TTL = 900
_documents = {}
_bindings = {}
_slots = weakref.WeakKeyDictionary()
DEFAULT_AGENT = "ASFB-Research/0.1"


class PolicySettings(BaseModel):
    model_config = ConfigDict(extra="forbid")
    researcher: str = Field(default="", max_length=100, pattern=r"^[A-Za-z0-9_.-]*$")
    test_email: str = Field(default="", max_length=254)
    test_account_confirmed: bool = False
    rules_reviewed: bool = False
    custom_agent: str = Field(default="", max_length=300)


class Selection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    review_id: str = Field(max_length=100)
    asset_ids: list[str] = Field(default_factory=list, max_length=1000)
    concrete_urls: list[str] = Field(default_factory=list, max_length=100)
    settings: PolicySettings = Field(default_factory=PolicySettings)


class ImportSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    programs: list[Selection] = Field(min_length=1, max_length=20)


class Text(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts, self.hidden = [], 0
    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.hidden += 1
        elif tag in ("p", "div", "li", "br", "h1", "h2", "h3", "tr"):
            self.parts.append("\n")
        elif tag not in ("a", "span", "strong", "em", "b", "i", "code", "pre", "ul", "ol", "table", "td", "th"):
            self.parts.append(self.get_starttag_text())
    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)
        elif tag in ("p", "div", "li", "pre", "tr"):
            self.parts.append("\n")
    def handle_data(self, value):
        if not self.hidden:
            self.parts.append(value)


def plain(value):
    if isinstance(value, str):
        parser = Text()
        parser.feed(value)
        return html.unescape("".join(parser.parts))
    if isinstance(value, dict):
        return "\n".join(plain(v) for k, v in value.items() if k not in ("raw", "id", "uuid"))
    if isinstance(value, list):
        return "\n".join(plain(v) for v in value)
    return ""


def printable(value):
    return isinstance(value, str) and 0 < len(value) <= 300 and chr(92) not in value and all(32 <= ord(c) < 127 for c in value)


def policy_analysis(rules, instructions="", partial=False):
    text = (plain(rules) + "\n" + instructions).strip()
    lines = [re.sub(r"[ \t]+", " ", line).strip() for line in text.splitlines() if line.strip()]
    agents, emails, headers, evidence, review = [], set(), [], [], []
    rates, blocked = [], False
    for line in lines:
        lower = line.lower()
        recognized = False
        if re.search(r"(?:automated|automatic|vulnerability)\s+(?:scann(?:ing|ers?)|tools?|testing)\s+(?:is\s+|are\s+)?(?:not allowed|not permitted|prohibited|forbidden)|do not use.{0,30}(?:automated|automatic).{0,20}scann|\bno\s+(?:automated|automatic)\s+(?:scann|testing)", lower):
            blocked = True
            evidence.append({"kind": "automation", "text": line[:600]})
            recognized = True
        match = re.search(r"user[- ]agent(?:\s+header)?\s*(?:must\s+(?:be|include)|should\s+(?:be|include)|to|as|=|:|include|contains?)\s*(.+)", line, re.I)
        if match:
            value = match.group(1).strip()
            quotes = {chr(96): chr(96), chr(34): chr(34), chr(39): chr(39), chr(8220): chr(8221)}
            if value and value[0] in quotes:
                value = value[1:].split(quotes[value[0]], 1)[0]
            else:
                value = re.split(r"\.\s+|\s+(?:for all|for every|when testing|on all|in all)\b",
                                 value, flags=re.I)[0].rstrip(".")
            if printable(value):
                mode = "contains" if re.search(r"include|contains?|append", match.group(0).split(value)[0], re.I) else "exact"
                item = {"value": value, "mode": mode, "evidence": line[:600]}
                if not any(a["value"] == value and a["mode"] == mode for a in agents):
                    agents.append(item)
                recognized = True
        if ("wearehackerone.com" in lower or "@" in lower) and re.search(r"email|account|register|sign.?up", lower) and re.search(r"must|required|use\b|register|sign.?up", lower):
            if not re.search(r"contact|questions|support|report.{0,10}(?:to|at)", lower) or re.search(r"register|test account|sign.?up", lower):
                domains = re.findall(r"@([a-z0-9.-]+\.[a-z]{2,})", lower)
                if "wearehackerone.com" in lower and "wearehackerone.com" not in domains:
                    domains.append("wearehackerone.com")
                if domains:
                    emails.update(d.rstrip(".") for d in domains)
                    evidence.append({"kind": "test_account", "text": line[:600]})
                    recognized = True
        for match in re.finditer(r"\b(X-[A-Za-z0-9-]{1,70})\s*:\s*[`\"]?([^\n`\"]{1,250})", line, re.I):
            name, value = match.groups()
            if re.search(r"bug|bounty|research|hackerone", name, re.I) and printable(value.strip().rstrip(".")):
                headers.append({"name": name, "value": value.strip().rstrip("."), "evidence": line[:600]})
                recognized = True
        for match in re.finditer(r"(\d+(?:\.\d+)?)\s*(?:requests?|reqs?)\s*(?:per|/)\s*(second|sec|s|minute|min|m)\b|(\d+(?:\.\d+)?)\s*rps\b", lower):
            number = float(match.group(1) or match.group(3))
            if number > 0:
                rates.append(number / 60 if match.group(2) in ("minute", "min", "m") else number)
                evidence.append({"kind": "rate", "text": line[:600]})
                recognized = True
        if re.search(r"must|required|shall|do not|prohibited|not allowed", lower) and not recognized:
            review.append("Other testing instructions need review")
    if len(agents) > 4 or len(headers) > 5 or len(emails) > 5 or len(text) > 250000:
        review.append("Some rule text or requirements exceed the automatic review limits")
    if partial:
        review.append("Program data is partial; verify current scope and rules")
    if not text:
        review.append("Rules are unavailable")
    if not (agents or emails or headers):
        review.append("No supported identification requirements were found")
    if re.search(r"see (?:the )?(?:linked|external|additional)|rules.{0,20}https?://", text, re.I):
        review.append("Referenced instructions may need separate review")
    return {"user_agents": agents[:4], "email_domains": sorted(emails)[:5], "headers": headers[:5],
            "max_rps": min(rates) if rates else None, "automation_prohibited": blocked,
            "review_required": bool(review), "review_reasons": list(dict.fromkeys(review)),
            "evidence": evidence[:30], "text": text[:250000], "partial": partial}


def substitute(value, researcher):
    pattern = r"<(?:your[-_ ]?)?(?:hackerone[-_ ]?)?(?:user(?:name)?|handle)>|\{(?:user(?:name)?|handle|researcher)\}|\[(?:user(?:name)?|handle)\]|YOUR_(?:HACKERONE_)?USERNAME"
    if re.search(pattern, value, re.I):
        if not researcher:
            raise ValueError("Enter your researcher handle to fill the required identity")
        value = re.sub(pattern, lambda _: researcher, value, flags=re.I)
    if re.search(r"[<>{}]|YOUR_|\byour[-_ ](?:username|handle)\b", value, re.I):
        raise ValueError("The identity template needs manual configuration")
    if not printable(value):
        raise ValueError("User-Agent/header values must be printable text up to 300 characters")
    return value


def configure(analysis, settings):
    if analysis["automation_prohibited"]:
        raise ValueError("Published rules prohibit automated scanning; this program cannot be queued")
    if analysis["review_required"] and not settings.rules_reviewed:
        raise ValueError("Confirm that you reviewed this program's current rules and configured the requirements")
    agent, requirements = DEFAULT_AGENT, analysis["user_agents"]
    exact = []
    for requirement in requirements:
        try:
            value = substitute(requirement["value"], settings.researcher)
        except ValueError:
            if not (settings.custom_agent and settings.rules_reviewed):
                raise
            continue
        if requirement["mode"] == "exact":
            exact.append(value)
        elif value not in agent:
            agent += " " + value
    if len(set(exact)) > 1 and not (settings.custom_agent and settings.rules_reviewed):
        raise ValueError("Conflicting User-Agent examples need a reviewed manual value")
    if exact:
        agent = exact[0]
    if settings.custom_agent:
        if not printable(settings.custom_agent):
            raise ValueError("Custom User-Agent contains unsupported characters")
        if requirements and settings.custom_agent != agent and not settings.rules_reviewed:
            raise ValueError("Review the rule before overriding the inferred User-Agent")
        agent = settings.custom_agent
    domains = analysis["email_domains"]
    if domains:
        email = settings.test_email.strip()
        if (not re.fullmatch(r"[^\s@]+@[^\s@]+", email) or email.rsplit("@", 1)[1].lower() not in domains
                or not settings.test_account_confirmed):
            raise ValueError("Enter a matching test-account email and confirm that this account is configured")
    headers = {}
    for item in analysis["headers"]:
        headers[item["name"]] = substitute(item["value"], settings.researcher)
    rate = analysis["max_rps"]
    if rate is not None and rate < 1 / 30:
        raise ValueError("This rate requirement is below the scanner's supported pacing; review manually")
    return {"user_agent": agent, "apply_agent": bool(requirements or settings.custom_agent),
            "headers": headers, "rate": rate, "email_domains": domains,
            "reviewed": settings.rules_reviewed}


def url_parts(value):
    if len(value) > 1000 or any(c in value for c in "\r\n\x00\\"):
        raise ValueError("Invalid scope URL")
    parts = urlsplit(value if "://" in value else "https://" + value)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.port not in (None, 80, 443, 8080):
        raise ValueError("Unsupported scope URL")
    path = parts.path or "/"
    for _ in range(2):
        path = unquote(path)
    if any(segment in (".", "..") for segment in path.split("/")) or chr(92) in path or re.search(r"%(?:2e|2f|5c|25)", path, re.I):
        raise ValueError("Ambiguous scope path")
    return parts, path


def matches(identifier, candidate):
    """Domain scopes are exact; wildcard scopes never authorize the apex."""
    try:
        if identifier.startswith("/") and not identifier.startswith("//"):
            target = urlsplit(candidate if "://" in candidate else "https://" + candidate)
            identifier = target._replace(path=identifier, query="", fragment="").geturl()
        a, path = url_parts(identifier)
        b, target_path = url_parts(candidate)
        wildcard = a.hostname.startswith("*.")
        host = (b.hostname.endswith(a.hostname[1:]) and b.hostname != a.hostname[2:]) if wildcard else b.hostname == a.hostname
        if not host:
            return False
        if "://" in identifier and (a.scheme != b.scheme or (a.port or (443 if a.scheme == "https" else 80)) != (b.port or (443 if b.scheme == "https" else 80))):
            return False
        if "*" in path:
            return fnmatchcase(target_path, path.replace("[", "[[]").replace("?", "[?]"))
        return (path == "/" or target_path == path or target_path.startswith(path.rstrip("/") + "/")) and (not a.query or a.query == b.query)
    except (ValueError, TypeError, AttributeError):
        return False


def asset_id(row):
    return hashlib.sha256(json.dumps([row.get("identifier"), row.get("type"), row.get("instructions"), row.get("raw")], sort_keys=True).encode()).hexdigest()[:24]


async def _fetch_json(path, params=None):
    loop = asyncio.get_running_loop()
    semaphore = _slots.setdefault(loop, asyncio.Semaphore(2))
    if semaphore.locked():
        raise HTTPException(429, "Discovery service is busy; retry shortly")
    async with semaphore:
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=15), trust_env=False, follow_redirects=False) as client:
                async with client.stream("GET", BASE + path, params=params, headers={"Accept": "application/json"}) as response:
                    if response.status_code != 200:
                        raise HTTPException(503 if response.status_code != 429 else 429,
                                            "Bounty API is busy or unavailable; retry shortly")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > 4_000_000:
                            raise HTTPException(502, "Program response exceeds the bounded discovery response size")
                    result = json.loads(body)
            if not isinstance(result, dict) or result.get("ok") is not True:
                raise HTTPException(502, "Bounty API returned no usable data")
            return result
        except (httpx.HTTPError, ValueError):
            raise HTTPException(503, "Bounty API could not be reached or returned invalid JSON")


async def fetch_json(path, params=None):
    try:
        async with asyncio.timeout(180):
            return await _fetch_json(path, params)
    except TimeoutError:
        raise HTTPException(503, "Bounty API request timed out; retry shortly")


def document(owner, review_id):
    record = _documents.get((owner, review_id))
    if not record or time.monotonic() - record["stored"] > TTL:
        raise ValueError("Program review expired; reload its current scope and rules")
    return record


def prepare(owner, selection):
    doc = document(owner, selection.review_id)
    config = configure(doc["analysis"], selection.settings)
    rows = {row["id"]: row for row in doc["assets"]}
    chosen = []
    for identifier in selection.asset_ids:
        if identifier not in rows:
            raise ValueError("A selected scope asset is stale; reload this program")
        row = rows[identifier]
        if row["type"] in ("url", "api", "domain") and "*" not in row["identifier"]:
            chosen.append((row["identifier"], row))
    for value in selection.concrete_urls:
        matching = [row for row in rows.values() if row["id"] in selection.asset_ids and matches(row["identifier"], value)]
        if not matching:
            raise ValueError("Concrete URL does not match a selected scope entry")
        chosen.append((value, matching[0]))
    prepared = []
    seen = set()
    for value, row in chosen:
        if classify(value, "") != "web":
            raise ValueError("Select explicit HTTP(S) URLs or hostnames; wildcard entries need concrete URLs")
        if not matches(row["identifier"], value):
            raise ValueError("Target exceeds its selected scope path or origin")
        if any(matches(exclusion["identifier"], value) for exclusion in doc["exclusions"]):
            raise ValueError("A selected target matches a published out-of-scope exclusion")
        url, path = url_parts(value)
        identity = url._replace(fragment="").geturl()
        if identity in seen:
            continue
        seen.add(identity)
        # Whole-site tools cannot enforce path-only authorization/exclusions.
        constrained = path != "/" or url.query or any(classify(x["identifier"], "") != "web" and "*" not in x["identifier"] for x in doc["exclusions"]) or any(
            matches(url._replace(path="/", query="").geturl(), x["identifier"].replace("*.", ""))
            for x in doc["exclusions"])
        prepared.append((value, row, config, bool(constrained)))
    if not prepared:
        raise ValueError("Choose at least one explicit web target; selected wildcards require concrete URLs")
    return doc, prepared


def enforce_asset(owner, asset, spec):
    binding = _bindings.get((owner, asset["id"]))
    if not asset.get("program"):
        return spec, None
    if not binding:
        raise ValueError("This program binding expired; reload and import its current scope")
    doc = document(owner, binding["review_id"])
    config, restricted = binding["config"], binding["restricted"]
    modules = list(spec.modules)
    reasons = []
    if restricted or config["headers"] or config["rate"] is not None:
        modules = [m for m in modules if m == "zap-passive"]
        reasons.append("Exact-URL ZAP profile enforces path/exclusion/header/rate constraints")
    elif config["apply_agent"]:
        modules = [m for m in modules if m not in ("testssl", "garak")]
        if len(modules) != len(spec.modules):
            reasons.append("TLS/LLM profiles without verified identity-header support omitted")
    if not modules:
        raise ValueError("Selected modules cannot enforce these rules; enable ZAP passive for this program")
    options = spec.options.model_copy(deep=True)
    delay = spec.delay_seconds
    if restricted or config["headers"] or config["rate"] is not None:
        options.reuse_discovery = False
        options.zap_endpoint_limit = 1
        options.parallel_jobs = 1
        if config["rate"] is not None:
            delay = max(delay, 1 / config["rate"])
    omitted = [m for m in spec.modules if m not in modules]
    spec = spec.model_copy(update={"modules": modules, "options": options, "delay_seconds": delay,
                                   "user_agent": config["user_agent"] if config["apply_agent"] else spec.user_agent})
    spec._program_headers = config["headers"]
    summary = {"id": doc["program_id"], "name": doc["name"], "url": doc["url"],
               "policy_revision": doc["revision"], "fetched_at": doc["source"].get("fetched_at"),
               "identity_applied": config["apply_agent"], "test_account_domains": config["email_domains"],
               "manual_review": config["reviewed"], "constraints": reasons,
               "omitted_modules": omitted}
    return spec, summary


def install(app, authorize, assets, maximum):
    @app.get("/api/discovery/programs", dependencies=[Depends(authorize)])
    async def programs(platforms: str = "hackerone,bugcrowd,intigriti,yeswehack",
                       search: str = Query(default="", max_length=200), bounty_only: bool = True,
                       currency: str = "", reward_at_least: float | None = Query(default=None, ge=0),
                       sort_by: str = "name", descending: bool = False, offset: int = Query(default=0, ge=0, le=100000)):
        selected = list(dict.fromkeys(p.strip().lower() for p in platforms.split(",") if p.strip()))
        if not selected or any(p not in PLATFORMS for p in selected) or sort_by not in ("name", "max_bounty", "min_bounty"):
            raise HTTPException(422, "Choose supported platforms and sort order")
        if currency and not re.fullmatch(r"[A-Za-z]{3}", currency):
            raise HTTPException(422, "Currency must be a three-letter code")
        if (reward_at_least is not None or sort_by != "name") and not currency:
            raise HTTPException(422, "Choose one currency before filtering or sorting rewards")
        params = dict(platforms=",".join(selected), search=search, bounty_only=str(bounty_only).lower(),
                      include_details="false", limit=25, offset=offset, sort_by=sort_by, descending=str(descending).lower())
        if currency:
            params["currency"] = currency.upper()
        if reward_at_least is not None:
            params["reward_at_least"] = reward_at_least
        result = await fetch_json("/programs", params)
        fields = ("id", "platform", "handle", "name", "url", "offers_bounties", "min_bounty", "max_bounty", "currency")
        return {**{k: result.get(k) for k in ("total", "next_offset", "offset", "partial", "sources")},
                "programs": [{k: p.get(k) for k in fields} for p in result.get("programs", []) if isinstance(p, dict)]}

    @app.get("/api/discovery/programs/{platform}/{handle}", dependencies=[Depends(authorize)])
    async def details(platform: str, handle: str, request: Request, offset: int = Query(default=0, ge=0, le=100000)):
        if platform not in PLATFORMS or not re.fullmatch(r"[A-Za-z0-9_.-]{1,200}", handle):
            raise HTTPException(422, "Unsupported program reference")
        result = await fetch_json("/programs/" + platform + "/" + quote(handle, safe="") + "/assets",
                                  {"limit": 1000, "offset": offset})
        rows = [dict(row, id=asset_id(row)) for row in result.get("in_scope", []) if isinstance(row, dict) and isinstance(row.get("identifier"), str)]
        exclusions = [row for row in result.get("out_of_scope", []) if isinstance(row, dict) and isinstance(row.get("identifier"), str)]
        instructions = "\n".join(plain(row.get("instructions")) + "\n" + plain(row.get("raw")) for row in rows)
        analysis = policy_analysis(result.get("rules"), instructions, bool(result.get("partial")))
        if any(classify(row["identifier"], "") != "web" and "*" not in row["identifier"] for row in exclusions):
            analysis["review_required"] = True
            analysis["review_reasons"].append("Some exclusions are prose or non-web scope; verify the selected URLs")
        source = result.get("source") if isinstance(result.get("source"), dict) else {}
        revision = hashlib.sha256(json.dumps([result.get("rules"), exclusions, rows], sort_keys=True).encode()).hexdigest()
        review_id = secrets.token_urlsafe(24)
        # Bound per-session review memory; snapshots expire without disk writes.
        owned = [(key, value) for key, value in _documents.items() if key[0] == request.state.sid]
        for key, value in owned:
            if time.monotonic() - value["stored"] > TTL:
                _documents.pop(key, None)
        owned = [key for key in _documents if key[0] == request.state.sid]
        if len(owned) >= 20:
            _documents.pop(owned[0], None)
        platform_hosts = {"hackerone": "https://hackerone.com/", "bugcrowd": "https://bugcrowd.com/",
                          "intigriti": "https://app.intigriti.com/programs/", "yeswehack": "https://yeswehack.com/programs/"}
        record = {"review_id": review_id, "program_id": platform + ":" + handle, "name": handle,
                  "url": platform_hosts[platform] + quote(handle), "assets": rows, "exclusions": exclusions,
                  "analysis": analysis, "revision": revision, "source": source, "stored": time.monotonic()}
        source_url = source.get("source_url", "")
        if isinstance(source_url, str) and urlsplit(source_url).scheme == "https" and urlsplit(source_url).hostname in (
                "hackerone.com", "bugcrowd.com", "app.intigriti.com", "intigriti.com", "yeswehack.com"):
            record["url"] = source_url
        _documents[(request.state.sid, review_id)] = record
        return {k: value for k, value in record.items() if k != "stored"} | {
            "next_offset": result.get("next_offset"), "total": result.get("total"),
            "scope_note": "Wildcards need explicit URLs. Exclusions remain in effect. Import does not start a scan."}

    @app.post("/api/discovery/import", dependencies=[Depends(authorize)])
    def import_programs(payload: ImportSelection, request: Request):
        prepared = []
        try:
            for selection in payload.programs:
                doc, rows = prepare(request.state.sid, selection)
                for value, row, config, restricted in rows:
                    asset = asset_from_row({"asset_identifier": value, "asset_type": "url",
                        "eligible_for_bounty": row.get("eligible_for_bounty"),
                        "description": doc["program_id"] + " · " + (row.get("instructions") or "")}, len(prepared))
                    asset.update(id="program-" + secrets.token_hex(12), owner=request.state.sid,
                                 program={"id": doc["program_id"], "url": doc["url"], "review_id": doc["review_id"]})
                    prepared.append((asset, doc, config, restricted))
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        if len(prepared) > 1000 or sum(a.get("owner") == request.state.sid for a in assets.values()) + len(prepared) > maximum:
            raise HTTPException(422, "Selection exceeds session/scan capacity")
        for asset, doc, config, restricted in prepared:
            assets[asset["id"]] = asset
            _bindings[(request.state.sid, asset["id"])] = {"review_id": doc["review_id"], "config": config, "restricted": restricted}
        return {"imported": len(prepared), "web_asset_ids": [asset["id"] for asset, *_ in prepared],
                "programs": len(payload.programs), "note": "Rules apply per target when scans are queued; review queue confirmations next."}
