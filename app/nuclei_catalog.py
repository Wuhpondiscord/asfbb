"""Bounded Nuclei template catalog and read-only HTTP profile validation."""
import re
import time
from pathlib import Path

import httpx
import yaml
from fastapi import HTTPException

from . import config

SOURCE_REPO = "projectdiscovery/nuclei-templates"
REPO_PATH = re.compile(r"^http/(?:[a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+\.ya?ml$")
SAFE_PATH = re.compile(r"^\{\{BaseURL\}\}(?:/[a-zA-Z0-9_./%?=&-]{0,150})?$")
_cache = {"expires": 0.0, "sha": "", "paths": set(), "templates": {}}


def builtins():
    return {**{Path(p).stem: p for p in config.NUCLEI_TEMPLATE_PATHS},\n            **config.NUCLEI_OPTIONAL_TEMPLATE_PATHS}


def validate_template(content):
    """Reject arbitrary flows, remote hosts, unsafe methods and executable DSLs."""
    if not isinstance(content, str) or not (30 <= len(content) <= config.NUCLEI_CUSTOM_MAX_BYTES):
        raise ValueError("Template must be YAML between 30 bytes and the configured size limit")
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as exc:
        raise ValueError("Invalid YAML syntax") from exc
    if not isinstance(data, dict) or set(data) - {"id", "info", "http"}:
        raise ValueError("Only simple HTTP templates are supported; flows, code, DNS and headless are excluded")
    if not isinstance(data.get("id"), str) or not re.fullmatch(r"[a-zA-Z0-9_-]{3,100}", data["id"]):
        raise ValueError("Template id is invalid")
    if not isinstance(data.get("info"), dict):
        raise ValueError("Template info is required")
    info = data["info"]
    if set(info) - {"name", "author", "severity", "description", "tags", "reference", "metadata"}:
        raise ValueError("Template metadata has unsupported fields")
    if not isinstance(info.get("name"), str) or len(info["name"]) > 160:
        raise ValueError("Template name is missing or too long")
    if str(info.get("severity", "")).lower() not in {"info", "low", "medium", "high", "critical"}:
        raise ValueError("Template severity is invalid")
    requests = data.get("http")
    if not isinstance(requests, list) or not 1 <= len(requests) <= config.NUCLEI_MAX_REQUESTS_PER_TEMPLATE:
        raise ValueError("Only a small number of read-only HTTP checks are allowed")
    for request in requests:
        if not isinstance(request, dict) or set(request) - {
                "method", "path", "matchers", "matchers-condition"}:
            raise ValueError("Raw requests, payloads, redirects, workflows and non-HTTP requests are disabled")
        if str(request.get("method", "GET")).upper() not in {"GET", "HEAD"}:
            raise ValueError("Only GET and HEAD are supported")
        paths = request.get("path")
        if not isinstance(paths, list) or not 1 <= len(paths) <= 2:
            raise ValueError("Each HTTP check requires one or two scoped paths")
        for url in paths:
            if not isinstance(url, str) or not SAFE_PATH.fullmatch(url) or "/.." in url:
                raise ValueError("Template path must remain under {{BaseURL}} with no dynamic host")
        matchers = request.get("matchers")
        if not isinstance(matchers, list) or not 1 <= len(matchers) <= 8:
            raise ValueError("Simple matchers are required")
        for matcher in matchers:
            if not isinstance(matcher, dict) or set(matcher) - {
                    "type", "part", "words", "regex", "status", "condition", "negative",
                    "case-insensitive", "name", "match-all"}:
                raise ValueError("Only word, status and regex matchers are supported")
            typ = matcher.get("type")
            if typ not in {"word", "status", "regex"}:
                raise ValueError("Dynamic DSL / XPath and other matcher types are disabled")
            values = matcher.get({"word": "words", "regex": "regex", "status": "status"}[typ])
            if not isinstance(values, list) or not 1 <= len(values) <= 20:
                raise ValueError("Matcher must specify a bounded value list")
            if any(not isinstance(v, (str, int)) or len(str(v)) > 350 for v in values):
                raise ValueError("Matcher value invalid or too long")
    return data["id"]


def validate_selection(default_ids, community_paths, custom_templates):
    allowed = builtins()
    if len(default_ids) > len(allowed) or any(x not in allowed for x in default_ids):
        raise ValueError("Unknown bundled template")
    if len(community_paths) > config.NUCLEI_COMMUNITY_MAX or any(
            not REPO_PATH.fullmatch(x) for x in community_paths):
        raise ValueError("Community selections must be HTTP template paths in nuclei-templates")
    if len(custom_templates) > config.NUCLEI_CUSTOM_MAX:
        raise ValueError("Too many custom templates")
    for yaml_content in custom_templates:
        validate_template(yaml_content)


async def catalog(query="", page=1):
    """Cache GitHub's recursive tree, then filter by name/path, without remote scans."""
    now = time.monotonic()
    if now >= _cache["expires"] or not _cache["paths"]:
        async with httpx.AsyncClient(timeout=18, trust_env=False) as client:
            resp = await client.get(
                f"https://api.github.com/repos/{SOURCE_REPO}/git/trees/main",
                params={"recursive": "1"},
                headers={"Accept": "application/vnd.github+json",
                         "User-Agent": "ASFB-template-browser"})
            resp.raise_for_status()
            payload = resp.json()
        paths = {x["path"] for x in payload.get("tree", [])
                 if x.get("type") == "blob" and isinstance(x.get("path"), str)
                 and REPO_PATH.fullmatch(x["path"])}
        if not paths:
            raise ValueError("Community template index is currently unavailable")
        _cache.update(expires=now + 3600, sha=payload.get("sha", "main"),
                      paths=paths, templates={})
    q = str(query).strip().lower()[:100]
    matches = sorted(path for path in _cache["paths"] if q in path.lower())
    page = max(1, min(1000, int(page)))
    size = config.NUCLEI_CATALOG_PAGE_SIZE
    return {"total": len(matches), "page": page, "page_size": size,
            "templates": matches[(page-1)*size:page*size],
            "repository": SOURCE_REPO, "truncated_upstream": False}


async def community_files(paths):
    if not paths:
        return {}
    await catalog()
    if any(p not in _cache["paths"] for p in paths):
        raise ValueError("Selected community template path not found in catalog")
    resolved = {}
    async with httpx.AsyncClient(timeout=12, trust_env=False) as client:
        for path in paths:
            if path not in _cache["templates"]:
                response = await client.get(
                    f"https://raw.githubusercontent.com/{SOURCE_REPO}/{_cache['sha']}/{path}",
                    headers={"User-Agent": "ASFB-template-browser"})
                response.raise_for_status()
                raw = response.text
                validate_template(raw)
                _cache["templates"][path] = raw
            resolved[path] = _cache["templates"][path]
    return resolved
