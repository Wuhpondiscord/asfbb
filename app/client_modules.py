"""Keyless Retire.js sampling and a bounded Wapiti profile."""
import asyncio
import json
import re
import tempfile
import time
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import config
from .coverage import profile as coverage_settings
from .pipeline import execute
from .scope import public_host
from .web_modules import same_origin, read_report, alert


from .sampling import FetchProblem, fetch_page


async def fetch_sample(url, agent, maximum):
    return await fetch_page(url, agent, maximum, public_host)


class ScriptInventory(HTMLParser):
    def __init__(self, target, maximum=None):
        super().__init__()
        self.maximum = maximum or config.RETIRE_MAX_FILE_BYTES
        self.inline_oversized = 0
        self.target, self.urls, self.inline = target, [], []
        self.current = None
        self.inline_bytes = 0

    def handle_starttag(self, tag, attrs):
        if tag != "script":
            return
        attrs = dict(attrs)
        src = attrs.get("src")
        if src:
            try:
                candidate = urljoin(self.target, src)
                if same_origin(candidate, self.target):
                    self.urls.append(candidate)
            except ValueError:
                pass
            self.current = None
        elif str(attrs.get("type", "")).lower() in ("", "text/javascript", "application/javascript", "module"):
            self.current = []

    def handle_data(self, data):
        if self.current is not None and self.inline_bytes < self.maximum * 16:
            self.current.append(data)
            self.inline_bytes += len(data.encode("utf-8"))

    def handle_endtag(self, tag):
        if tag == "script" and self.current is not None:
            code = "".join(self.current).encode("utf-8")
            if code.strip() and len(code) <= self.maximum:
                self.inline.append(code)
            elif code.strip():
                self.inline_oversized += 1
            self.current = None


def parse_retire(report, mapping):
    results = []
    entries = report.get("data", []) if isinstance(report, dict) else []
    if not isinstance(entries, list):
        return []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            continue
        target = mapping.get(str(Path(entry["file"]).resolve()))
        if target is None:
            continue
        for component in entry.get("results", []):
            if not isinstance(component, dict):
                continue
            for vuln in component.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    continue
                ids = vuln.get("identifiers") or {}
                if not isinstance(ids, dict):
                    ids = {}
                cves = ids.get("CVE") or []
                references = ", ".join(str(v) for v in cves[:8]) if isinstance(cves, list) else str(cves)
                risk = str(vuln.get("severity") or "info").title()
                if risk not in ("Low", "Medium", "High", "Critical"):
                    risk = "Informational"
                title = str(component.get("component") or "JavaScript library") + " " + str(component.get("version") or "")
                description = ("Unverified library/version advisory match. " + str(ids.get("summary") or vuln.get("details") or "") +
                               ("; " + references if references else ""))
                results.append(alert("retirejs", title, target, description, risk, references))
    return results[:config.WEB_FINDINGS_LIMIT]


async def retirejs(url, host, agent, delay, discovered, profile="current"):
    settings = coverage_settings(profile)
    limit = config.RETIRE_MAX_FILES if profile == "current" else settings["retire_files"]
    maximum = config.RETIRE_MAX_FILE_BYTES if profile == "current" else settings["retire_bytes"]
    attempts_limit = limit if profile == "current" else settings["retire_attempts"]
    reasons, samples = [], []
    policy_limits = set()
    byte_limit = settings["retire_total_bytes"]
    sampled_bytes = 0
    parser = ScriptInventory(url, maximum)
    started = time.monotonic()
    coverage = {"profile": profile, "max_files": limit, "max_file_bytes": maximum,
                "attempted_scripts": 0, "oversized": 0, "fetch_failures": 0,
                "inline_available": 0, "external_available": 0,
                "max_total_bytes": byte_limit, "missing_inventory_scripts": 0}

    def add_sample(source, body):
        nonlocal sampled_bytes
        if sampled_bytes + len(body) > byte_limit:
            policy_limits.add("total_bytes")
            return False
        samples.append((source, body))
        sampled_bytes += len(body)
        return True

    async def sample(candidate, cap):
        remaining = settings["retire_sampling_seconds"] - (time.monotonic() - started)
        if remaining <= 0:
            raise asyncio.TimeoutError()
        return await asyncio.wait_for(fetch_sample(candidate, agent, cap), remaining)

    try:
        page_cap = config.WEB_PREFLIGHT_MAX_BYTES if profile == "current" else maximum
        body, content_type, page_url = await sample(url, page_cap)
        parser = ScriptInventory(page_url, maximum)
        if "html" in content_type or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            parser.feed(body.decode("utf-8", "replace"))
        elif "javascript" in content_type or urlsplit(url).path.lower().endswith(".js"):
            add_sample(page_url, body)
    except (FetchProblem, httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
        reasons.append("Page sampling: " + (str(exc) if isinstance(exc, FetchProblem) else exc.__class__.__name__))
        coverage["fetch_failures"] += 1
    candidates = list(dict.fromkeys(parser.urls + [
        item for item in discovered if isinstance(item, str) and same_origin(item, url) and
        urlsplit(item).path.lower().endswith((".js", ".mjs"))]))
    already = {source for source, _ in samples}
    candidates = [candidate for candidate in candidates if candidate not in already]
    coverage["eligible_files"] = len(candidates) + len(parser.inline) + len(samples)
    coverage.update(external_available=len(candidates), inline_available=len(parser.inline),
                    oversized=parser.inline_oversized)
    # Keep a mix of inline and external code. Cheap inline samples should not
    # be crowded out by several oversized remote bundles.
    initial_inline = 0 if profile == "current" else min(len(parser.inline), limit // 2)
    for body in parser.inline[:initial_inline]:
        add_sample(parser.target, body)
    attempted = 0
    for candidate in candidates:
        if len(samples) >= limit or attempted >= attempts_limit:
            policy_limits.add("file_or_attempt_count")
            break
        if time.monotonic() - started + max(config.REQUEST_DELAY_MIN, float(delay)) >= settings["retire_sampling_seconds"]:
            reasons.append("JavaScript sampling time budget reached")
            policy_limits.add("sampling_time")
            break
        await asyncio.sleep(max(config.REQUEST_DELAY_MIN, float(delay)))
        attempted += 1
        coverage["attempted_scripts"] = attempted
        try:
            body, content_type, sampled_url = await sample(candidate, maximum)
            if "html" in content_type or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
                raise FetchProblem("HTML returned instead of JavaScript")
            if "javascript" not in content_type and not urlsplit(candidate).path.lower().endswith((".js", ".mjs")):
                raise FetchProblem("Response not identified as JavaScript")
            if body:
                add_sample(sampled_url, body)
        except (FetchProblem, httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
            detail = str(exc) if isinstance(exc, FetchProblem) else exc.__class__.__name__
            if detail in ("HTTP 404", "HTTP 410") and candidate not in parser.urls:
                coverage["missing_inventory_scripts"] += 1
                coverage["eligible_files"] -= 1
                continue
            if "byte limit" in detail:
                coverage["oversized"] += 1
                policy_limits.add("file_bytes")
            else:
                coverage["fetch_failures"] += 1
            reasons.append("Script sampling: " + detail)
    remaining_inline = parser.inline[initial_inline:]
    inline_limit = max(0, limit - len(samples))
    for body in remaining_inline[:inline_limit]:
        add_sample(parser.target, body)
    omitted_external = max(0, len(candidates) - attempted)
    omitted_inline = max(0, len(remaining_inline) - inline_limit)
    if omitted_external:
        reasons.append("JavaScript URL sample limited to " + str(attempted))
        policy_limits.add("external_sample_count")
    if omitted_inline:
        reasons.append("Inline JavaScript sample limited")
        policy_limits.add("inline_sample_count")
    if parser.inline_oversized:
        reasons.append("Oversized inline JavaScript excluded")
        policy_limits.add("inline_bytes")
    if "total_bytes" in policy_limits:
        reasons.append("Aggregate JavaScript byte budget reached")
    coverage.update(sampled_bytes=sampled_bytes, policy_limits=sorted(policy_limits), sampled_files=len(samples), omitted_external=omitted_external,
                    omitted_inline=omitted_inline)
    if not samples:
        reason = "; ".join(reasons) or "No same-origin or inline JavaScript available"
        return {"status": "skipped", "source": "retirejs", "alerts": [], "target": url,
                "reason": reason, "coverage": coverage, "output": "Retire.js skipped: " + reason}
    with tempfile.TemporaryDirectory(prefix="asfb-retirejs-") as tmp:
        root = Path(tmp)
        assets = root / "assets"
        assets.mkdir()
        mapping = {}
        for index, (source, body) in enumerate(samples):
            folder = assets / str(index)
            folder.mkdir()
            name = re.sub(r"[^A-Za-z0-9_.-]", "_", Path(urlsplit(source).path).name)[:100]
            if not name.lower().endswith(".js"):
                name = "sample.js"
            filename = folder / name
            filename.write_bytes(body)
            mapping[str(filename.resolve())] = source
        report_path = str(root / "report.json")
        ignore_path = root / "ignore.json"
        ignore_path.write_text("[]", encoding="utf-8")
        rows, status = await execute([
            "/usr/local/bin/node", "/opt/retire/lib/cli.js", "--path", str(assets),
            "--jsrepo", "/opt/retire-db/jsrepository-v5.json", "--cachedir", str(root / "cache"),
            "--ignorefile", str(ignore_path), "--outputformat", "json",
            "--outputpath", report_path, "--exitwith", "13"],
            config.RETIRE_TIMEOUT_SECONDS)
        report = read_report(report_path)
        findings = parse_retire(report, mapping)
    diagnostic = [row[:180] for row in rows if row.startswith(("[stderr]", "[diagnostic]"))]
    code13 = any(row.strip() == "[diagnostic] Process exit code: 13" for row in rows)
    if code13 and isinstance(report, dict) and findings and not report.get("errors"):
        status = "findings"
        diagnostic = [s for s in diagnostic if s != "[diagnostic] Process exit code: 13"]
    if not isinstance(report, dict) or not isinstance(report.get("data"), list):
        if status == "completed":
            status = "failed"
        reasons.append("No readable Retire.js JSON report")
    elif report.get("errors"):
        reasons.append("Retire.js reported scanner errors")
        if status in ("completed", "findings"):
            status = "partial" if findings else "failed"
    execution_state = status
    early_stop = (bool(policy_limits) and coverage["fetch_failures"] == 0
                  and status in ("completed", "findings") and isinstance(report, dict)
                  and not report.get("errors"))
    if reasons and status in ("completed", "findings") and not early_stop:
        status = "partial"
    if early_stop:
        status = "findings" if findings else "completed"
        reasons.insert(0, "Early stop: configured JavaScript sampling limits; coverage is incomplete")
    coverage["engine_status"] = execution_state
    coverage["coverage_limited"] = bool(reasons)
    reasons.extend(diagnostic)
    if coverage["missing_inventory_scripts"]:
        reasons.append(str(coverage["missing_inventory_scripts"]) + " unavailable inventory-only script URLs excluded (HTTP 404/410)")
    reasons.append("Bounded JavaScript sample using the image-bundled advisory snapshot")
    return {"status": status, "source": "retirejs", "target": url, "alerts": findings,
            "sampled_files": len(samples), "coverage": coverage,
            **({"early_stop": True, "stop_reason": "sampling_policy", "coverage_complete": False} if early_stop else {}),
            "reason": "; ".join(dict.fromkeys(reasons))[:500],
            "output": f"Retire.js: engine {execution_state}; {len(samples)}/{coverage['eligible_files']} eligible files sampled; {len(findings)} unverified advisory matches; coverage: {'limited' if coverage['coverage_limited'] else 'complete'}"}


def parse_wapiti(report, target):
    findings = []
    groups = report.get("vulnerabilities", {}) if isinstance(report, dict) else {}
    if not isinstance(groups, dict):
        return []
    risks = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
    for category, entries in groups.items():
        if not isinstance(entries, list):
            continue
        for item in entries:
            if not isinstance(item, dict) or str(item.get("method", "GET")).upper() not in ("GET", "HEAD"):
                continue
            candidate = urljoin(target, str(item.get("path") or target))
            if same_origin(candidate, target):
                findings.append(alert("wapiti", "Wapiti: " + str(category), candidate,
                                      item.get("info") or "Unverified Wapiti observation",
                                      risks.get(item.get("level"), "Informational"),
                                      item.get("module", "")))
    return findings[:config.WEB_FINDINGS_LIMIT]


async def wapiti(url, host, agent, delay):
    with tempfile.TemporaryDirectory(prefix="asfb-wapiti-") as tmp:
        root = Path(tmp)
        report_path, stats_path = str(root / "report.json"), str(root / "stats.json")
        args = ["/opt/wapiti/bin/python", "/app/app/wapiti_runner.py",
                "--asfb-stats", stats_path, "--asfb-delay", str(delay),
                "--asfb-budget", str(config.WAPITI_REQUEST_LIMIT),
                "-u", url, "--scope", "url", "-m", "csp,http_headers,cookieflags",
                "--headless", "no", "--tasks", "1", "-d", "0",
                "--max-links-per-page", "1", "--max-files-per-dir", "1",
                "--max-scan-time", str(config.WAPITI_SCAN_SECONDS), "--max-attack-time", "5",
                "--max-parameters", "5", "-t", "5", "-A", agent, "--verify-ssl", "1",
                "--store-session", str(root / "session"), "--store-config", str(root / "config"),
                "--no-bugreport", "-f", "json", "-o", report_path]
        rows, status = await execute(args, config.WAPITI_TIMEOUT_SECONDS)
        report, stats = read_report(report_path), read_report(stats_path)
    findings = parse_wapiti(report, url)
    reasons = [row[:180] for row in rows if row.startswith(("[stderr]", "[diagnostic]"))]
    if not isinstance(report, dict) or not isinstance(report.get("vulnerabilities"), dict):
        if status == "completed":
            status = "failed"
        reasons.append("No valid Wapiti JSON report produced")
    if isinstance(stats, dict):
        if stats.get("limit_reached") or stats.get("response_limited") or stats.get("blocked"):
            if status == "completed":
                status = "partial"
            reasons.append("Origin/method/request/response guard limited coverage")
    else:
        if status == "completed":
            status = "partial"
        reasons.append("Wapiti guard telemetry unavailable")
    if any("maximum scan time" in row.lower() or "max scan time" in row.lower() for row in rows):
        if status == "completed":
            status = "partial"
        reasons.append("Wapiti scan deadline reached")
    reasons.append("Limited GET/HEAD CSP, header and cookie profile; no browser or injection modules")
    return {"status": status, "source": "wapiti", "target": url, "alerts": findings,
            "request_count": stats.get("requests", 0) if isinstance(stats, dict) else 0,
            "reason": "; ".join(reasons)[:500],
            "output": f"Wapiti: {len(findings)} unverified findings; status: {status}"}
