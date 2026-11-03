"""Opt-in single-target verification stages. Output is evidence, not confirmed findings."""
import json
import tempfile
from pathlib import Path
import re
from collections import Counter
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from .pipeline import execute, in_host
from . import config
from .coverage import profile as coverage_settings

ACTIVE_MODULES = {"ffuf", "sqlmap", "dalfox", "arjun"}

def command(module, url, host, profile="current"):
    settings = coverage_settings(profile)
    if not in_host(url, host):
        raise ValueError("Review URL must stay on the selected exact host")
    if module == "ffuf":
        parts = urlsplit(url)
        discovery_url = urlunsplit(parts._replace(path=parts.path.rstrip("/") + "/FUZZ",
                                                   query="", fragment=""))
        return ["/usr/local/bin/ffuf", "-u", discovery_url,
                "-w", "/app/app/wordlists/paths.txt", "-t", "1", "-rate", "1",
                "-maxtime", "25", "-timeout", "5", "-noninteractive", "-json"]
    if module == "arjun":
        return ["/opt/asfb-venv/bin/python", "-m", "app.arjun_runner", "-u", url, "-t", "1",
                "-T", str(config.ARJUN_HTTP_TIMEOUT_SECONDS), "-w", config.ARJUN_WORDLIST, "-c", str(config.ARJUN_CHUNK_SIZE), "--rate-limit", str(config.ARJUN_RATE_LIMIT), "--disable-redirects"]
    if module == "dalfox":
        # Dalfox's --timeout limits a request, not an entire stage. The scan
        # stage also gets an internal deadline; external process timeout remains
        # authoritative for discovery/preflight or network stalls.
        return ["/opt/asfb-venv/bin/python", "-m", "app.dalfox_runner", "/usr/local/bin/dalfox", "scan", url, "--workers", str(config.DALFOX_WORKERS),
                "--timeout", str(config.DALFOX_HTTP_TIMEOUT_SECONDS),
                "--scan-timeout", str(config.DALFOX_SCAN_TIMEOUT_SECONDS if profile == "current" else settings["dalfox_scan_seconds"]),
                "--max-payloads-per-param", str(config.DALFOX_PAYLOADS_PER_PARAM if profile == "current" else settings["dalfox_payloads"]),
                "--rate-limit", str(config.DALFOX_RATE_LIMIT),
                "--skip-mining", "--skip-waf-probe", "--skip-reflection-header",
                "--skip-reflection-cookie", "--skip-reflection-path", "--no-color", "-f", "json"] + (
                    ["--skip-discovery", "--skip-xss-scanning"] if not urlsplit(url).query else [])
    if module == "sqlmap":
        if not urlsplit(url).query:
            raise ValueError("SQLmap review requires a parameterized URL")
        names = [name for name, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)
                 if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$-]{0,79}", name)]
        if not names:
            raise ValueError("SQLmap review requires a supported GET parameter")
        return ["python3", "/opt/sqlmap/sqlmap.py", "-u", url, "-p", names[0],
                "--batch", "--level=1", "--risk=1", "--threads=1",
                "--timeout=5", "--retries=0", "--technique=B",
                "--smart", "--disable-coloring", "--ignore-redirects", "--delay=1"]
    raise ValueError("Unsupported review module")

def ffuf_discoveries(lines, host):
    """Only preserve directly observed same-host success responses as URLs."""
    found = []
    for line in lines:
        try:
            item = json.loads(line)
        except (TypeError, ValueError):
            continue
        if (isinstance(item, dict) and item.get("status") in (200, 201, 202, 204)
                and isinstance(item.get("url"), str) and in_host(item["url"], host)):
            found.append(item["url"])
    return list(dict.fromkeys(found))[:100]


def summarize_review(module, lines):
    if module == "ffuf":
        results = []
        for line in lines:
            try:
                item = json.loads(line)
            except (ValueError, TypeError):
                continue
            if isinstance(item, dict) and isinstance(item.get("status"), int) and item.get("url"):
                results.append(item)
        if results:
            redirects = Counter((item.get("status"), item.get("redirectlocation")) for item in results
                                if 300 <= item["status"] < 400 and item.get("redirectlocation"))
            common = {pair for pair, count in redirects.items() if count >= 3}
            kept = [item for item in results if (item.get("status"), item.get("redirectlocation")) not in common]
            return ("\n".join(f'{item["status"]} {item["url"]} -> {item.get("redirectlocation") or "-"}' for item in kept[:100])
                    + (f"\nSuppressed {len(results)-len(kept)} repeated redirects to the same destination; likely wildcard redirect behavior." if common else "")).strip()
    if module == "arjun":
        cleaned = [re.sub(r"\s+", " ", line).strip() for line in lines
                   if "Processing chunks:" not in line]
        return "\n".join(line for line in cleaned if line)[-2500:]
    return "\n".join(lines)[:5000]

def read_arjun_results(path, host):
    """Parse Arjun's JSON export without trusting URLs outside the exact host."""
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8")[:500000])
    except (OSError, ValueError):
        return []
    if not isinstance(payload, dict):
        return []
    found = []
    for candidate, data in payload.items():
        if not in_host(candidate, host) or not isinstance(data, dict):
            continue
        method = str(data.get("method") or "GET").upper()
        for entry in data.get("params", []):
            name = entry.get("name") if isinstance(entry, dict) else entry
            if isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_.$-]{1,100}", name):
                found.append({"url": candidate, "method": method, "name": name,
                              "source": "arjun"})
    return found[:100]


def choose_arjun_target(primary, discovered, host):
    """Prefer an already-discovered parameterized or API URL on the same exact host."""
    if not config.ARJUN_PREFER_DYNAMIC_ENDPOINTS:
        return primary
    candidates = [u for u in discovered if isinstance(u, str) and in_host(u, host)]
    def score(value):
        parts = urlsplit(value)
        path = parts.path.lower()
        if parts.query:
            return 3
        if "/api/" in path or path.endswith((".php", ".aspx", ".jsp", ".cgi")):
            return 2
        if path.endswith((".js", ".css", ".svg", ".png", ".jpg", ".woff", ".json", ".map", ".ico", ".webmanifest")):
            return -1
        return 0
    best = max(candidates, key=score, default=primary)
    return best if score(best) > score(primary) else primary


def choose_dalfox_target(primary, parameters, host):
    """Use one same-host GET parameter from Arjun; retain the original query.

    Avoid inventing parameters: a bare URL remains eligible for AST-only review
    while Dalfox's expensive automatic parameter mining stays disabled.
    """
    candidates = []
    for item in parameters or []:
        if not isinstance(item, dict) or str(item.get("method", "GET")).upper() != "GET":
            continue
        candidate = item.get("url")
        name = item.get("name")
        if (not isinstance(candidate, str) or not in_host(candidate, host) or
            not isinstance(name, str) or
            not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$-]{0,79}", name)):
            continue
        parts = urlsplit(candidate)
        params = parse_qsl(parts.query, keep_blank_values=True)
        if any(k == name for k, _ in params):
            selected = candidate
        else:
            params.append((name, "asfb-review"))
            selected = urlunsplit(parts._replace(query=urlencode(params)))
        if in_host(selected, host):
            candidates.append(selected)
    return candidates[0] if candidates else primary


def same_review_origin(candidate, primary, host):
    if not isinstance(candidate, str):
        return False
    try:
        a, b = urlsplit(candidate), urlsplit(primary)
        return (in_host(candidate, host) and a.scheme == b.scheme and
                (a.port or (443 if a.scheme == "https" else 80)) ==
                (b.port or (443 if b.scheme == "https" else 80)))
    except (TypeError, ValueError):
        return False


def choose_sqlmap_target(primary, discovered, parameters, host):
    """Use one observed same-origin GET query/parameter, retaining known values."""
    for candidate in [primary] + list(discovered or []):
        if not isinstance(candidate, str) or not same_review_origin(candidate, primary, host):
            continue
        parts = urlsplit(candidate)
        if any(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.$-]{0,79}", name)
               for name, _ in parse_qsl(parts.query, keep_blank_values=True)):
            return parts._replace(fragment="").geturl()
    eligible = [item for item in parameters or [] if isinstance(item, dict) and
                same_review_origin(item.get("url"), primary, host)]
    return choose_dalfox_target(primary, eligible, host)

def dalfox_coverage(meta):
    """Keep compact coverage counters/status codes; omit raw requests and errors."""
    result = {}
    if isinstance(meta.get("incomplete"), bool):
        result["incomplete"] = meta["incomplete"]
    for key in ("total_requests", "failed_requests", "scan_duration_ms", "findings_count",
                "targets_unparsable"):
        value = meta.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            result[key] = value
    targets = []
    for item in meta.get("target_summary", []) if isinstance(meta.get("target_summary"), list) else []:
        if not isinstance(item, dict):
            continue
        target = {}
        status, code = item.get("status"), item.get("error_code")
        if status in ("completed", "clean", "findings", "incomplete", "error", "cancelled", "skipped", "failed"):
            target["status"] = status
        if isinstance(code, (int, str)) and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", str(code)):
            target["error_code"] = code
        if target:
            targets.append(target)
    if targets:
        result["target_summary"] = targets[:10]
    return result


def dalfox_incomplete_reason(meta):
    parts = ["Dalfox reports incomplete results"]
    if "total_requests" in meta:
        parts.append("requests=" + str(meta["total_requests"]))
    if "failed_requests" in meta:
        parts.append("failed requests=" + str(meta["failed_requests"]))
    statuses = [str(item.get("error_code") or item.get("status"))
                for item in meta.get("target_summary", [])]
    if statuses:
        parts.append("target status=" + ",".join(dict.fromkeys(statuses)))
    if len(parts) == 1:
        parts.append("tool report did not include a specific cause")
    return "; ".join(parts)


def read_dalfox_report(path, host, default_url):
    """Parse Dalfox v3 JSON output and discard out-of-scope finding URLs."""
    try:
        report = json.loads(Path(path).read_text(encoding="utf-8")[:2_000_000])
    except (OSError, ValueError):
        return [], {}
    if not isinstance(report, dict):
        return [], {}
    meta = dalfox_coverage(report.get("meta") if isinstance(report.get("meta"), dict) else {})
    findings = []
    for item in report.get("findings", []):
        if not isinstance(item, dict):
            continue
        candidate = item.get("data") or default_url
        if not isinstance(candidate, str) or not in_host(candidate, host):
            continue
        tier = str(item.get("type") or "unknown").upper()
        evidence = str(item.get("evidence") or item.get("message_str") or "")[:350]
        findings.append({
            "source": "dalfox", "name": "Dalfox XSS candidate (" + tier + ")",
            "url": candidate, "tier": tier,
            "risk": str(item.get("severity") or "info").title().replace("Info", "Informational"),
            "confidence": "Medium" if tier == "V" else "Low",
            "description": ("Unverified automated " + tier + " signal; " + evidence)[:600],
            "parameter": str(item.get("param") or "")[:80],
        })
    return findings[:config.DALFOX_FINDINGS_LIMIT], meta


async def review(module, url, host, profile="current"):
    settings = coverage_settings(profile)
    if module == "sqlmap" and not urlsplit(url).query:
        return {"source": module, "status": "skipped", "target": url, "output": "", "reason": "URL has no query parameters"}
    args = command(module, url, host, profile)
    parameters = []
    dalfox_findings, dalfox_meta = [], {}
    arjun_meta = {}
    early_stop = False
    stop_reason = ""
    if module == "arjun":
        with tempfile.TemporaryDirectory(prefix="asfb-arjun-") as tmp:
            export_path = str(Path(tmp) / "parameters.json")
            guard_path = str(Path(tmp) / "guard.json")
            lines, status = await execute(args + ["--asfb-report", guard_path, "-oJ", export_path],
                                          config.ARJUN_TIMEOUT_SECONDS)
            parameters = read_arjun_results(export_path, host)
            try:
                raw = json.loads(Path(guard_path).read_text())
                arjun_meta = {key: raw[key] for key in ("status", "stop_reason", "http_status", "requests",
                                                       "early_stop", "coverage_complete") if key in raw}
            except (OSError, ValueError, TypeError):
                pass
            if status == "completed" and arjun_meta.get("status") in ("completed", "partial", "failed"):
                status = arjun_meta["status"]
                early_stop = arjun_meta.get("early_stop") is True
                stop_reason = arjun_meta.get("stop_reason", "")
    elif module == "dalfox":
        with tempfile.TemporaryDirectory(prefix="asfb-dalfox-") as tmp:
            path = str(Path(tmp) / "findings.json")
            lines, status = await execute(args + ["-o", path], config.DALFOX_TIMEOUT_SECONDS if profile == "current" else settings["dalfox_timeout"])
            dalfox_findings, dalfox_meta = read_dalfox_report(path, host, url)
    elif module == "sqlmap":
        with tempfile.TemporaryDirectory(prefix="asfb-sqlmap-") as tmp:
            lines, status = await execute(args + ["--output-dir", tmp, "--flush-session"],
                                          config.PROCESS_TIMEOUT_SECONDS)
    else:
        lines, status = await execute(args, config.PROCESS_TIMEOUT_SECONDS)
    has_evidence = module == "dalfox" and any("[POC]" in line for line in lines)
    exit_code = next((int(line.rsplit(":", 1)[1].strip()) for line in lines
                      if line.startswith("[diagnostic] Process exit code:")
                      and line.rsplit(":", 1)[1].strip().isdigit()), None)
    if module == "dalfox":
        if dalfox_meta.get("incomplete") and status not in ("timeout", "unavailable"):
            status = "partial"
        elif exit_code == 1 or (dalfox_findings and status == "completed"):
            status = "findings"
        elif has_evidence and status == "failed":
            status = "partial"
    if (module == "dalfox" and dalfox_meta.get("incomplete") is True
            and "[asfb] dalfox_scan_budget" in lines and exit_code in (None, 1)
            and status not in ("timeout", "unavailable")
            and bool(dalfox_meta.get("target_summary"))
            and all(item.get("status") in ("incomplete", "findings") for item in dalfox_meta["target_summary"])
            and dalfox_meta.get("failed_requests") == 0
            and not any(item.get("error_code") for item in dalfox_meta.get("target_summary", []))):
        status = "findings" if dalfox_findings else "completed"
        early_stop, stop_reason = True, "native_time_budget"
    # Code 1 is an expected Dalfox finding outcome, not an error diagnostic.
    displayed_lines = [line for line in lines
                       if line != "[asfb] dalfox_scan_budget" and not (module == "dalfox" and status == "findings"
                               and line.strip() == "[diagnostic] Process exit code: 1")]
    reason = " | ".join(line[:180] for line in displayed_lines
                        if line.startswith(("[stderr]", "[diagnostic]")))
    if not reason and status == "failed":
        reason = f"{module} exited unsuccessfully; inspect its output"
    if not reason and status == "partial" and has_evidence:
        reason = "Unverified findings were returned; runtime verification required. The tool did not finish cleanly"
    if module == "dalfox" and dalfox_findings:
        output = "\n".join(
            f'{i + 1}. {item["name"]} | {item["url"]} | confidence={item["confidence"]}'
            for i, item in enumerate(dalfox_findings[:30]))
    else:
        output = summarize_review(module, displayed_lines)
    if module == "dalfox" and dalfox_meta.get("incomplete") and not early_stop:
        reason = (dalfox_incomplete_reason(dalfox_meta) + ("; " + reason if reason else ""))[:500]
        if not output:
            output = reason
    if module == "arjun" and arjun_meta.get("stop_reason"):
        reason = {"http_unavailable": "Target returned an unhealthy HTTP response",
                  "endpoint_unavailable": "Selected endpoint is unavailable",
                  "request_failed": "Target request failed",
                  "content_unavailable": "Response is not a supported text endpoint",
                  "native_error": "Arjun native engine error"}.get(stop_reason or arjun_meta["stop_reason"],
                                                                   "Configured transport policy stopped the profile")
        if arjun_meta.get("http_status"):
            reason += " (HTTP " + str(arjun_meta["http_status"]) + ")"
        output = "Arjun guarded parameter review; " + str(arjun_meta.get("requests", 0)) + " requests; " + reason
    if early_stop:
        if module == "dalfox" and not dalfox_findings:
            output = "Dalfox stopped at its configured native scan budget; partial coverage retained"
        reason = "Early stop: " + ("native scan time budget reached" if module == "dalfox" else reason) + "; coverage is incomplete"
    if module == "dalfox" and not early_stop and status == "completed" and not urlsplit(url).query:
        # This is a deliberate coverage tradeoff: DOM AST runs, dictionary
        # mining doesn't. Don't imply an exhaustive reflected-XSS assessment.
        reason = "Bounded DOM/URL review; no query parameters supplied. Dictionary mining is disabled."
    return {"source": module, "status": status, "target": url,
            "coverage": {"profile": profile, "budget_seconds": settings["dalfox_scan_seconds"],
                         "payloads_per_parameter": settings["dalfox_payloads"]} if module == "dalfox" else {},
            "exit_code": exit_code,
            "metadata": arjun_meta if module == "arjun" else dalfox_meta,
            **({"early_stop": True, "stop_reason": stop_reason, "coverage_complete": False} if early_stop else {}),
            "findings": dalfox_findings,
            "parameters": parameters,
            "endpoints": ffuf_discoveries(lines, host) if module == "ffuf" else [],
            "output": output,
            "reason": reason[:500],
            "note": "Unverified tool output. Confirm impact manually before reporting."}