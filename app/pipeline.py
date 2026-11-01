import asyncio
import json
import re
import os
import tempfile
import time
from urllib.parse import urlsplit
from . import config

def clean_output(data):
    value = data.decode("utf-8", "replace") if isinstance(data, bytes) else str(data)
    return re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", value).replace("\r", "\n")

async def execute(args, timeout):
    try:
        p = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    except FileNotFoundError:
        return ["Binary missing"], "unavailable"
    try:
        out, err = await asyncio.wait_for(p.communicate(), timeout)
    except asyncio.CancelledError:
        # Cancelling a scan must terminate its tool process, not only its Python task.
        if p.returncode is None:
            try:
                p.kill()
            except ProcessLookupError:
                pass
        await p.communicate()
        raise
    except asyncio.TimeoutError:
        p.kill()
        out, err = await p.communicate()
        lines = clean_output(out).splitlines()[:config.PROCESS_OUTPUT_MAX_LINES]
        lines += ["[stderr] " + line[:200] for line in clean_output(err).splitlines()[-8:]]
        lines.append("[diagnostic] Deadline exceeded after " + str(timeout) + " seconds; partial output retained")
        return lines, "timeout"
    lines = clean_output(out).splitlines()[:500]
    if p.returncode:
        lines += ["[stderr] " + x[:200] for x in clean_output(err).splitlines()[-8:]]
        lines.append("[diagnostic] Process exit code: " + str(p.returncode))
    return lines, "completed" if p.returncode == 0 else "failed"

def in_host(url, host):
    try:
        p = urlsplit(url)
        return p.scheme in ("http", "https") and p.hostname == host and not p.username and not p.password
    except ValueError:
        return False

async def katana(url, host, agent, depth=1, limit=None):
    rows, status = await execute(["/usr/local/bin/katana", "-u", url, "-d", str(max(1,min(int(depth),5))), "-fs", "fqdn", "-c", "1",
        "-p", "1", "-rl", "1", "-ct", "30s", "-timeout", "8", "-retry", "0",
        "-H", "User-Agent: " + agent, "-silent", "-duc"], config.KATANA_TIMEOUT_SECONDS)
    return {"status": status, "endpoints": list(dict.fromkeys(x.strip() for x in rows if in_host(x.strip(), host)))[:max(1, min(int(limit or config.ENDPOINT_LIMIT_DEFAULT), config.ENDPOINT_LIMIT_MAX))], "reason": " | ".join(x[:160] for x in rows if x.startswith("[diagnostic]") or x.startswith("[stderr]"))[:350]}

async def nuclei(url, host, agent, urls=None):
    """Run configured low-impact templates against selected exact-host URLs."""
    targets = list(dict.fromkeys(
        candidate for candidate in (urls if urls is not None else [url])
        if isinstance(candidate, str) and in_host(candidate, host)
    ))[:config.NUCLEI_TARGET_LIMIT]
    templates = list(config.NUCLEI_TEMPLATE_PATHS)
    if not targets:
        return {"status": "skipped", "alerts": [], "templates": [],
                "targets_checked": 0, "reason": "No exact-host targets"}
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False,
                                     prefix="asfb-nuclei-", suffix=".txt") as handle:
        target_file = handle.name
        handle.write("\n".join(targets) + "\n")
    try:
        args = ["/usr/local/bin/nuclei", "-l", target_file]
        for template in templates:
            args.extend(["-t", template])
        args.extend(["-rl", "1", "-c", "1", "-bs", "1", "-timeout", "8",
                     "-retries", "0", "-jsonl", "-silent", "-duc", "-dr", "-or",
                     "-H", "User-Agent: " + agent])
        rows, status = await execute(args, config.NUCLEI_TIMEOUT_SECONDS)
    finally:
        try:
            os.unlink(target_file)
        except FileNotFoundError:
            pass
    findings = []
    for row in rows:
        try:
            obj = json.loads(row)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        matched_url = obj.get("matched-at") or obj.get("matched") or obj.get("host") or url
        if not in_host(matched_url, host):
            continue
        info = obj.get("info") or {}
        if not isinstance(info, dict):
            info = {}
        findings.append({
            "name": info.get("name") or obj.get("template-id") or "Template match",
            "risk": str(info.get("severity", "info")).title().replace("Info", "Informational"),
            "confidence": "Low", "url": matched_url,
            "description": str(info.get("description") or "")[:1000],
            "source": "nuclei", "template_id": obj.get("template-id")
        })
    diag = " | ".join(line[:180] for line in rows
                      if line.startswith(("[stderr]", "[diagnostic]")))
    return {"status": status, "alerts": findings[:config.NUCLEI_FINDINGS_LIMIT],
            "templates": [t.rsplit("/", 1)[-1].removesuffix(".yaml") for t in templates],
            "targets_checked": len(targets), "reason": diag[:500]}

_gau_failures = 0
_gau_disabled_until = 0.0

async def gau(url, host, limit=None):
    """Query isolated archive providers and report partial provider coverage."""
    global _gau_failures, _gau_disabled_until
    maximum = max(1, min(int(limit or config.ENDPOINT_LIMIT_DEFAULT), config.ENDPOINT_LIMIT_MAX))
    providers = (config.GAU_PROVIDER,) + tuple(config.GAU_FALLBACK_PROVIDERS)
    collected = []
    provider_results = []
    now = time.monotonic()
    for provider in dict.fromkeys(providers):
        if provider == config.GAU_PROVIDER and now < _gau_disabled_until:
            provider_results.append({"provider": provider, "status": "unavailable",
                                     "reason": "Circuit breaker cooldown"})
            continue
        args = ["/usr/local/bin/gau", "--threads", "1",
                "--timeout", str(config.GAU_HTTP_TIMEOUT_SECONDS),
                "--retries", "0", "--providers", provider, host]
        rows, status = await execute(args, config.GAU_PROVIDER_DEADLINE_SECONDS)
        urls = [value.strip() for value in rows
                if isinstance(value, str) and in_host(value.strip(), host)]
        collected.extend(urls)
        diagnostics = " | ".join(value[:180] for value in rows
                                 if value.startswith(("[stderr]", "[diagnostic]")))
        provider_results.append({"provider": provider, "status": status,
                                 "urls": len(urls), "reason": diagnostics[:300]})
        if provider == config.GAU_PROVIDER:
            if status in ("timeout", "failed", "unavailable"):
                _gau_failures += 1
                if _gau_failures >= config.GAU_BREAKER_FAILURES:
                    _gau_disabled_until = time.monotonic() + config.GAU_BREAKER_COOLDOWN_SECONDS
                    _gau_failures = 0
            else:
                _gau_failures = 0
                _gau_disabled_until = 0.0
        if status == "completed" and urls and not config.GAU_AGGREGATE_ALL_PROVIDERS:
            break
    unique = list(dict.fromkeys(collected))[:maximum]
    statuses = [item["status"] for item in provider_results]
    if statuses and all(s == "completed" for s in statuses):
        final_status = "completed"
    elif unique or any(s == "completed" for s in statuses):
        final_status = "partial"
    elif "timeout" in statuses:
        final_status = "timeout"
    elif "failed" in statuses:
        final_status = "failed"
    else:
        final_status = "unavailable"
    problems = [f'{item["provider"]}: {item["status"]}' +
                (f' ({item.get("reason")})' if item.get("reason") else "")
                for item in provider_results if item["status"] != "completed"]
    return {"status": final_status, "endpoints": unique, "providers": provider_results,
            "reason": " | ".join(problems)[:500],
            "summary": f"Archive sources: {len(provider_results)}; scoped URLs: {len(unique)}"}

async def probe(urls, host, agent, limit=1):
    """Probe exact-host URLs in bounded batches, avoiding one subprocess per URL."""
    targets = list(dict.fromkeys(
        u for u in urls if isinstance(u, str) and "\n" not in u and "\r" not in u
        and in_host(u, host)))[:max(1, min(int(limit), config.HTTPX_LIMIT_MAX))]
    if not targets:
        return {"status": "completed", "probes": [], "submitted": 0}
    all_rows = []
    failures = []
    for start in range(0, len(targets), config.HTTPX_BATCH_SIZE):
        subset = targets[start:start + config.HTTPX_BATCH_SIZE]
        path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                                             prefix="asfb-httpx-", suffix=".txt",
                                             delete=False) as handle:
                path = handle.name
                handle.write("\n".join(subset) + "\n")
            args = ["/usr/local/bin/pd-httpx", "-l", path, "-json", "-silent",
                    "-rl", "1", "-threads", "1", "-timeout", "8", "-retries", "0",
                    "-H", "User-Agent: " + agent, "-no-color"]
            rows, status = await execute(
                args, config.HTTPX_TIMEOUT_SECONDS + len(subset) * 2)
            all_rows.extend(rows)
            if status != "completed":
                failures.append(status)
        finally:
            if path is not None:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
    probes = []
    for line in all_rows:
        try:
            item = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(item, dict):
            continue
        found = item.get("url", "")
        if in_host(found, host):
            probes.append({"url": found, "status_code": item.get("status_code"),
                           "title": str(item.get("title") or "")[:160],
                           "webserver": str(item.get("webserver") or "")[:120],
                           "source": "httpx"})
    reason = " | ".join(x[:160] for x in all_rows
                        if x.startswith("[stderr]") or x.startswith("[diagnostic]"))[:350]
    return {"status": failures[0] if failures else "completed",
            "probes": probes[:config.HTTPX_LIMIT_MAX], "submitted": len(targets),
            "reason": reason}
