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
    # communicate() owns the pipe readers. Cancelling it at the deadline and
    # calling it again loses bytes already consumed by those readers.
    communication = asyncio.create_task(p.communicate())
    timed_out = False

    def stop_process():
        if p.returncode is None:
            try:
                p.kill()
            except ProcessLookupError:
                # The process may exit between the returncode check and kill.
                pass

    try:
        out, err = await asyncio.wait_for(asyncio.shield(communication), timeout)
    except asyncio.CancelledError:
        # Keep the same pipe readers alive while terminating the tool.
        stop_process()
        await communication
        raise
    except asyncio.TimeoutError:
        timed_out = True
        stop_process()
        out, err = await communication
    lines = clean_output(out).splitlines()[:config.PROCESS_OUTPUT_MAX_LINES]
    if timed_out or p.returncode:
        lines += ["[stderr] " + line[:200] for line in clean_output(err).splitlines()[-8:]]
    if timed_out:
        lines.append("[diagnostic] Deadline exceeded after " + str(timeout) + " seconds; partial output retained")
        return lines, "timeout"
    if p.returncode:
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

async def nuclei(url, host, agent, urls=None, default_ids=None,
                 community_templates=None, custom_templates=None):
    """Run configured low-impact templates against selected exact-host URLs."""
    from .nuclei_catalog import builtins
    options = builtins()
    selected_ids = list(config.NUCLEI_DEFAULT_IDS) if default_ids is None else default_ids
    discovered_urls = list(dict.fromkeys(
        candidate for candidate in (urls if urls is not None else [url])
        if isinstance(candidate, str) and in_host(candidate, host)
    ))
    # Exposure profiles probe fixed paths relative to the web origin. Running them
    # on /app/main.js or /manifest.json can produce misleading or wasted requests.
    origin = urlsplit(url)._replace(path="/", query="", fragment="").geturl()
    exposure_profile = any(name.startswith("bounty-ultimate-") for name in selected_ids)
    if exposure_profile:
        targets = [origin]
        scope_strategy = "origin-only exposure profile"
    else:
        def target_priority(candidate):
            parts = urlsplit(candidate)
            path = parts.path.lower()
            static = path.endswith((".js", ".css", ".json", ".map", ".svg", ".png",
                                    ".jpg", ".jpeg", ".gif", ".woff", ".woff2", ".ico", ".pdf"))
            return (0 if candidate.rstrip("/") == origin.rstrip("/") else 1,
                    2 if static else 0, len(path))
        targets = sorted(dict.fromkeys([origin] + discovered_urls), key=target_priority)
        scope_strategy = "prioritized page sample"
    targets = targets[:config.NUCLEI_TARGET_LIMIT]
    inventory_count = len(discovered_urls)
    templates = [options[name] for name in selected_ids]
    blobs = dict(community_templates or {})
    for index, yaml_source in enumerate(custom_templates or []):
        blobs[f"custom-{index+1}"] = yaml_source
    if not templates and not blobs:
        return {"status": "skipped", "alerts": [], "templates": [],
                "targets_checked": 0, "reason": "No Nuclei templates selected"}
    if not targets:
        return {"status": "skipped", "alerts": [], "templates": [],
                "targets_checked": 0, "reason": "No exact-host targets"}
    with tempfile.TemporaryDirectory(prefix="asfb-nuclei-") as tmp:
        target_file = os.path.join(tmp, "targets.txt")
        with open(target_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(targets) + "\n")
        for index, (label, content) in enumerate(blobs.items()):
            from .nuclei_catalog import validate_template
            validate_template(content)
            path = os.path.join(tmp, f"custom-{index}.yaml")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write(content)
            templates.append(path)
        import yaml
        estimated_per_url = 0
        for template in templates:
            # Docker deploys to /app/app; offline CI runs from the checkout.
            local_path = template if os.path.isfile(template) else os.path.join(
                os.path.dirname(__file__), "nuclei-templates", os.path.basename(template))
            with open(local_path, encoding="utf-8") as source:
                document = yaml.safe_load(source) or {}
            requests = document.get("http", []) if isinstance(document, dict) else []
            estimated_per_url += sum(max(1, len(req.get("path", [])))
                                     for req in requests if isinstance(req, dict))
        estimated_per_url = max(1, estimated_per_url)
        # Keep the request volume bounded even if the user selects broad presets
        # and multiple community/custom templates together.
        if estimated_per_url > config.NUCLEI_MAX_REQUEST_BUDGET:
            return {"status": "failed", "alerts": [], "templates": list(selected_ids) + list(blobs),
                    "targets_checked": 0,
                    "reason": (f"Nuclei selected templates require approximately {estimated_per_url} "
                               f"requests per target, above the configured job budget of "
                               f"{config.NUCLEI_MAX_REQUEST_BUDGET}. Reduce template selections."),
                    "estimated_per_target": estimated_per_url,
                    "max_job_requests": config.NUCLEI_MAX_REQUEST_BUDGET}
        max_targets = config.NUCLEI_MAX_REQUEST_BUDGET // estimated_per_url
        requested_targets = len(targets)
        targets = targets[:max_targets]
        with open(target_file, "w", encoding="utf-8") as handle:
            handle.write("\n".join(targets) + "\n")
        args = ["/usr/local/bin/nuclei", "-l", target_file]
        for template in templates:
            args.extend(["-t", template])
        args.extend(["-rl", "1", "-c", "1", "-bs", "1", "-timeout", "8",
                     "-retries", "0", "-jsonl", "-silent", "-duc", "-dr", "-or",
                     "-H", "User-Agent: " + agent])
        rows, status = await execute(args, config.NUCLEI_TIMEOUT_SECONDS)
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
        template_id = str(obj.get("template-id") or "")
        matcher = str(obj.get("matcher-name") or "")
        path = urlsplit(matched_url).path.lower()
        file_candidate = template_id.startswith("bounty-ultimate-") and any(
            token in path for token in ("/.git/", "/.env", "/backup.", "/dump.",
                                        "/debug.log", "/appsettings.", "/terraform.tfstate",
                                        "/docker-compose.", "/.npmrc", "/.aws/"))
        findings.append({
            "name": info.get("name") or template_id or "Template match",
            "risk": str(info.get("severity", "info")).title().replace("Info", "Informational"),
            "confidence": "Low", "url": matched_url,
            "description": str(info.get("description") or "")[:1000],
            "source": "nuclei", "template_id": template_id,
            "matcher_name": matcher, "potential_file_exposure": file_candidate
        })
    diag = " | ".join(line[:180] for line in rows
                      if line.startswith(("[stderr]", "[diagnostic]")))
    budget_limited = requested_targets > len(targets)
    if budget_limited and status == "completed":
        status = "partial"
    if budget_limited:
        diag = ("Template request budget limited coverage to " + str(len(targets)) +
                " of " + str(requested_targets) + " scoped URLs. " + diag)
    if exposure_profile and inventory_count > 1:
        note = (f"Exposure templates evaluated at the web origin, not repeated "
                f"on {inventory_count - 1} discovered asset paths. ")
        diag = (note + diag)[:500]
    return {"status": status, "alerts": findings[:config.NUCLEI_FINDINGS_LIMIT],
            "templates": (list(selected_ids) + list(blobs)),
            "targets_checked": len(targets), "requested_targets": requested_targets,
            "inventory_urls": inventory_count, "scope_strategy": scope_strategy,
            "estimated_requests_per_target": estimated_per_url,
            "reason": diag[:500]}

_gau_failures = 0
_gau_disabled_until = 0.0
_gau_provider_failures = {}
_gau_provider_disabled_until = {}

async def gau(url, host, limit=None, mode=None):
    """Query fast archives by default; slower archives are opt-in per job."""
    global _gau_failures, _gau_disabled_until
    chosen_mode = mode or config.GAU_MODE_DEFAULT
    if chosen_mode not in ("balanced", "expanded"):
        raise ValueError("Invalid GAU archive mode")
    maximum = max(1, min(int(limit or config.ENDPOINT_LIMIT_DEFAULT), config.ENDPOINT_LIMIT_MAX))
    providers = (config.GAU_PROVIDER,) + tuple(config.GAU_FAST_PROVIDERS)
    if chosen_mode == "expanded":
        providers += tuple(config.GAU_SLOW_PROVIDERS)
        if config.GAU_ENABLE_WAYBACK:
            providers += ("wayback",)
    collected, provider_results = [], []
    for provider in dict.fromkeys(providers):
        now = time.monotonic()
        is_primary = provider == config.GAU_PROVIDER
        disabled_until = (_gau_disabled_until if is_primary
                          else _gau_provider_disabled_until.get(provider, 0.0))
        if now < disabled_until:
            provider_results.append({
                "provider": provider, "status": "unavailable",
                "urls": 0, "reason": "Circuit breaker cooldown",
                "cooldown_seconds": round(disabled_until - now)})
            continue
        deadline = (config.GAU_WAYBACK_DEADLINE_SECONDS if provider == "wayback"
                    else config.GAU_SLOW_PROVIDER_DEADLINE_SECONDS if provider in config.GAU_SLOW_PROVIDERS
                    else config.GAU_PROVIDER_DEADLINE_SECONDS)
        args = ["/usr/local/bin/gau", "--threads", "1",
                "--timeout", str(min(config.GAU_HTTP_TIMEOUT_SECONDS, deadline)),
                "--retries", "0", "--providers", provider, host]
        began = time.monotonic()
        rows, status = await execute(args, deadline)
        urls = [value.strip() for value in rows
                if isinstance(value, str) and in_host(value.strip(), host)]
        collected.extend(urls)
        diagnostics = " | ".join(value[:180] for value in rows
                                 if value.startswith(("[stderr]", "[diagnostic]")))
        provider_results.append({"provider": provider, "status": status,
                                 "urls": len(urls), "reason": diagnostics[:300],
                                 "deadline_seconds": deadline,
                                 "elapsed_ms": round((time.monotonic() - began) * 1000)})
        failed = status in ("timeout", "failed", "unavailable")
        if is_primary:
            if failed:
                _gau_failures += 1
                if _gau_failures >= config.GAU_BREAKER_FAILURES:
                    _gau_disabled_until = time.monotonic() + config.GAU_BREAKER_COOLDOWN_SECONDS
                    _gau_failures = 0
            else:
                _gau_failures = 0
                _gau_disabled_until = 0.0
        else:
            if failed:
                count = _gau_provider_failures.get(provider, 0) + 1
                if count >= config.GAU_FALLBACK_BREAKER_FAILURES:
                    _gau_provider_disabled_until[provider] = (
                        time.monotonic() + config.GAU_FALLBACK_BREAKER_COOLDOWN_SECONDS)
                    _gau_provider_failures[provider] = 0
                else:
                    _gau_provider_failures[provider] = count
            else:
                _gau_provider_failures.pop(provider, None)
                _gau_provider_disabled_until.pop(provider, None)
        if status == "completed" and urls and not config.GAU_AGGREGATE_ALL_PROVIDERS:
            break
    unique = list(dict.fromkeys(collected))[:maximum]
    statuses = [item["status"] for item in provider_results]
    successes = [item for item in provider_results if item["status"] == "completed"]
    if statuses and all(s == "completed" for s in statuses):
        final_status = "completed"
    elif unique or successes:
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
    coverage = ("degraded" if problems and (successes or unique) else
                "unavailable" if problems else "found" if unique else "no-archive-hits")
    reason = " | ".join(problems)
    if not unique:
        reason = (reason + " | " if reason else "") + (
            "No exact-host archive URLs were returned. This does not imply the host has no URLs.")
    return {
        "status": final_status, "mode": chosen_mode, "endpoints": unique,
        "providers": provider_results, "coverage": coverage,
        "reason": reason[:500],
        "summary": f"GAU mode: {chosen_mode}; archive providers queried: {len(provider_results)}; "
                   f"responded: {len(successes)}; exact-host URLs: {len(unique)}; "
                   f"coverage: {coverage}" +
                   (f"; {' | '.join(problems)}" if problems else ""),
    }

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
