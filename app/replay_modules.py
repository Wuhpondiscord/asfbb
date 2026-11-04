"""Private replay configurations; only counts, controls and fixed observations leave the runner."""
import json
import math
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .module_inputs import ModuleInputs
from .pipeline import execute
from .sampling import origin
from .web_modules import alert, read_report

REASONS = {
    "scope_blocked": "Request outside the selected origin/profile was blocked",
    "origin_mismatch": "Replay profile is bound to another origin; other selected modules may continue",
    "request_budget": "Replay request budget reached",
    "rate_limited": "HTTP 429; replay stopped without retries",
    "redirect_not_followed": "Redirect was not followed",
    "server_error": "Server error; replay stopped without retries",
    "request_failed": "A bounded replay request failed",
    "response_limit": "Replay response exceeded 64 KiB",
    "encoded_response": "Server ignored the identity encoding request; compressed content was not processed",
    "deadline": "Replay deadline reached; partial control results retained",
    "matcher_unavailable": "Configured JSON success field could not be evaluated",
    "baseline_unconfirmed": "NoSQL baseline did not demonstrate the configured success condition",
    "counter_unavailable": "Read-only state counter was unavailable",
    "control_not_fresh": "Control fixture did not start at a zero counter",
    "parallel_not_fresh": "Parallel fixture did not start at a zero counter",
    "control_not_single_effect": "Sequential control did not establish exactly one accepted response; parallel burst skipped",
    "control_effect_unconfirmed": "Sequential control did not establish exactly one state-counter effect",
    "parallel_effect_unconfirmed": "Parallel success was reported but a state-counter effect was not yet observed",
    "overlap_unconfirmed": "Client-side request overlap was not observed; no race claim",
    "replay_error": "Replay validation or transport error; private diagnostics redacted",
}
MODULES = {"race-replay", "nosql"}


async def run(module, url, host, agent, delay, inputs=None):
    values = inputs if isinstance(inputs, ModuleInputs) else ModuleInputs(**(inputs or {}))
    cfg = values.race if module == "race-replay" else values.nosql
    if cfg is None:
        reason = "Requires a replay profile under Settings → Replay checks"
        return {"source": module, "target": url, "status": "skipped", "alerts": [], "reason": reason, "output": reason}
    if cfg.target_origin and origin(cfg.target_origin) != origin(url):
        reason = REASONS["origin_mismatch"]
        return {"source": module, "target": url, "status": "skipped", "alerts": [], "reason": reason, "output": reason}
    count = 8 if module == "race-replay" and cfg.verification else 4 if module == "race-replay" else 6
    deadline = max(75, min(330, math.ceil(count * (delay + 8) + 10)))
    target = url  # Private replay paths/fixture identifiers are not persisted.
    with tempfile.TemporaryDirectory(prefix="asfb-" + module + "-") as tmp:
        spec, output = Path(tmp) / "private.json", Path(tmp) / "report.json"
        spec.write_text(json.dumps({"module": module, "target": url, "host": host, "agent": agent,
                                    "delay": delay, "deadline": deadline, "config": cfg.model_dump()}), encoding="utf-8")
        spec.chmod(0o600)
        rows, status = await execute(["/opt/asfb-venv/bin/python", "-m", "app.replay_runner", str(spec), str(output)], deadline)
        report = read_report(output)
    if not isinstance(report, dict) or report.get("profile") != module or not isinstance(report.get("observations"), list):
        return {"source": module, "target": target, "status": status if status != "completed" else "failed",
                "alerts": [], "reason": "No valid private replay report", "output": module + ": incomplete; diagnostics redacted"}
    findings = []
    for item in report["observations"]:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        if module == "race-replay" and kind == "race_state_candidate":
            finding = alert(module, "Race candidate: state counter exceeded sequential control", target,
                "Separate fresh fixtures established one sequential effect but more than one effect after a two-request overlap. "
                "Counter values and requests are redacted. Verify fixture equivalence, isolation and business impact; this is a corroborated candidate, not proof of general exploitability.",
                "Medium", kind)
            finding["confidence"] = "Medium"
            findings.append(finding)
        elif module == "race-replay" and kind == "race_response_signal":
            findings.append(alert(module, "Concurrent response signal; state verification required", target,
                "Two parallel success responses followed a single-success sequential control. "
                "Idempotent/cached acknowledgements can produce this result without duplicate effects. "
                "No persistent state verification was supplied; this does not prove a race vulnerability.", "Informational", kind))
        elif module == "nosql" and kind == "nosql_operator_candidate":
            findings.append(alert(module, "NoSQL operator-dependent behavior candidate", target,
                "Scalar and inert-object controls plus $eq/$ne variants followed the configured success predicate. "
                "This suggests operator interpretation in the selected field; documented filter APIs may intentionally support it. "
                "No database, authentication bypass, data extraction or exploitability is proven. Request and response values are redacted.", "Medium", kind))
    metadata = {"request_limit": count, "deadline_seconds": deadline}
    requests = report.get("requests", 0)
    requests = requests if type(requests) is int and 0 <= requests <= count else 0
    metadata["requests"] = requests
    for name in ("control_successes", "parallel_successes"):
        value = report.get(name)
        if type(value) is int and 0 <= value <= 2:
            metadata[name] = value
    for name in ("client_overlap", "state_overrun"):
        if type(report.get(name)) is bool:
            metadata[name] = report[name]
    if type(report.get("start_gap_ms")) is int and 0 <= report["start_gap_ms"] <= 60000:
        metadata["start_gap_ms"] = report["start_gap_ms"]
    for name in ("control_statuses", "parallel_statuses"):
        if isinstance(report.get(name), list):
            metadata[name] = [code for code in report[name] if type(code) is int and 100 <= code <= 599][:2]
    if module == "nosql":
        names = ("baseline", "negative_scalar", "inert_object", "eq_baseline", "eq_negative", "ne_negative")
        for field in ("matches", "statuses"):
            source = report.get(field)
            if isinstance(source, dict):
                metadata[field] = {name: source[name] for name in names if name in source and
                    (source[name] is None or type(source[name]) is bool if field == "matches"
                     else type(source[name]) is int and 100 <= source[name] <= 599)}
    if status == "completed" and report.get("status") in ("partial", "failed", "skipped"):
        status = report["status"]
    if status == "completed" and report.get("status") != "completed":
        status = "partial"
    if status == "completed" and findings:
        status = "findings"
    reason = REASONS.get(report.get("stop_reason"), "")
    if not reason:
        reason = ("One best-effort two-request overlap; not HTTP/2 single-packet synchronization. No signal does not rule out races"
                  if module == "race-replay" else "Six typed HTTP controls; Mongo-style operators only; no scripts, sleeps, enumeration or direct database access")
    return {"source": module, "target": target, "status": status, "alerts": findings[:3],
            "requests": requests, "deadline_seconds": deadline, "metadata": metadata,
            "reason": reason, "output": f"{module}: {len(findings)} observations; {requests} bounded attempts; status: {status}; private values redacted"}