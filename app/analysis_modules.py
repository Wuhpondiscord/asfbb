"""Keyless native WAF fingerprinting and supplied-source SAST adapters."""
import json
import tempfile
from pathlib import Path

from .module_inputs import ModuleInputs
from .pipeline import execute
from .web_modules import alert, read_report

SAST_RULES = {
    "asfb-python-shell-true": "Review subprocess execution with shell=True.",
    "asfb-python-dynamic-code": "Review dynamically evaluated code and input provenance.",
    "asfb-python-pickle": "Deserialization must only accept trusted input.",
    "asfb-python-unsafe-yaml": "Review use of an unsafe YAML loader.",
    "asfb-python-tls-disabled": "Review disabled certificate verification.",
    "asfb-js-eval": "Review dynamic evaluation and input provenance.",
    "asfb-js-function-constructor": "Review dynamic Function construction.",
    "asfb-js-shell-command": "Review shell command execution and input provenance.",
    "asfb-js-html-assignment": "Review HTML assignments for untrusted content.",
}
LANGUAGES = {"python": ".py", "javascript": ".js", "typescript": ".ts"}


def normalized_sast(report, target):
    findings = []
    seen = set()
    for item in report.get("results", []):
        if not isinstance(item, dict):
            continue
        rule = str(item.get("check_id", "")).rsplit(".", 1)[-1]
        line = (item.get("start") or {}).get("line")
        if rule not in SAST_RULES or type(line) is not int or not 1 <= line <= 200001:
            continue
        if (rule, line) in seen:
            continue
        seen.add((rule, line))
        finding = alert("semgrep", "Semgrep: " + SAST_RULES[rule], target,
                        f"Supplied source, line {line}; rule {rule}. "
                        "Pattern review only; input trust, reachability and exploitability are not proven. "
                        "Source, values and native context are redacted.", "Medium", rule)
        finding["source_line"] = line
        findings.append(finding)
    return findings[:100]


async def run(module, url, host, agent, delay, inputs=None):
    values = inputs if isinstance(inputs, ModuleInputs) else ModuleInputs(**(inputs or {}))
    if module == "semgrep" and (not values.source_text.strip() or values.sast_language not in LANGUAGES):
        reason = "Requires supplied source text and an explicit Python, JavaScript or TypeScript language"
        return {"source": module, "status": "skipped", "alerts": [], "reason": reason, "output": reason}
    with tempfile.TemporaryDirectory(prefix="asfb-" + module + "-") as tmp:
        root = Path(tmp)
        output = root / "report.json"
        if module == "semgrep":
            source = root / ("source" + LANGUAGES[values.sast_language])
            source.write_text(values.source_text, encoding="utf-8")
            source.chmod(0o600)
            args = ["/usr/bin/env", "SEMGREP_SEND_METRICS=off", "SEMGREP_ENABLE_VERSION_CHECK=0",
                    "SEMGREP_APP_TOKEN=", "/opt/semgrep/bin/semgrep", "scan", "--oss-only",
                    "--config", "/app/app/semgrep-rules/review.yaml", "--json", "--output", str(output),
                    "--metrics", "off", "--disable-version-check", "--no-git-ignore",
                    "--jobs", "1", "--timeout", "5", "--max-memory", "512",
                    "--max-target-bytes", "1000000", str(source)]
            deadline = 75
            reason = "Supplied source only; nine bundled pattern-review rules; CE single-file analysis; no code execution, remote registry, uploads or autofix"
        elif module == "wafw00f":
            spec = root / "spec.json"
            spec.write_text(json.dumps({"target": url, "host": host, "agent": agent, "delay": delay}), encoding="utf-8")
            args = ["/opt/wafw00f/bin/python", "/app/app/waf_runner.py", str(spec), str(output)]
            deadline = 45
            reason = "Native WAFW00F vendor signatures; up to eight paced same-origin GET requests; no redirects or generic blocking heuristics"
        else:
            raise ValueError("Unsupported analysis module")
        rows, status = await execute(args, deadline)
        report = read_report(output)
        findings, vendors, requests = [], [], 0
        if module == "semgrep" and isinstance(report, dict) and isinstance(report.get("results"), list):
            findings = normalized_sast(report, url)
            errors = report.get("errors") or []
            scanned = (report.get("paths") or {}).get("scanned") or []
            if errors and status == "completed":
                status = "partial" if findings else "failed"
                reason += "; native analysis errors were reported (details redacted)"
            if not scanned and status == "completed":
                status = "failed"
                reason += "; supplied file was not reported as scanned"
        elif module == "wafw00f" and isinstance(report, dict) and report.get("profile") == "wafw00f-bounded":
            vendors = [name for name in report.get("vendors", []) if isinstance(name, str) and len(name) <= 120][:10]
            requests = report.get("requests", 0)
            requests = requests if type(requests) is int and 0 <= requests <= 8 else 0
            if report.get("status") in ("partial", "failed"):
                status = report["status"] if status == "completed" else status
            for vendor in vendors:
                findings.append(alert(module, "WAF fingerprint: " + vendor, url,
                    "Native vendor-signature observation; this is infrastructure inventory, not a vulnerability. "
                    "Header/body signatures can be spoofed or hidden. Raw responses and probe URLs are omitted."))
            if report.get("stop_reason") in ("request_budget", "response_limit", "rate_limited", "deadline",
                                             "request_failed", "scope_blocked", "probe_blocked"):
                reason += "; " + report["stop_reason"].replace("_", " ")
        else:
            if status == "completed":
                status = "failed"
            reason += "; no valid native report"
        if status == "completed" and findings:
            status = "findings"
        if status in ("timeout", "failed", "unavailable"):
            reason += "; incomplete scan; parsed results retained"
        return {"source": module, "target": url, "status": status, "alerts": findings,
                "waf": {"vendors": vendors, "requests": requests} if module == "wafw00f" else None,
                "requests": requests, "deadline_seconds": deadline, "reason": reason,
                "output": f"{module}: {len(findings)} observations; status: {status}; native output redacted"}
