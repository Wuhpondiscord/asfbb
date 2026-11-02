"""Bounded optional web scanners. All processes run inside the HF container."""
import asyncio
import json
import os
import re
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from . import config
from .pipeline import execute, in_host
from .scope import public_host

from .final_module_names import FINAL_MODULES

MODULES = {"nikto", "wpscan", "testssl", "wapiti", "retirejs", "idor-forge", "wafw00f", "semgrep", "graphw00f", "corsy", "takeover", "s3-review", "websocket", "vcs-artifacts", "race-replay", "nosql"} | FINAL_MODULES


def same_origin(candidate, target):
    try:
        a, b = urlsplit(candidate), urlsplit(target)
        return (in_host(candidate, b.hostname) and a.scheme == b.scheme and
                (a.port if a.port is not None else (443 if a.scheme == "https" else 80)) ==
                (b.port if b.port is not None else (443 if b.scheme == "https" else 80)))
    except (TypeError, ValueError):
        return False


class WordPressEvidence(HTMLParser):
    def __init__(self, target):
        super().__init__()
        self.target = target
        self.install_url = None
        self.evidence = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if (tag == "meta" and str(attrs.get("name", "")).lower() == "generator"
                and re.match(r"wordpress(?:\s|$)", str(attrs.get("content", "")), re.I)):
            self.evidence.append("WordPress generator meta tag")
            self.install_url = self.install_url or urlsplit(self.target)._replace(query="", fragment="").geturl()
        if tag not in ("link", "script"):
            return
        value = attrs.get("href" if tag == "link" else "src")
        if not value:
            return
        try:
            candidate = urljoin(self.target, value)
            if not same_origin(candidate, self.target):
                return
            parts = urlsplit(candidate)
            match = re.search(r"/(?:wp-content|wp-includes)/", parts.path, re.I)
            if match:
                self.evidence.append("Same-origin WordPress asset")
                self.install_url = parts._replace(
                    path=parts.path[:match.start() + 1], query="", fragment="").geturl()
        except ValueError:
            pass


async def wordpress_preflight(url, host, agent):
    """A current-page sample with bounded, same-origin-only redirects."""
    from .sampling import FetchProblem, fetch_page
    try:
        body, content_type, sampled_url = await fetch_page(
            url, agent, config.WEB_PREFLIGHT_MAX_BYTES, public_host,
            timeout=10, request_timeout=8, truncate=True)
        parser = WordPressEvidence(sampled_url)
        parser.feed(body.decode("utf-8", "replace"))
        evidence = "; ".join(dict.fromkeys(parser.evidence))
        if evidence and sampled_url != url:
            evidence += "; same-origin redirected page sampled"
        return parser.install_url, evidence or "WordPress unconfirmed: no current-page WordPress evidence"
    except (FetchProblem, httpx.HTTPError, asyncio.TimeoutError, ValueError) as exc:
        detail = str(exc) if isinstance(exc, FetchProblem) else exc.__class__.__name__
        return None, "WordPress unconfirmed: preflight " + detail


def read_report(path):
    try:
        with open(path, encoding="utf-8") as source:
            content = source.read(config.WEB_REPORT_MAX_BYTES + 1)
        if len(content) > config.WEB_REPORT_MAX_BYTES:
            return None
        return json.loads(content)
    except (OSError, ValueError):
        return None


def alert(source, title, url, description, risk="Informational", rule=""):
    return {"source": source, "name": str(title)[:200], "url": url,
            "description": str(description)[:1500], "risk": risk,
            "confidence": "Low", "rule_id": str(rule)[:120]}


def parse_nikto(report, target):
    findings = []
    hosts = report if isinstance(report, list) else [report]
    for item in hosts:
        if not isinstance(item, dict):
            continue
        for entry in item.get("vulnerabilities", []):
            if not isinstance(entry, dict):
                continue
            candidate = urljoin(target, str(entry.get("url") or "/"))
            if same_origin(candidate, target):
                findings.append(alert("nikto", "Nikto: " + str(entry.get("msg") or entry.get("id")),
                                      candidate, entry.get("msg") or "", rule=entry.get("id", "")))
    return findings[:config.WEB_FINDINGS_LIMIT]


def parse_wpscan(report, target):
    if not isinstance(report, dict):
        return []
    findings = []
    for entry in report.get("interesting_findings", []):
        if not isinstance(entry, dict):
            continue
        candidate = str(entry.get("url") or target)
        if same_origin(candidate, target):
            findings.append(alert("wpscan", "WPScan: " + str(entry.get("to_s") or entry.get("type")),
                                  candidate, entry.get("found_by") or "WordPress observation"))
    components = [("WordPress", report.get("version")), ("Theme", report.get("main_theme"))]
    for section in ("plugins", "themes"):
        entries = report.get(section)
        if isinstance(entries, dict):
            components.extend((str(name), item) for name, item in entries.items())
    for label, item in components:
        if not isinstance(item, dict):
            continue
        candidate = str(item.get("location") or target)
        if not same_origin(candidate, target):
            continue
        for vuln in item.get("vulnerabilities", []):
            if isinstance(vuln, dict):
                findings.append(alert("wpscan", label + ": " + str(vuln.get("title") or "Vulnerability candidate"),
                                      candidate, "Unverified database match. Fixed in: " +
                                      str(vuln.get("fixed_in") or "not provided"),
                                      rule=vuln.get("id", "")))
    return findings[:config.WEB_FINDINGS_LIMIT]


def parse_testssl(report, target):
    if not isinstance(report, list):
        return []
    # OK/INFO records describe capabilities; do not turn them into vulnerabilities.
    risks = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High", "CRITICAL": "Critical", "WARN": "Low"}
    return [alert("testssl", "TLS: " + str(item.get("id") or "configuration"),
                  target, item.get("finding") or "", risks[str(item.get("severity")).upper()],
                  item.get("id", ""))
            for item in report if isinstance(item, dict) and
            str(item.get("severity")).upper() in risks][:config.WEB_FINDINGS_LIMIT]


def command(module, target, host, agent, report, delay):
    pause = str(max(config.REQUEST_DELAY_MIN, float(delay)))
    if module == "nikto":
        return ["perl", "/opt/nikto/program/nikto.pl", "-h", target,
                "-ask", "no", "-Tuning", "23b", "-Pause", pause,
                "-timeout", "5", "-maxtime", str(config.NIKTO_SCAN_SECONDS) + "s",
                "-useragent", agent, "-Format", "json", "-output", report]
    if module == "wpscan":
        return ["ruby", "/app/app/wpscan_runner.rb", "--url", target,
                "--scope", host, "--detection-mode", "passive",
                "--plugins-detection", "passive", "--plugins-version-detection", "passive",
                "--themes-detection", "passive", "--themes-version-detection", "passive",
                "--enumerate", "vp,vt", "--max-threads", "1",
                "--throttle", str(round(float(pause) * 1000)),
                "--request-timeout", "5", "--connect-timeout", "5",
                "--max-response-size", "1", "--max-scan-duration", str(config.WPSCAN_SCAN_SECONDS),
                "--cookie-jar", str(Path(report).parent / "cookies.txt"),
                "--cache-dir", str(Path(report).parent / "cache"),
                "--no-update", "--no-banner", "--format", "json", "--output", report]
    if module == "testssl":
        # Server-defaults subset only. No exhaustive cipher/vulnerability sweeps.
        origin = urlsplit(target)._replace(path="/", query="", fragment="").geturl()
        return ["bash", "/opt/testssl/testssl.sh", "--quiet", "--color", "0",
                "--warnings", "batch", "-S", "--ip", "one",
                "--nodns", "min", "--connect-timeout", "5", "--openssl-timeout", "5",
                "--jsonfile", report, origin]
    raise ValueError("Unknown web module")


async def run_web_module(module, url, host, agent, delay=1.5, discovered=None, inputs=None, profile="current"):
    if module not in MODULES or not in_host(url, host):
        raise ValueError("Invalid module or out-of-scope web target")
    if module in ("race-replay", "nosql"):
        from .replay_modules import run
        return await run(module, url, host, agent, delay, inputs)
    if module in ("graphw00f", "corsy", "takeover", "s3-review", "websocket", "vcs-artifacts"):
        from .protocol_modules import run
        return await run(module, url, host, agent, delay, discovered, inputs)
    if module in ("wafw00f", "semgrep"):
        from .analysis_modules import run
        return await run(module, url, host, agent, delay, inputs)
    if module == "idor-forge":
        from .idor_module import run
        return await run(url, host, agent, delay, inputs)
    if module in FINAL_MODULES:
        from .final_modules import run
        return await run(module, url, host, agent, delay, inputs, profile=profile)
    if module in ("wapiti", "retirejs"):
        from . import client_modules
        if module == "retirejs":
            return await client_modules.retirejs(url, host, agent, delay, discovered or [], **({"profile": profile} if profile != "current" else {}))
        return await client_modules.wapiti(url, host, agent, delay)
    target, evidence = url, ""
    if module == "testssl" and urlsplit(url).scheme != "https":
        return {"status": "skipped", "source": module, "alerts": [], "target": url,
                "reason": "Not applicable: TLS review requires an HTTPS target",
                "output": "Skipped testssl.sh: HTTP target"}
    if module == "wpscan":
        target, evidence = await wordpress_preflight(url, host, agent)
        if not target:
            return {"status": "skipped", "source": module, "alerts": [], "target": url,
                    "reason": evidence, "output": "Skipped WPScan: " + evidence}
    public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
    deadlines = {"nikto": config.NIKTO_TIMEOUT_SECONDS, "wpscan": config.WPSCAN_TIMEOUT_SECONDS,
                 "testssl": config.TESTSSL_TIMEOUT_SECONDS}
    with tempfile.TemporaryDirectory(prefix="asfb-" + module + "-") as tmp:
        path = str(Path(tmp) / "report.json")
        rows, status = await execute(command(module, target, host, agent, path, delay), deadlines[module])
        report = read_report(path)
    code = next((int(row.rsplit(":", 1)[1]) for row in rows
                 if row.startswith("[diagnostic] Process exit code:") and
                 row.rsplit(":", 1)[1].strip().isdigit()), None)
    if module == "wpscan" and code == 5 and isinstance(report, dict) and not report.get("scan_aborted"):
        status = "findings"  # Documented WPScan vulnerability exit code.
    parsers = {"nikto": parse_nikto, "wpscan": parse_wpscan, "testssl": parse_testssl}
    findings = parsers[module](report, target)
    reasons = [row[:180] for row in rows if row.startswith(("[diagnostic]", "[stderr]"))
               and not (module == "wpscan" and code == 5 and status == "findings" and
                        row.startswith("[diagnostic] Process exit code:"))]
    if module == "nikto" and any("maximum execution time" in row.lower() for row in rows):
        status = "partial"
        reasons.append("Nikto reached its internal scan deadline; coverage is partial")
    if isinstance(report, dict) and report.get("scan_aborted"):
        if status not in ("timeout", "unavailable"):
            status = "partial" if findings else "failed"
        reasons.append(str(report["scan_aborted"])[:200])
    if report is None:
        if status in ("completed", "findings"):
            status = "failed"
        reasons.append("No readable bounded JSON report was produced")
    if module == "wpscan" and not os.environ.get("WPSCAN_API_TOKEN"):
        reasons.append("No WPSCAN_API_TOKEN: inventory only; vulnerability database coverage is unavailable")
    if module == "testssl":
        reasons.append("Limited TLS server-defaults profile; exhaustive TLS tests are not enabled")
    # Never include raw report metadata or credentials in persisted results.
    token = os.environ.get("WPSCAN_API_TOKEN")
    reason = " | ".join(reasons)
    if token:
        reason = reason.replace(token, "[redacted]")
        for item in findings:
            item["description"] = item["description"].replace(token, "[redacted]")
    return {"status": status, "source": module, "target": target, "alerts": findings,
            "reason": reason[:500], "applicability_evidence": evidence,
            "exit_code": code,
            "output": f"{module}: {len(findings)} unverified findings; status: {status}"}
