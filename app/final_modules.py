"""Artifact-aware final-stage adapters, using pinned tools on remote infrastructure."""
import json
import base64
import os
import re
import tempfile
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .pipeline import execute
from .web_modules import alert, same_origin, read_report
from .module_inputs import ModuleInputs
from .coverage import profile as coverage_settings

MODULES = {"trufflehog", "amass", "depscan", "trivy", "kiterunner", "osv-scanner", "garak", "nettacker"}
CACHE = Path("/app/data/scanner-cache")


def skipped(module, url, reason):
    return {"source": module, "target": url, "status": "skipped", "alerts": [],
            "reason": reason, "output": module + " skipped: " + reason}


def diagnostics(rows):
    # Raw stderr and secret-scanner JSON can contain supplied source or model responses.
    # Persist fixed diagnostic categories only.
    if any(row.startswith("[diagnostic] Deadline") for row in rows):
        return "Process deadline reached; any parsed partial findings were retained"
    if any(row.startswith("[diagnostic] Process exit") for row in rows):
        return "Tool returned a nonzero exit status"
    return ""


def json_rows(rows):
    found = []
    for row in rows:
        try:
            item = json.loads(row)
        except (TypeError, ValueError):
            continue
        if isinstance(item, dict):
            found.append(item)
    return found


# Audited pinned v3.99.7 provider checks; never enable arbitrary-host/DB verifiers.
TRUFFLEHOG_VERIFIERS = frozenset({"AWS", "Github", "Slack", "HuggingFace", "OpenAI"})
TRUFFLEHOG_VERIFY_LIMIT = 10
TRUFFLEHOG_VERIFY_SECONDS = 30


def trufflehog_candidates(rows):
    # Keys and native metadata remain in memory only, never in returned diagnostics.
    candidates = {}
    for row in json_rows(rows):
        name = row.get("DetectorName")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", name):
            continue
        raw = row.get("RawV2") or row.get("Raw") or ""
        if not isinstance(raw, str):
            continue
        candidates.setdefault((name, raw), row)
    return candidates


def verification_source(name, row):
    raw = row.get("Raw")
    if not isinstance(raw, str) or not raw or len(raw) > 8000 or any(c in raw for c in "\r\n\x00"):
        return None
    if name == "AWS":
        # The upstream canary verifier uses SNS Publish. Do not invoke it.
        extra = row.get("ExtraData")
        if isinstance(extra, dict) and str(extra.get("is_canary", "")).lower() == "true":
            return None
        pair = row.get("RawV2", "")
        if not isinstance(pair, str) or not re.fullmatch(r"(?:AKIA|ABIA|ACCA)[A-Z0-9]{16}:[A-Za-z0-9/+=]{40}", pair):
            return None
        return pair.replace(":", "\n", 1)
    # Preserve the context needed by GitHub's legacy 40-character token detector.
    return ("github_token = " if name == "Github" else "") + raw


async def verify_trufflehog(rows, root):
    candidates = trufflehog_candidates(rows)
    states = {key: "not_attempted" for key in candidates}
    attempted = 0
    started = time.monotonic()
    directory = root / "verification"
    directory.mkdir(mode=0o700)
    for key, row in candidates.items():
        name, _ = key
        text = verification_source(name, row) if name in TRUFFLEHOG_VERIFIERS else None
        remaining = TRUFFLEHOG_VERIFY_SECONDS - (time.monotonic() - started)
        if text is None or attempted >= TRUFFLEHOG_VERIFY_LIMIT or remaining < 1:
            continue
        path = directory / "candidate.txt"
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        args = ["/usr/local/bin/trufflehog", "filesystem", str(path), "--json",
                "--include-detectors", name, "--results", "verified,unverified,unknown",
                "--allow-verification-overlap", "--no-verification-cache", "--no-update",
                "--concurrency", "1", "--force-skip-binaries", "--force-skip-archives",
                "--fail-on-scan-errors"]
        attempted += 1
        try:
            verified_rows, status = await execute(args, min(12, max(1, int(remaining))))
        except Exception:
            # Executor failures must preserve detection results without persisting exception text.
            verified_rows, status = [], "failed"
        finally:
            path.unlink(missing_ok=True)
        matches = [item for candidate, item in trufflehog_candidates(verified_rows).items() if candidate == key]
        # Missing output, timeout and transport/provider errors never mean invalid.
        state = "unknown"
        if any(item.get("Verified") is True for item in matches):
            state = "verified"
        elif status == "completed" and matches and all(
                item.get("Verified") is False and not item.get("VerificationError") for item in matches):
            state = "unverified"
        states[key] = state
    return states, attempted


def parse_trufflehog(rows, url, states=None):
    # Never return Raw, RawV2, Redacted, ExtraData, errors or source snippets.
    groups = {}
    for key in trufflehog_candidates(rows):
        name, _ = key
        state = (states or {}).get(key, "not_attempted")
        groups[(name, state)] = groups.get((name, state), 0) + 1
    descriptions = {
        "verified": "Provider authentication confirmed this credential at scan time.",
        "unverified": "TruffleHog did not confirm validity. This does not prove the credential is invalid.",
        "unknown": "Verification was inconclusive, failed or timed out; validity is unknown.",
        "not_attempted": "Detection only; verification was disabled, unsupported, excluded or outside the verification budget.",
    }
    findings = []
    for (name, state), count in groups.items():
        label = {"verified": "Verified", "unverified": "Unverified",
                 "unknown": "Inconclusive", "not_attempted": "Detection-only"}[state]
        finding = alert("trufflehog", label + " " + name + " secret", url,
                        descriptions[state] + f" {count} distinct candidate(s). Values and context redacted.",
                        "High" if state == "verified" else "Medium", name)
        finding.update(verification_status=state, candidate_count=count,
                       confidence="High" if state == "verified" else "Low")
        findings.append(finding)
    return findings[:100]


def parse_dependency_report(module, report, url):
    findings = []
    if module == "trivy" and isinstance(report, dict):
        for result in report.get("Results") or []:
            if not isinstance(result, dict):
                continue
            for item in result.get("Vulnerabilities") or []:
                if isinstance(item, dict):
                    findings.append(alert(module, str(item.get("VulnerabilityID") or "Advisory") +
                                          ": " + str(item.get("PkgName") or "package"), url,
                                          "SBOM advisory match; installed " + str(item.get("InstalledVersion") or "?") +
                                          "; fixed " + str(item.get("FixedVersion") or "not provided"),
                                          str(item.get("Severity") or "info").title().replace("Info", "Informational"),
                                          item.get("VulnerabilityID", "")))
    elif module == "osv-scanner" and isinstance(report, dict):
        for result in report.get("results") or []:
            for package in result.get("packages") or []:
                info = package.get("package") or {}
                for vuln in package.get("vulnerabilities") or []:
                    if isinstance(vuln, dict):
                        findings.append(alert(module, str(vuln.get("id") or "Advisory") + ": " +
                                              str(info.get("name") or "package"), url,
                                              "Unverified SBOM advisory match for version " + str(info.get("version") or "?"),
                                              "Informational", vuln.get("id", "")))
    elif module == "depscan" and isinstance(report, dict):
        for item in report.get("vulnerabilities") or []:
            if not isinstance(item, dict):
                continue
            ratings = item.get("ratings") or []
            severity = str(ratings[0].get("severity") or "info") if ratings and isinstance(ratings[0], dict) else "info"
            findings.append(alert(module, str(item.get("id") or "Dependency advisory"), url,
                                  "Unverified SBOM advisory match. Application-only database profile.",
                                  severity.title().replace("Info", "Informational"), item.get("id", "")))
    return findings[:100]


async def prepare_database(module):
    directory = CACHE / module
    directory.mkdir(parents=True, exist_ok=True)
    if module == "trivy":
        ready = directory / "db" / "metadata.json"
        args = ["/usr/local/bin/trivy", "--cache-dir", str(directory),
                "image", "--download-db-only", "--no-progress"]
    else:
        ready = directory / ".depscan-vdb-image"
        args = ["/usr/bin/env", "VDB_HOME=" + str(directory),
                "VDB_DATABASE_URL=ghcr.io/appthreat/vdbxz-app-2y:v6.7.x",
                "VDB_DOWNLOAD_RETRIES=1", "/opt/depscan/bin/depscan-vdb",
                "download", "--scope", "app", "--time", "2y", "--compression", "xz"]
    if ready.is_file():
        return True, ""
    rows, status = await execute(args, 180)
    return status == "completed" and ready.is_file(), diagnostics(rows) or "Vulnerability database preparation did not complete"


async def run(module, url, host, agent, delay, inputs=None, profile="current"):
    settings = coverage_settings(profile)
    values = inputs if isinstance(inputs, ModuleInputs) else ModuleInputs(**(inputs or {}))
    if module == "trufflehog" and not values.source_text.strip():
        return skipped(module, url, "Requires supplied source text; a URL is not a filesystem input")
    if module in {"depscan", "trivy", "osv-scanner"} and not values.sbom_text:
        return skipped(module, url, "Requires a CycloneDX SBOM with named/versioned package URLs")
    if module == "kiterunner" and not values.api_target:
        return skipped(module, url, "API-target option is not enabled for this asset")
    if module == "garak" and not values.llm_path:
        return skipped(module, url, "Requires an explicitly configured same-origin REST LLM endpoint")
    with tempfile.TemporaryDirectory(prefix="asfb-" + module + "-") as tmp:
        root = Path(tmp)
        report_path = str(root / "report.json")
        args, deadline = [], 60
        report, findings, hosts, endpoints, probes = None, [], [], [], []
        reason = ""
        verification = None
        if module == "trufflehog":
            source = root / "source"
            source.mkdir()
            (source / "source.txt").write_text(values.source_text, encoding="utf-8")
            (source / "source.txt").chmod(0o600)
            args = ["/usr/local/bin/trufflehog", "filesystem", str(source), "--json",
                    "--no-verification", "--no-update", "--concurrency", "1",
                    "--force-skip-binaries", "--force-skip-archives", "--fail-on-scan-errors"]
            deadline = 40
            reason = "Supplied source only; secret verification disabled; values and context redacted"
        elif module in ("trivy", "depscan", "osv-scanner"):
            sbom = root / "bom.json"
            sbom.write_text(values.sbom_text, encoding="utf-8")
            if module in ("trivy", "depscan"):
                ok, failure = await prepare_database(module)
                if not ok:
                    return {"source": module, "target": url, "status": "unavailable",
                            "alerts": [], "reason": failure,
                            "output": module + ": database unavailable; no clean-scan claim"}
            if module == "trivy":
                args = ["/usr/local/bin/trivy", "--cache-dir", str(CACHE / module), "sbom",
                        "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--format", "json",
                        "--output", report_path, str(sbom)]
                reason = "Supplied application SBOM only; cached database; no container daemon"
            elif module == "osv-scanner":
                args = ["/usr/local/bin/osv-scanner", "scan", "source", "--sbom", str(sbom),
                        "--format", "json", "--output", report_path]
                reason = "Supplied SBOM package names/versions are queried against the public keyless OSV service"
            else:
                args = ["/usr/bin/env", "VDB_HOME=" + str(CACHE / module),
                        "VDB_DATABASE_URL=ghcr.io/appthreat/vdbxz-app-2y:v6.7.x",
                        "VDB_DOWNLOAD_RETRIES=1", "/opt/depscan/bin/depscan",
                        "--bom", str(sbom), "--reports-dir", str(root / "reports"),
                        "--reachability-analyzer", "off", "--no-suggest", "--no-vuln-table"]
                reason = "Application-only SBOM profile; smaller 2024+ advisory database; no source builds or OS reachability"
            deadline = 90
        elif module == "amass":
            args = ["/usr/local/bin/amass", "enum", "-passive", "-d", host, "-timeout", str(settings["amass_minutes"]),
                    "-dir", str(root / "state"), "-o", str(root / "hosts.txt"), "-nocolor"]
            deadline = settings["amass_timeout"]
            reason = "HF standalone-compatible Amass 4.2.0 passive profile; discovered names are inventory, never auto-scanned"
        elif module == "kiterunner":
            dictionary = root / "routes.txt"
            dictionary.write_text("api\napi/v1\napi/v2\nhealth\nstatus\nopenapi.json\nswagger.json\nversion\n", encoding="utf-8")
            target = urlsplit(url)._replace(path="/", query="", fragment="").geturl()
            args = ["/usr/local/bin/kr", "brute", target, "-w", str(dictionary),
                    "-x", "1", "-j", "1", "--max-redirects", "0", "--force-method", "GET",
                    "--delay", str(max(1.0, delay)) + "s", "--timeout", "5s",
                    "--disable-precheck", "--wildcard-detection=false", "--progress=false",
                    "--preflight-depth", "0", "--header", "Accept: application/json",
                    "--user-agent", agent, "-o", "json", "-q"]
            deadline = 65
            reason = "Eight-route GET-only API sample; one connection, no redirects, no generated payloads"
        elif module == "nettacker":
            args = ["/opt/nettacker/bin/python", "/app/app/nettacker_runner.py", url, report_path, agent]
            deadline = 15
            reason = "Partial Nettacker integration: one exact-URL HTTP-status check using its HTTP engine and module conditions"
        elif module == "garak":
            target = urljoin(urlsplit(url)._replace(path="/", query="", fragment="").geturl(), values.llm_path)
            if not same_origin(target, url):
                raise ValueError("LLM endpoint outside selected origin")
            request = root / "config.json"
            request.write_text(json.dumps({"url": target, "prompt_field": values.prompt_field,
                                          "response_field": values.response_field, "delay": delay}), encoding="utf-8")
            args = ["/opt/garak/bin/python", "/app/app/garak_runner.py", str(request), report_path]
            deadline = 35
            reason = "Two garak REST output-filter test-signature prompts; applicable when that LLM is expected to filter antivirus signatures"
        else:
            raise ValueError("Unsupported module")
        rows, status = await execute(args, deadline)
        if module == "trufflehog":
            states, attempted = {}, 0
            if values.trufflehog_verify:
                states, attempted = await verify_trufflehog(rows, root)
                deadline += TRUFFLEHOG_VERIFY_SECONDS
            findings = parse_trufflehog(rows, url, states)
            candidates = trufflehog_candidates(rows)
            eligible = sum(name in TRUFFLEHOG_VERIFIERS and verification_source(name, row) is not None
                           for (name, _), row in candidates.items())
            verification = {"enabled": values.trufflehog_verify, "attempted": attempted,
                            "eligible": eligible,
                            "budget_limited": max(0, eligible - attempted) if values.trufflehog_verify else 0,
                            "limit": TRUFFLEHOG_VERIFY_LIMIT, "budget_seconds": TRUFFLEHOG_VERIFY_SECONDS,
                            **{state: sum(states.get(key, "not_attempted") == state for key in candidates)
                               for state in ("verified", "unverified", "unknown", "not_attempted")}}
            if values.trufflehog_verify:
                reason = ("Provider verification enabled; up to 10 candidates / 30s; " +
                          ", ".join(f"{verification[state]} {state.replace('_', ' ')}"
                                    for state in ("verified", "unverified", "unknown", "not_attempted")) +
                          "; values, identity metadata and provider errors redacted")
                if (verification["unknown"] or verification["budget_limited"]) and status == "completed":
                    status = "partial"
        elif module == "amass":
            path = root / "hosts.txt"
            candidates = (path.read_text(encoding="utf-8", errors="replace").splitlines()[:500] if path.is_file() else []) + rows
            for entry in candidates:
                name = entry.strip().lower().rstrip(".")
                if re.fullmatch(r"[a-z0-9.-]{1,253}", name) and (name == host or name.endswith("." + host)):
                    hosts.append(name)
            hosts = sorted(set(hosts))[:100]
        elif module == "kiterunner":
            # Kiterunner prints structured zerolog hit records; retain only scoped URLs.
            for item in json_rows(rows):
                def as_text(value):
                    if not isinstance(value, str):
                        return ""
                    if value.startswith(("http://", "https://", "/")):
                        return value
                    try:
                        return base64.b64decode(value, validate=True).decode("utf-8")
                    except (ValueError, UnicodeError):
                        return value
                target = as_text(item.get("target"))
                path = as_text(item.get("path"))
                candidate = item.get("url") or (urljoin(target.rstrip("/") + "/", path) if target else "")
                if isinstance(candidate, str) and same_origin(candidate, url):
                    endpoints.append(candidate)
            endpoints = sorted(set(endpoints))[:20]
        elif module == "depscan":
            candidates = sorted((root / "reports").glob("*.vdr.json"))
            if candidates:
                report = read_report(str(candidates[0]))
            findings = parse_dependency_report(module, report, url)
        else:
            report = read_report(report_path)
            if module in ("trivy", "osv-scanner"):
                findings = parse_dependency_report(module, report, url)
                if module == "osv-scanner" and report is not None and any(
                        row.strip() == "[diagnostic] Process exit code: 1" for row in rows) and findings:
                    status = "findings"
            elif module == "nettacker" and isinstance(report, dict):
                if isinstance(report.get("status_code"), int):
                    probes = [{"url": url, "status_code": report["status_code"], "source": "nettacker"}]
                if report.get("status") == "failed":
                    status = "failed"
            elif module == "garak" and isinstance(report, dict):
                for item in report.get("tests", []):
                    if item.get("matched"):
                        findings.append(alert("garak", "LLM emitted antivirus test signature", url,
                                              "Output-filter observation from a benign garak test signature; this is not proof of a general model vulnerability.",
                                              "Informational", "EICAR"))
                if report.get("status") == "failed":
                    status = "failed"
        valid_report = isinstance(report, dict) and (
            (module == "depscan" and report.get("bomFormat") == "CycloneDX") or
            (module == "trivy" and isinstance(report.get("Results"), list)) or
            (module == "osv-scanner" and isinstance(report.get("results"), list)) or
            (module == "garak" and isinstance(report.get("tests"), list) and bool(report.get("tests"))) or
            (module == "nettacker" and isinstance(report.get("status_code"), int))
        )
        if module in ("depscan", "trivy", "osv-scanner", "garak", "nettacker") and not valid_report:
            if status in ("completed", "findings"):
                status = "failed"
            reason += "; no valid structured report produced"
        if status in ("completed", "findings") and findings:
            status = "findings"
        diag = diagnostics(rows) if status not in ("completed", "findings") else ""
        summary = (f"{module}: {len(findings)} unverified findings; {len(hosts)} inventory hosts; "
                   f"{len(endpoints)} observed routes; status: {status}")
        if verification is not None:
            summary = ("trufflehog: " + ", ".join(f"{verification[state]} {state.replace('_', ' ')}"
                       for state in ("verified", "unverified", "unknown", "not_attempted")) + f"; status: {status}")
        return {"source": module, "target": url, "status": status, "alerts": findings,
                **({"verification": verification} if verification is not None else {}),
                "hosts": hosts, "endpoints": endpoints, "probes": probes,
                "deadline_seconds": deadline,
                "reason": (reason + ("; " + diag if diag else ""))[:700],
                "output": summary}
