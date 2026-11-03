"""Artifact-aware final-stage adapters, using pinned tools on remote infrastructure."""
import json
import base64
import os
import re
import tempfile
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


def amass_internal_stop(rows, status):
    """Recognize the pinned CLI's context deadline, never an outer forced kill."""
    if status not in ("completed", "failed"):
        return False
    messages = [row.removeprefix("[stderr] ").strip() for row in rows]
    if "context deadline exceeded" not in messages:
        return False
    exits = [row for row in messages if row.startswith("[diagnostic] Process exit code:")]
    return (status == "completed" and not exits or
            status == "failed" and exits == ["[diagnostic] Process exit code: 1"])


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


# Let the pinned native tool choose and run its built-in detector verifiers.
TRUFFLEHOG_DETECTION_SECONDS = 40
TRUFFLEHOG_VERIFY_SECONDS = 120


def native_secret_state(row):
    if row.get("Verified") is True:
        return "verified"
    if row.get("VerificationSkipped") is True:
        return "not_attempted"
    if row.get("VerificationError") or not isinstance(row.get("Verified"), bool):
        return "unknown"
    # Native false includes unsupported/skipped verification in versions whose
    # JSON does not expose VerificationSkipped. Never describe it as invalid.
    return "unverified"


def trufflehog_candidates(rows):
    # Keys and native metadata remain in memory only, never in returned diagnostics.
    candidates = {}
    rank = {"verified": 3, "unknown": 2, "unverified": 1, "not_attempted": 0}
    for row in json_rows(rows):
        name = row.get("DetectorName")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,79}", name):
            continue
        raw = row.get("RawV2") or row.get("Raw") or ""
        if not isinstance(raw, str):
            continue
        key = (name, raw)
        previous = candidates.get(key)
        if previous is None or rank[native_secret_state(row)] > rank[native_secret_state(previous)]:
            candidates[key] = row
    return candidates


def trufflehog_states(rows, verification_enabled):
    return {key: native_secret_state(row) if verification_enabled else "not_attempted"
            for key, row in trufflehog_candidates(rows).items()}


def parse_trufflehog(rows, url, verification_enabled=False):
    # Never return Raw, RawV2, Redacted, ExtraData, errors or source snippets.
    groups = {}
    for (name, _), state in trufflehog_states(rows, verification_enabled).items():
        groups[(name, state)] = groups.get((name, state), 0) + 1
    descriptions = {
        "verified": "Native TruffleHog verification confirmed this credential at scan time.",
        "unverified": ("Native TruffleHog did not confirm validity. The detector may not support "
                       "verification or may have skipped it; this does not prove the credential is invalid."),
        "unknown": "Native verification was inconclusive or reported an error; validity is unknown.",
        "not_attempted": "Detection only; verification was disabled or the native detector reported skipping it.",
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
        early_stop = False
        if module == "trufflehog":
            source = root / "source"
            source.mkdir()
            (source / "source.txt").write_text(values.source_text, encoding="utf-8")
            (source / "source.txt").chmod(0o600)
            args = ["/usr/local/bin/trufflehog", "filesystem", str(source), "--json",
                    "--results", "verified,unverified,unknown", "--no-update", "--concurrency", "1",
                    "--force-skip-binaries", "--force-skip-archives", "--fail-on-scan-errors"]
            if values.trufflehog_verify:
                deadline = TRUFFLEHOG_VERIFY_SECONDS
                reason = "Native TruffleHog verification enabled for all detectors; original supplied source; values and context redacted"
            else:
                args.append("--no-verification")
                deadline = TRUFFLEHOG_DETECTION_SECONDS
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
            states = trufflehog_states(rows, values.trufflehog_verify)
            findings = parse_trufflehog(rows, url, values.trufflehog_verify)
            verification = {"enabled": values.trufflehog_verify, "mode": "native",
                            "detectors": "all", "deadline_seconds": deadline,
                            "candidates_reported": len(states),
                            **{state: sum(value == state for value in states.values())
                               for state in ("verified", "unverified", "unknown", "not_attempted")}}
            if values.trufflehog_verify:
                reason += "; " + ", ".join(f"{verification[state]} {state.replace('_', ' ')}"
                                          for state in ("verified", "unverified", "unknown", "not_attempted"))
                if verification["unknown"] and status == "completed":
                    status = "partial"
        elif module == "amass":
            path = root / "hosts.txt"
            candidates = (path.read_text(encoding="utf-8", errors="replace").splitlines()[:500] if path.is_file() else []) + rows
            for entry in candidates:
                name = entry.strip().lower().rstrip(".")
                if re.fullmatch(r"[a-z0-9.-]{1,253}", name) and (name == host or name.endswith("." + host)):
                    hosts.append(name)
            hosts = sorted(set(hosts))[:100]
            if amass_internal_stop(rows, status):
                status, early_stop = "completed", True
                reason += "; Early stop: native enumeration time budget reached; inventory coverage is incomplete"
        elif module == "kiterunner":
            # The pinned CLI's responses[].sc is the observed HTTP status.
            # A route record alone (including 404/wildcard hits) is not discovery.
            for item in json_rows(rows):
                responses = item.get("responses")
                if (item.get("method") != "GET" or not isinstance(responses, list)
                        or not responses or not isinstance(responses[0], dict)):
                    continue
                code = responses[0].get("sc")
                if type(code) is not int or not 200 <= code < 300:
                    continue
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
                    probes.append({"url": candidate, "status_code": code, "source": "kiterunner"})
            endpoints = sorted(set(endpoints))[:20]
            probes = list({item["url"]: item for item in probes}.values())[:20]
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
                **({"early_stop": True, "stop_reason": "native_time_budget", "coverage_complete": False}
                   if early_stop else {}),
                "hosts": hosts, "endpoints": endpoints, "probes": probes,
                "deadline_seconds": deadline,
                "reason": (reason + ("; " + diag if diag else ""))[:700],
                "output": summary}