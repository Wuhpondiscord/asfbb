"""Applicability and redacted result normalization for scoped protocol profiles."""
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from .module_inputs import ModuleInputs
from .pipeline import execute
from .web_modules import alert, read_report, same_origin
from .protocol_runner import bucket_target

MODULES = {"graphw00f", "corsy", "takeover", "s3-review", "websocket", "vcs-artifacts"}
DEADLINES = {"graphw00f": 100, "corsy": 40, "takeover": 35, "s3-review": 30, "websocket": 25, "vcs-artifacts": 35}
# These stops successfully enforce configured scope/sampling policy.
# Provider, DNS, transport, engine and time failures remain incomplete statuses.
POLICY_STOPS = {"redirect_not_followed", "scope_blocked", "request_budget", "response_limit"}

LABELS = {
    "vcs_metadata": ("Exposed VCS metadata candidate", "Medium"),
    "graphql_present": ("GraphQL metadata endpoint observed", "Informational"),
    "graphql_introspection": ("GraphQL limited introspection accessible", "Informational"),
    "graphql_engine": ("GraphQL native engine fingerprint", "Informational"),
    "cors_observation": ("CORS policy observation", "Informational"),
    "takeover_candidate": ("Potential dangling service binding", "Medium"),
    "s3_anonymous_list": ("S3 anonymous ListBucket accepted", "Medium"),
    "s3_acl_readable": ("S3 bucket ACL anonymously readable", "Informational"),
    "s3_public_acl": ("S3 public ACL grant advertised", "Medium"),
    "websocket_present": ("WebSocket opening handshake verified", "Informational"),
    "websocket_cross_origin": ("Anonymous WebSocket accepts cross-origin handshake", "Informational"),
}
KINDS = {"vcs-artifacts": {"vcs_metadata"}, "graphw00f": {"graphql_present", "graphql_introspection", "graphql_engine"},
         "corsy": {"cors_observation"}, "takeover": {"takeover_candidate"},
         "s3-review": {"s3_anonymous_list", "s3_acl_readable", "s3_public_acl"},
         "websocket": {"websocket_present", "websocket_cross_origin"}}
CORS_CLASSES = {"origin reflected", "post-domain wildcard", "pre-domain wildcard", "null origin allowed",
                "wildcard value", "third party allowed", "unrecognized underscore", "broken parser",
                "unescaped regex", "http origin allowed", "invalid value"}
REASONS = {
    "directory_url_required": "Requires a scoped directory URL ending in / without query parameters",
    "graphql_unconfirmed": "No GraphQL __typename metadata response was confirmed",
    "s3_root_required": "Requires an explicitly scoped AWS S3 REST bucket-root URL",
    "websocket_unconfirmed": "No valid RFC 6455 opening handshake; Socket.IO negotiation is outside this profile",
    "scope_blocked": "A request outside this profile was blocked",
    "request_budget": "Request budget reached", "deadline": "Profile deadline reached",
    "request_failed": "A scoped HTTP request failed", "rate_limited": "HTTP 429; profile stopped without retries",
    "redirect_not_followed": "Redirect not followed; review the exact endpoint URL",
    "response_limit": "Response sample exceeded 64 KiB", "dns_inconclusive": "DNS evidence was inconclusive",
    "engine_error": "Native profile error; raw diagnostics redacted",
}


def target_for(module, primary, discovered, values):
    field = {"graphw00f": "graphql_path", "corsy": "cors_path", "websocket": "websocket_path"}.get(module)
    explicit = getattr(values, field, "") if field else ""
    if explicit:
        return urljoin(urlsplit(primary)._replace(path="/", query="", fragment="").geturl(), explicit)
    if module in ("graphw00f", "websocket"):
        pattern = (r"/(?:graphql|gql)(?:/|$)" if module == "graphw00f"
                   else r"/(?:ws|websocket|socket)(?:/|$)")
        for candidate in [primary] + list(discovered or []):
            if (isinstance(candidate, str) and same_origin(candidate, primary)
                    and re.search(pattern, urlsplit(candidate).path, re.I)):
                # Archive query strings may contain credentials or another GraphQL
                # operation. Supply only this profile's metadata query/handshake.
                return urlsplit(candidate)._replace(query="", fragment="").geturl()
        return None
    if module == "vcs-artifacts" and (urlsplit(primary).query or urlsplit(primary).path and not urlsplit(primary).path.endswith("/")):
        return None
    if module == "s3-review" and bucket_target(primary) is None:
        return None
    return primary


def normalize(module, report, target):
    findings, seen = [], set()
    for item in report.get("observations", []):
        if not isinstance(item, dict) or item.get("kind") not in KINDS[module]:
            continue
        kind = item["kind"]
        name, risk = LABELS[kind]
        detail = ""
        if kind == "vcs_metadata":
            artifact = item.get("artifact")
            if artifact not in ("git_head", "git_config", "hg_requires", "svn_entries"):
                continue
            name += ": " + artifact.replace("_", " ")
            detail = "Structured " + artifact.replace("_", " ") + " metadata matched, distinct from a random missing-path response. No repository reconstruction, object/history download or credential extraction. File contents are redacted."
        elif kind == "graphql_engine":
            engine = item.get("engine")
            if not isinstance(engine, str) or not re.fullmatch(r"[a-z0-9_-]{1,50}", engine):
                continue
            detail = "Native engine candidate: " + engine + ". Signatures can be ambiguous."
        elif kind.startswith("graphql_"):
            detail = "Metadata-only observation; introspection is not itself a vulnerability. No schema reconstruction, application data, mutations or subscriptions."
        elif kind == "cors_observation":
            category = item.get("category")
            if category not in CORS_CLASSES:
                continue
            detail = "Native Corsy category: " + category + ". "
            name += ": " + category
            if category in {"origin reflected", "post-domain wildcard", "pre-domain wildcard", "null origin allowed"} and item.get("credential_candidate") is True:
                risk = "Medium"
                detail += "Credential-enabled policy candidate; authenticated response sensitivity and browser exploitability require manual validation."
            else:
                detail += "No credential-enabled browser exposure established. Wildcard ACAO with ACAC does not allow credentialed browser reads."
        elif kind == "takeover_candidate":
            provider = item.get("provider")
            evidence = item.get("evidence")
            if not isinstance(provider, str) or not re.fullmatch(r"[A-Za-z0-9 /()._-]{1,100}", provider) or evidence not in ("cname_and_nxdomain", "cname_and_literal_fingerprint"):
                continue
            name += ": " + provider
            detail = provider + "; evidence: " + evidence.replace("_", " ") + ". Candidate only; ownership verification/claimability is not proven. No service registration or binding attempted."
        elif kind == "s3_public_acl":
            permission = item.get("permission")
            if permission not in ("READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"):
                continue
            name += ": " + permission
            risk = "High" if permission in ("WRITE", "WRITE_ACP", "FULL_CONTROL") else "Medium"
            detail = "AllUsers ACL advertises " + permission + ". Metadata only; no write/delete was attempted and effective policy enforcement is not proven."
        elif kind.startswith("s3_"):
            detail = "Anonymous bucket-root metadata check. Public access may be intentional. No object contents, object names or owner identifiers retained."
        else:
            detail = "Opening handshake only; no frames, fuzzing or supplied credentials. Cross-origin anonymous acceptance alone does not prove authenticated WebSocket hijacking."
        key = (kind, detail)
        if key in seen:
            continue
        seen.add(key)
        findings.append(alert(module, name, target, detail + " Raw responses and native context are redacted.", risk, kind))
    return findings[:100]


async def run(module, url, host, agent, delay, discovered=None, inputs=None):
    values = inputs if isinstance(inputs, ModuleInputs) else ModuleInputs(**(inputs or {}))
    target = target_for(module, url, discovered, values)
    if target is None:
        reason = ("Requires an explicit same-origin endpoint path or a matching discovered URL"
                  if module in ("graphw00f", "websocket") else REASONS["directory_url_required"] if module == "vcs-artifacts" else REASONS["s3_root_required"])
        return {"source": module, "target": url, "status": "skipped", "alerts": [], "reason": reason, "output": reason}
    with tempfile.TemporaryDirectory(prefix="asfb-" + module + "-") as tmp:
        spec, output = Path(tmp) / "spec.json", Path(tmp) / "report.json"
        spec.write_text(json.dumps({"module": module, "target": target, "host": host, "agent": agent, "delay": delay}), encoding="utf-8")
        rows, status = await execute(["/opt/protocol/bin/python", "/app/app/protocol_runner.py", str(spec), str(output)], DEADLINES[module])
        report = read_report(output)
    if not isinstance(report, dict) or report.get("profile") != module or not isinstance(report.get("observations"), list):
        return {"source": module, "target": target, "status": status if status != "completed" else "failed",
                "alerts": [], "reason": "No valid bounded protocol report; native diagnostics redacted",
                "output": module + ": incomplete; no clean-scan claim"}
    findings = normalize(module, report, target)
    early_stop = (status == "completed" and report.get("status") == "partial"
                  and report.get("stop_reason") in POLICY_STOPS)
    if early_stop:
        status = "findings" if findings else "completed"
    if not early_stop and status == "completed" and report.get("status") in ("skipped", "partial", "failed"):
        status = report["status"]
    if not early_stop and status == "completed" and report.get("status") != "completed":
        status = "partial"
    if status == "completed" and findings:
        status = "findings"
    requests = report.get("requests", 0)
    requests = requests if type(requests) is int and 0 <= requests <= 64 else 0
    metadata = {"requests": requests, "observations": len(findings)}
    for key in ("excluded_probe_types", "provider_candidates"):
        value = report.get(key)
        if type(value) is int and 0 <= value <= 100:
            metadata[key] = value
    aliases = report.get("dns_aliases")
    if isinstance(aliases, list):
        metadata["dns_aliases"] = [name for name in aliases if isinstance(name, str) and re.fullmatch(r"[a-z0-9_.-]{1,253}", name)][:4]
    reason = REASONS.get(report.get("stop_reason"), "")
    if not reason:
        reason = {"graphw00f": "Native query-only fingerprinting and limited introspection; no schema reconstruction",
                  "corsy": "Native Corsy tests; supplied account credentials are not used",
                  "takeover": "Pinned provider data with CNAME corroboration; candidates require manual claimability review",
                  "s3-review": "S3 anonymous ListBucket max-keys=0 and ACL metadata; no object downloads or writes",
                  "websocket": "Two opening handshakes at most; no application frames or authenticated hijack testing",
                  "vcs-artifacts": "Five GETs: missing-path control and four structured VCS metadata checks; no reconstruction or history"}[module]
    if early_stop:
        reason = "Early stop: " + reason + "; policy enforced; coverage is incomplete"
    confirmed_graphql = module == "graphw00f" and any(item["rule_id"] == "graphql_present" for item in findings)
    return {"source": module, "target": target, "status": status, "alerts": findings, "metadata": metadata,
            "requests": requests, "deadline_seconds": DEADLINES[module], "reason": reason,
            **({"early_stop": True, "stop_reason": report["stop_reason"], "coverage_complete": False}
               if early_stop else {}),
            "endpoints": [target] if confirmed_graphql else [],
            "output": f"{module}: {len(findings)} observations; {requests} scoped HTTP requests; status: {status}; native context redacted"}
