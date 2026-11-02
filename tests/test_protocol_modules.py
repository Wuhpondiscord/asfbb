import asyncio
import base64
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import main, planning, protocol_modules as modules, protocol_runner as engine
from app.module_inputs import ModuleInputs
from app.scope import DNSResolutionFailed
from test_worker_pipeline import run_job


@pytest.mark.parametrize("field", ["graphql_path", "cors_path", "websocket_path"])
@pytest.mark.parametrize("path", ["https://outside.org/", "//outside.org/", "/api?token=secret", "/../api"])
def test_protocol_path_inputs_cannot_change_origin_or_embed_query_credentials(field, path):
    with pytest.raises(ValidationError):
        ModuleInputs(**{field: path})


def test_protocol_discovery_strips_archived_operations_and_rejects_other_origins():
    target = modules.target_for("graphw00f", "https://example.org/", [
        "https://outside.org/graphql", "http://example.org/graphql",
        "https://example.org:8080/graphql", "https://example.org/api/graphql?query=mutation%20Danger"],
        ModuleInputs())
    assert target == "https://example.org/api/graphql"
    assert modules.target_for("websocket", "https://example.org/", ["https://example.org/ws?token=secret"], ModuleInputs()) == "https://example.org/ws"


@pytest.mark.parametrize("module", ["graphw00f", "websocket", "s3-review"])
def test_inapplicable_protocol_profiles_skip_without_native_process(module):
    with patch.object(modules, "execute") as execute:
        result = asyncio.run(modules.run(module, "https://example.org/", "example.org", "Test", 1))
    assert result["status"] == "skipped" and not execute.called


@pytest.mark.parametrize("url,expected", [
    ("https://unit-bucket.s3.amazonaws.com/", True),
    ("https://unit-bucket.s3.us-east-1.amazonaws.com/", True),
    ("https://s3.amazonaws.com/unit-bucket/", True),
    ("https://unit-bucket.s3.amazonaws.com/object.txt", False),
    ("https://unit-bucket.s3-website-us-east-1.amazonaws.com/", False),
    ("https://unit-bucket.s3.amazonaws.com:8080/", False),
    ("https://unit-bucket.s3.amazonaws.com/?X-Amz-Signature=secret", False),
    ("https://s3.amazonaws.com/unit-bucket/object", False),
    ("https://s3.amazonaws.com/", False),
    ("https://unit-bucket.s3.amazonaws.com.outside.org/", False),
])
def test_s3_applicability_is_an_explicit_rest_bucket_root(url, expected):
    assert (engine.bucket_target(url) is not None) is expected


class Response:
    def __init__(self, code=200, headers=None, body=b""):
        self.status_code, self.headers, self.body = code, headers or {}, body
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def iter_content(self, size): yield self.body


class Session:
    def __init__(self, handler):
        self.handler, self.calls, self.closed, self.trust_env = handler, [], False, True
        self.cookie_clears = 0
        self.cookies = SimpleNamespace(clear=self.clear_cookies)
    def clear_cookies(self): self.cookie_clears += 1
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        assert kwargs["allow_redirects"] is False and kwargs["verify"] is True
        assert "Cookie" not in kwargs["headers"] and "Authorization" not in kwargs["headers"]
        return self.handler(method, url, kwargs)
    def close(self): self.closed = True


def spec(module, target="https://example.org/"):
    return {"module": module, "target": target, "host": "example.org", "agent": "Test", "delay": 1}


def run_profile(module, handler, target="https://example.org/", **engines):
    session = Session(handler)
    cfg = spec(module, target);cfg["host"] = engine.origin(target)[1]
    snapshots = []
    with patch.object(engine, "public_host"):
        result = engine.run(cfg, session, pause=lambda seconds: None,
                            checkpoint=lambda data: snapshots.append(json.loads(json.dumps(data))), **engines)
    assert session.closed and session.trust_env is False
    assert session.cookie_clears == len(session.calls)
    return result, session, snapshots


def test_transport_rejects_cross_origin_mutations_and_private_dns_before_http():
    session = Session(lambda *args: Response())
    net = engine.Transport(spec("corsy"), session, pause=lambda seconds: None)
    for method, url in (("POST", "https://example.org/"), ("GET", "https://outside.org/"), ("GET", "http://example.org/")):
        with pytest.raises(engine.Stopped, match="scope_blocked"):
            net.request(method, url)
    with patch.object(engine, "public_host", side_effect=ValueError("private")):
        with pytest.raises(ValueError):
            net.request("GET")
    assert session.calls == []


@pytest.mark.parametrize("code,reason", [(429, "rate_limited"), (302, "redirect_not_followed")])
def test_rate_limits_and_redirects_stop_without_followups(code, reason):
    result, session, _ = run_profile("websocket", lambda *args: Response(code), "https://example.org/ws")
    assert result["status"] == "partial" and result["stop_reason"] == reason
    assert len(session.calls) == 1


def test_transport_request_budget_and_header_only_reads():
    class NoBody(Response):
        def iter_content(self, size): raise AssertionError("Headers only")
    session = Session(lambda *args: NoBody())
    net = engine.Transport(spec("s3-review"), session, pause=lambda seconds: None)
    with patch.object(engine, "public_host"):
        net.request("GET", body=False);net.request("GET", body=False)
        with pytest.raises(engine.Stopped, match="request_budget"):
            net.request("GET", body=False)
    assert len(session.calls) == 2


def test_graphql_metadata_checkpoint_survives_native_profile_budget_failure():
    class Native:
        def __init__(self, **kwargs): pass
        def execute(self, url):
            self.graph_query(url, payload="mutation { update }")
            self.graph_query(url, payload="subscription { updates }")
            self.graph_query(url, payload="query { __typename ...A } fragment A on Query { ...A }")
            raise engine.Stopped("deadline")
    def handler(method, url, kwargs):
        query = (kwargs.get("json") or {}).get("query", "")
        assert "mutation" not in query and "fragment" not in query and "subscription" not in query
        result = {"data": {"__schema": {"queryType": {"name": "fixture-private-schema"}}}} if "__schema" in query else {"data": {"__typename": "Query"}}
        return Response(body=json.dumps(result).encode())
    result, session, snapshots = run_profile("graphw00f", handler, "https://example.org/graphql", engine_cls=Native)
    assert result["status"] == "partial" and len(session.calls) == 2
    assert {row["kind"] for row in result["observations"]} == {"graphql_present", "graphql_introspection"}
    assert any(row["observations"] for row in snapshots)
    assert "fixture-private" not in json.dumps(result)


def test_graphql_get_fallback_caches_identical_native_queries():
    class Native:
        def __init__(self, **kwargs): pass
        def execute(self, url):
            self.graph_query(url, payload="query{__typename}")
            return "test-engine"
    def handler(method, url, kwargs):
        if method == "POST": return Response(405)
        query = kwargs["params"]["query"]
        data = {"__schema": {"queryType": {"name": "Query"}}} if "__schema" in query else {"__typename": "Query"}
        return Response(body=json.dumps({"data": data}).encode())
    result, session, _ = run_profile("graphw00f", handler, "https://example.org/graphql", engine_cls=Native)
    assert result["status"] == "completed" and len(session.calls) == 3
    assert result["observations"][-1]["engine"] == "test-engine"


@pytest.mark.parametrize("category,credentials,risk", [
    ("origin reflected", True, "Medium"), ("origin reflected", False, "Informational"),
    ("wildcard value", True, "Informational"), ("unrecognized underscore", True, "Informational"),
])
def test_cors_never_equates_wildcards_or_non_browser_origins_with_credentials(category, credentials, risk):
    report = {"observations": [{"kind": "cors_observation", "category": category, "credential_candidate": credentials}]}
    result = modules.normalize("corsy", report, "https://example.org/")
    # Native normalization only grants credential risk to browser-reachable categories.
    assert result[0]["risk"] == risk


def test_s3_checks_only_listing_zero_keys_and_acl_metadata_redacting_owner_data():
    def handler(method, url, kwargs):
        assert method == "GET"
        if "acl" in kwargs["params"]:
            return Response(body=b'<AccessControlPolicy><Owner><ID>fixture-private-owner</ID></Owner><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>WRITE</Permission></Grant></AccessControlList></AccessControlPolicy>')
        assert kwargs["params"] == {"list-type": "2", "max-keys": "0"}
        return Response(body=b'<ListBucketResult><Name>unit-bucket</Name><KeyCount>0</KeyCount></ListBucketResult>')
    result, session, _ = run_profile("s3-review", handler, "https://unit-bucket.s3.amazonaws.com/")
    findings = modules.normalize("s3-review", result, "https://unit-bucket.s3.amazonaws.com/")
    assert len(session.calls) == 2 and any(row["risk"] == "High" for row in findings)
    assert "fixture-private" not in json.dumps(result) + json.dumps(findings)
    assert engine.xml_body(b'<!DOCTYPE a [<!ENTITY b "x">]><a>&b;</a>') is None


def test_websocket_accept_validation_and_origin_observation_do_not_imply_hijacking():
    def handler(method, url, kwargs):
        key = kwargs["headers"]["Sec-WebSocket-Key"]
        accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        return Response(101, {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Accept": accept})
    result, session, _ = run_profile("websocket", handler, "https://example.org/ws")
    assert len(session.calls) == 2
    findings = modules.normalize("websocket", result, "https://example.org/ws")
    assert len(findings) == 2 and all(row["risk"] == "Informational" for row in findings)
    assert all("does not prove" in row["description"] for row in findings)


def test_bad_websocket_accept_is_not_a_verified_handshake():
    result, session, _ = run_profile("websocket", lambda *args: Response(101, {"Upgrade": "websocket"}), "https://example.org/ws")
    assert result["status"] == "skipped" and not result["observations"] and len(session.calls) == 1


FINGERPRINT = {"service": "Microsoft Azure", "vulnerable": True, "cicd_pass": True,
               "cname": ["azurewebsites.net"], "nxdomain": True, "fingerprint": "NXDOMAIN"}


def test_takeover_requires_correlated_alias_and_provider_evidence_and_never_claims_services():
    for alias, expected in (("missing.azurewebsites.net", 1), ("azurewebsites.net.outside.org", 0)):
        resolve = lambda host: {"aliases": [alias], "nxdomain": True, "unknown": False}
        result, session, _ = run_profile("takeover", lambda *args: pytest.fail("HTTP forbidden"),
                                        resolve=resolve, fingerprints=[FINGERPRINT])
        assert len(result["observations"]) == expected and session.calls == []
        if expected:
            finding = modules.normalize("takeover", result, "https://example.org/")[0]
            assert "claimability is not proven" in finding["description"]


def test_vcs_metadata_uses_missing_path_control_and_never_downloads_objects():
    def handler(method, url, kwargs):
        assert method == "GET" and "/objects/" not in url
        if url.endswith(".git/config"):
            return Response(body=b'[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = fixture-private-credential\n')
        return Response(404, body=b"missing")
    result, session, _ = run_profile("vcs-artifacts", handler)
    assert len(session.calls) == 5 and result["observations"] == [{"kind": "vcs_metadata", "artifact": "git_config"}]
    assert "fixture-private" not in json.dumps(result)


def test_vcs_soft_404_that_looks_like_git_metadata_is_suppressed():
    result, session, _ = run_profile("vcs-artifacts", lambda *args: Response(body=b"ref: refs/heads/main"))
    assert len(session.calls) == 5 and result["observations"] == []


def test_protocol_adapter_keeps_partial_native_observations_but_redacts_unrecognized_fields():
    async def execute(args, timeout):
        cfg = json.loads(Path(args[-2]).read_text())
        assert cfg["target"] == "https://example.org/graphql"
        Path(args[-1]).write_text(json.dumps({"profile": "graphw00f", "status": "running", "requests": 1,
            "observations": [{"kind": "graphql_present", "raw": "fixture-private-value"}],
            "native_context": "fixture-private-error"}))
        return ["[stderr] fixture-private-value"], "timeout"
    with patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run("graphw00f", "https://example.org/", "example.org", "Test", 1,
                                        inputs=ModuleInputs(graphql_path="/graphql")))
    assert result["status"] == "timeout" and len(result["alerts"]) == 1
    assert "fixture-private" not in json.dumps(result)


def test_dns_fallback_does_not_relax_private_host_validation_or_normal_web_jobs():
    with patch.object(main, "public_host", side_effect=DNSResolutionFailed("DNS resolution failed")):
        main.validate_scan_host("example.org", ["takeover", "httpx"])
        with pytest.raises(DNSResolutionFailed):
            main.validate_scan_host("example.org", ["httpx"])
    with patch.object(main, "public_host", side_effect=ValueError("Private address")):
        with pytest.raises(ValueError):
            main.validate_scan_host("example.org", ["takeover"])


def test_unresolved_full_pipeline_runs_only_takeover_evidence():
    run, job = run_job(["gau", "takeover", "httpx"])
    async def review(name, *args, **kwargs):
        assert name == "takeover"
        return {"source": name, "status": "completed", "alerts": [], "metadata": {"requests": 0}}
    with patch.object(main, "public_host", side_effect=DNSResolutionFailed("DNS resolution failed")), \
         patch.object(main, "run_web_module", review), patch.object(main, "gau") as gau, patch.object(main, "probe") as probe:
        asyncio.run(run())
    assert job["pipeline"] == {"gau": "skipped", "takeover": "completed", "httpx": "skipped"}
    assert not gau.called and not probe.called


def test_guided_discovery_precedes_protocol_checks_and_manual_is_exact():
    requested = ["websocket", "graphw00f", "httpx", "kiterunner", "gau", "corsy"]
    guided = planning.plan(requested, "guided", True)["effective"]
    assert guided.index("gau") < guided.index("graphw00f")
    assert guided.index("kiterunner") < guided.index("websocket")
    assert guided.index("httpx") < guided.index("corsy")
    assert planning.plan(requested, "manual", True)["effective"] == requested


def test_protocol_paths_are_not_in_public_job_options():
    summary = ModuleInputs(graphql_path="/fixture-private-graphql", cors_path="/fixture-private-cors",
                           websocket_path="/fixture-private-ws").public_summary()
    assert summary["graphql_configured"] and summary["cors_configured"] and summary["websocket_configured"]
    assert "fixture-private" not in json.dumps(summary)


def test_unresolved_takeover_job_can_be_queued_but_private_targets_stay_rejected():
    main.assets.clear();main.jobs.clear();main.queue = asyncio.Queue()
    async def no_scan(*args): pass
    with TestClient(main.app) as client, patch.object(main, "run_scan_job", no_scan):
        owner = client.get("/api/health").headers["x-asfb-session"]
        main.assets["dns"] = {"id": "dns", "owner": owner, "name": "https://dangling.example.org/",
                              "compatibility": "web", "type": "URL"}
        body = {"asset_id": "dns", "modules": ["takeover", "httpx"],
                "policy_confirmed": True, "active_confirmed": True}
        with patch.object(main, "public_host", side_effect=DNSResolutionFailed("DNS resolution failed")):
            response = client.post("/api/scans", json=body)
            assert response.status_code == 200, response.text
        with patch.object(main, "public_host", side_effect=ValueError("Private address")):
            assert client.post("/api/scans", json=body).status_code == 422


@pytest.mark.parametrize("value,expected", [("null", True), ("https://example.org", True),
    ("https://example.org:8080.example.com", False), ("https://example.org/path", False),
    ("https://example.org_.outside.org", False)])
def test_browser_origin_proof_excludes_malformed_native_probe_origins(value, expected):
    assert engine.browser_origin(value) is expected


def test_vcs_pattern_like_missing_control_is_suppressed_even_with_different_branches():
    def handler(method, url, kwargs):
        branch = "missing" if ".asfb-missing-" in url else "main"
        return Response(body=("ref: refs/heads/" + branch).encode())
    result, _, _ = run_profile("vcs-artifacts", handler)
    assert result["observations"] == []


def test_all_registered_modules_have_an_acyclic_guided_plan_without_auto_enabling():
    requested = list(planning.MODULES)
    result = planning.plan(requested, "guided", True)
    assert set(result["effective"]) == set(requested) and len(result["effective"]) == len(requested)
    assert not result["warnings"]
    assert planning.plan(result["effective"], "guided", True)["effective"] == result["effective"]
