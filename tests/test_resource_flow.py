import asyncio
import json
from unittest.mock import patch

import httpx
import pytest

from app import request_policy as policy
from app.resource_flow import Flow
from app.module_inputs import ModuleInputs
from app.replay_inputs import RaceReplay, NoSQLReplay
from app.client_modules import retire_components
from app.planning import plan


def operation(input_name, output_name, path):
    return {"post": {"operationId": path,
        "requestBody": {"content": {"application/json": {"schema": {"type": "object",
            "properties": {input_name: {"type": "string"}}}}}},
        "responses": {"200": {"content": {"application/json": {"schema": {"type": "object",
            "properties": {output_name: {"type": "string" if output_name == "response" else "boolean"}}}}}}}}}


def test_openapi_generates_review_only_drafts_without_inventing_fixtures():
    token = policy.CURRENT.set({"target": "https://example.org/"})
    flow = Flow("https://example.org/")
    doc = {"openapi": "3.0.0", "paths": {
        "/api/generate": operation("prompt", "response", "llm-generate"),
        "/api/search": operation("reference", "found", "search"),
        "/api/redeem": operation("ticket", "accepted", "redeem")}}
    flow.inspect("https://example.org/openapi.json", "application/json", json.dumps(doc).encode())
    assert {s["kind"] for s in flow.suggestions} == {"garak", "nosql", "race-replay"}
    assert all(s["review_required"] for s in flow.suggestions)
    for candidate in flow.suggestions:
        if candidate["kind"] == "nosql":
            with pytest.raises(ValueError): NoSQLReplay(**candidate["inputs"]["nosql"])
        if candidate["kind"] == "race-replay":
            with pytest.raises(ValueError): RaceReplay(**candidate["inputs"]["race"])
    policy.CURRENT.reset(token)


def test_untrusted_openapi_shapes_are_not_treated_as_confirmed_endpoints():
    token = policy.CURRENT.set({"target": "https://example.org/"})
    flow = Flow("https://example.org/")
    for request in (True, "invalid", {"content": []}):
        flow.inspect("https://example.org/spec.json", "application/json", json.dumps({
            "openapi": "3.0.0", "paths": {"/api/generate": {"post": {"requestBody": request, "responses": []}}}}).encode())
    assert not flow.suggestions
    policy.CURRENT.reset(token)


def test_complete_js_samples_feed_source_tools_without_enabling_credential_verification():
    flow = Flow("https://example.org/")
    flow.samples["https://example.org/app.js"] = (b"const fixture = 'private-source';", "application/javascript", "https://example.org/app.js")
    values, provenance = flow.inputs_for("trufflehog", ModuleInputs(trufflehog_verify=True))
    assert values.source_text and values.trufflehog_verify is False
    assert provenance["source"] == "observed-javascript"
    assert "private-source" not in json.dumps(flow.public())
    explicit = ModuleInputs(source_text="user-supplied", sast_language="python", trufflehog_verify=True)
    assert flow.inputs_for("trufflehog", explicit)[0] is explicit


def test_retire_inventory_without_findings_feeds_bounded_unverified_sbom():
    components = retire_components({"data": [{"results": [{"component": "jquery", "version": "3.6.0", "vulnerabilities": []},
        {"component": "unknown-package", "version": "1.0.0"}, {"component": "react", "version": "18"}]}]})
    flow = Flow("https://example.org/"); flow.ingest_components(components)
    inputs, evidence = flow.inputs_for("osv-scanner", ModuleInputs())
    bom = json.loads(inputs.sbom_text)
    assert len(bom["components"]) == 1 and bom["components"][0]["purl"] == "pkg:npm/jquery@3.6.0"
    assert evidence["verification"] == "unverified package mapping"


def test_resource_check_caches_complete_scripts_and_never_follows_external_links():
    seen = []
    def handler(request):
        seen.append(str(request.url))
        assert request.headers["X-HackerOne-Research"] == "fixture"
        if request.url.path == "/":
            return httpx.Response(200, headers={"Content-Type": "text/html"},
                text='<script src="/app.js"></script><script src="https://outside.example/foreign.js"></script>')
        return httpx.Response(200, headers={"Content-Type": "application/javascript"}, text="const source = 'private-js';")
    original = httpx.AsyncClient
    def factory(**kwargs):
        return original(transport=httpx.MockTransport(handler), **kwargs)
    async def noop(*args): pass
    async def run():
        token = policy.CURRENT.set({"target": "https://example.org/", "headers": {"X-HackerOne-Research": "fixture"}})
        flow = Flow("https://example.org/", 3); flow.add(flow.primary, "scope")
        with patch("app.resource_flow.public_host"), patch("app.resource_flow.httpx.AsyncClient", factory), \
             patch.object(flow.pacer, "await_turn", noop):
            await flow.check_new("Fixture")
            await flow.check_new("Fixture")
            await flow.check_new("Fixture")
        assert len(seen) == 2 and flow.records["https://example.org/app.js"]["kind"] == "javascript"
        assert flow.samples["https://example.org/app.js"][0].startswith(b"const source")
        assert all("outside.example" not in row["url"] for row in flow.public()["resources"])
        assert "private-js" not in json.dumps(flow.public())
        policy.CURRENT.reset(token)
    asyncio.run(run())


def test_guided_artifact_consumers_follow_their_producers_but_manual_order_remains_custom():
    requested = ["osv-scanner", "retirejs", "semgrep", "katana", "httpx", "trufflehog"]
    guided = plan(requested, "guided", True)["effective"]
    assert guided.index("katana") < guided.index("httpx") < guided.index("semgrep")
    assert guided.index("retirejs") < guided.index("osv-scanner")
    assert plan(requested, "manual", True)["effective"] == requested
