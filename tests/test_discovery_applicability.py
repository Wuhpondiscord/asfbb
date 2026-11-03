"""Offline regressions for 404 route pollution and parameter-discovery selection."""
import asyncio
import base64
import json
from unittest.mock import patch

import pytest

from app import final_modules, main, review
from app.module_inputs import ModuleInputs
from test_worker_pipeline import run_job


def test_kiterunner_only_promotes_observed_successes_and_keeps_response_evidence():
    def record(path, response, method="GET"):
        return json.dumps({"method": method, "target": base64.b64encode(b"https://example.org").decode(),
                           "path": base64.b64encode(path.encode()).decode(), "responses": response})
    async def execute(args, timeout):
        return [record("/ok", [{"sc": 200}]), record("/missing", [{"sc": 404}]),
                record("/gone", [{"sc": 410}]), record("/redirect", [{"sc": 302}, {"sc": 200}]),
                record("/empty", []), record("/unknown", [{}]), record("/wrong-type", [{"sc": "200"}]),
                record("/post", [{"sc": 200}], "POST"),
                json.dumps({"method": "GET", "url": "https://outside.org/", "responses": [{"sc": 200}]})], "completed"
    with patch.object(final_modules, "execute", execute):
        result = asyncio.run(final_modules.run("kiterunner", "https://example.org/", "example.org", "Test", 1,
                                             ModuleInputs(api_target=True)))
    assert result["endpoints"] == ["https://example.org/ok"]
    assert result["probes"] == [{"url": "https://example.org/ok", "status_code": 200, "source": "kiterunner"}]


def test_live_page_beats_unprobed_api_name_and_known_missing_route():
    primary = "https://example.org"
    urls = ["https://example.org/api/v1", "https://example.org/api/v2", "https://example.org/home"]
    probes = [{"url": "https://example.org/", "status_code": 200},
              {"url": urls[0], "status_code": 404}, {"url": urls[2], "status_code": 200}]
    chosen = review.choose_arjun_targets(primary, urls, "example.org", probes)
    assert chosen[:2] == [primary, urls[2]]
    assert urls[0] not in chosen and chosen[-1] == urls[1]


def test_missing_root_and_static_inventory_yield_no_applicable_parameter_endpoint():
    assert review.choose_arjun_targets("https://example.org", ["https://example.org/app.js",
        "http://example.org/api", "https://example.org:8080/api"], "example.org",
        [{"url": "https://example.org/", "status_code": 404}]) == []


@pytest.mark.parametrize("code", [401, 403, 429, 500, 503])
def test_authentication_and_provider_errors_remain_visible_candidates(code):
    assert review.choose_arjun_targets("https://example.org", [], "example.org",
        [{"url": "https://example.org/", "status_code": code}]) == ["https://example.org"]


def worker_with_reuse(modules):
    run, job = run_job(modules)
    original = main.queue.put
    async def put(item):
        identifier, spec = item
        spec.options.reuse_discovery = True
        await original((identifier, spec))
    return run, job, put


def test_worker_uses_observed_live_root_instead_of_missing_api_path():
    run, job, put = worker_with_reuse(["gau", "httpx", "arjun"])
    seen = []
    async def gau(*args):
        return {"status": "completed", "endpoints": ["https://example.com/api/v1"]}
    async def probe(*args):
        return {"status": "completed", "probes": [
            {"url": "https://example.com/", "status_code": 200},
            {"url": "https://example.com/api/v1", "status_code": 404}]}
    async def inspect(module, url, host, **kwargs):
        seen.append(url)
        return {"status": "completed", "parameters": []}
    with patch.object(main.queue, "put", put), patch.object(main, "public_host"), \
         patch.object(main, "gau", gau), patch.object(main, "probe", probe), patch.object(main, "review", inspect):
        asyncio.run(run())
    assert seen == ["https://example.com"] and job["status"] == "completed"


@pytest.mark.parametrize("all_missing,expected", [(False, "completed"), (True, "skipped")])
def test_worker_falls_back_only_after_missing_baseline_and_caps_attempts(all_missing, expected):
    run, job, put = worker_with_reuse(["gau", "arjun"])
    seen = []
    async def gau(*args):
        return {"status": "completed", "endpoints": ["https://example.com/api/one",
            "https://example.com/api/two", "https://example.com/api/three", "https://example.com/api/four"]}
    async def inspect(module, url, host, **kwargs):
        seen.append(url)
        if all_missing or len(seen) == 1:
            return {"status": "partial", "target": url, "parameters": [], "metadata": {
                "stop_reason": "endpoint_unavailable", "http_status": 404, "requests": 1}}
        return {"status": "completed", "target": url, "parameters": []}
    with patch.object(main.queue, "put", put), patch.object(main, "public_host"), \
         patch.object(main, "gau", gau), patch.object(main, "review", inspect):
        asyncio.run(run())
    assert job["pipeline"]["arjun"] == expected
    assert len(seen) == (3 if all_missing else 2)
    assert job["status"] == "completed"
    event = next(e for e in main.scan_events if e.get("event") == "stage_finished" and e.get("module") == "arjun")
    assert event["diagnostics"]["parameter_review"]["attempted_endpoints"] == len(seen)


def test_worker_skips_known_missing_root_without_starting_arjun():
    run, job, put = worker_with_reuse(["httpx", "arjun"])
    async def probe(*args):
        return {"status": "completed", "probes": [{"url": "https://example.com/", "status_code": 404}]}
    with patch.object(main.queue, "put", put), patch.object(main, "public_host"), \
         patch.object(main, "probe", probe), patch.object(main, "review") as inspect:
        asyncio.run(run())
    assert not inspect.called and job["pipeline"]["arjun"] == "skipped"
    assert job["status"] == "completed"


@pytest.mark.parametrize("requests,code", [(2, 404), (1, 403), (1, 429)])
def test_worker_does_not_hide_mid_scan_or_non_missing_errors(requests, code):
    run, job, put = worker_with_reuse(["arjun"])
    async def inspect(*args, **kwargs):
        return {"status": "partial", "parameters": [], "metadata": {
            "stop_reason": "endpoint_unavailable", "http_status": code, "requests": requests}}
    with patch.object(main.queue, "put", put), patch.object(main, "public_host"), patch.object(main, "review", inspect):
        asyncio.run(run())
    assert job["status"] == "partial" and job["pipeline"]["arjun"] == "partial"
