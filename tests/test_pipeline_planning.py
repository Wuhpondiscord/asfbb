import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import main, pipeline, planning, review
from app.coverage import profile
from app.module_inputs import ModuleInputs
from test_worker_pipeline import run_job


def test_guided_order_moves_enabled_producers_before_consumers_only():
    requested = ["sqlmap", "nuclei", "arjun", "httpx", "ffuf", "katana", "gau"]
    result = planning.plan(requested, "guided", True)
    order = result["effective"]
    assert set(order) == set(requested) and len(order) == len(requested)
    assert order.index("gau") < order.index("katana")
    assert max(order.index(m) for m in ("ffuf", "katana", "gau")) < order.index("httpx")
    assert order.index("httpx") < order.index("arjun") < order.index("sqlmap")
    assert not result["warnings"]
    assert planning.plan(order, "guided", True)["effective"] == order


def test_manual_order_is_exact_and_reports_unavailable_handoffs():
    requested = ["sqlmap", "arjun", "katana", "gau"]
    result = planning.plan(requested, "manual", True)
    assert result["effective"] == requested
    assert result["warnings"]
    assert any(not handoff["available"] for handoff in result["handoffs"])


@pytest.mark.parametrize("modules", [[], ["gau", "gau"], ["unknown"]])
def test_invalid_plans_cannot_enable_unknown_or_duplicate_modules(modules):
    with pytest.raises(ValueError):
        planning.plan(modules, "guided")


def test_scoped_seed_selection_excludes_assets_and_other_origins():
    seeds = planning.crawl_seeds("https://example.org/", [
        "https://example.org/search?q=1", "https://outside.org/", "http://example.org/",
        "https://example.org:8080/", "https://example.org/app.js", "https://example.org/help"])
    assert seeds == ["https://example.org/", "https://example.org/help",
                     "https://example.org/search?q=1"]


def test_probe_metadata_selects_a_real_html_page_without_expanding_scope():
    probes = [{"url": "https://example.org/", "status_code": 308},
              {"url": "https://outside.org/", "status_code": 200, "content_type": "text/html"},
              {"url": "https://example.org/api", "status_code": 200, "content_type": "application/json"},
              {"url": "https://example.org/home", "status_code": 200, "content_type": "text/html"}]
    assert planning.page_target("https://example.org/", probes) == "https://example.org/home"
    urls = planning.assessed_urls("https://example.org/", [
        "https://example.org/gone", "https://example.org/home", "https://outside.org/"],
        probes + [{"url": "https://example.org/gone", "status_code": 404}])
    assert urls[0] == "https://example.org/home" and "https://example.org/gone" not in urls


def test_katana_receives_a_bounded_same_origin_seed_file_and_keeps_scoping():
    async def execute(args, timeout):
        seeds = Path(args[args.index("-list") + 1]).read_text().splitlines()
        assert seeds == ["https://example.org/", "https://example.org/help"]
        assert timeout == profile("balanced")["katana_timeout"]
        assert args[args.index("-fs") + 1] == "fqdn"
        assert args[args.index("-c") + 1] == "1"
        assert args[args.index("-p") + 1] == "1"
        assert "-cs" in args
        return ["https://example.org/help", "https://outside.org/no"], "completed"
    with patch.object(pipeline, "execute", execute):
        result = asyncio.run(pipeline.katana("https://example.org/", "example.org", "Test",
            seed_urls=["https://example.org/help", "https://outside.org/no"], coverage_profile="balanced"))
    assert result["seed_count"] == 2 and result["endpoints"] == ["https://example.org/help"]


def test_planner_endpoint_does_not_run_scanners_or_queue_jobs():
    main.queue = asyncio.Queue()
    with TestClient(main.app) as client, patch.object(main, "run_scan_job") as run:
        result = client.post("/api/pipeline/plan", json={
            "modules": ["sqlmap", "arjun", "gau"], "order_mode": "guided",
            "reuse_discovery": True, "coverage_profile": "balanced"})
        assert result.status_code == 200
        assert result.json()["effective"] == ["gau", "arjun", "sqlmap"]
        assert result.json()["budgets"]["retire_files"] == 16
        assert main.queue.empty() and not run.called


def test_queued_job_records_the_previewed_plan_but_manual_remains_exact():
    main.jobs.clear()
    main.queue = asyncio.Queue()
    async def no_scan(*args): pass
    with patch.object(main, "public_host"), patch.object(main, "run_scan_job", no_scan), \
         TestClient(main.app) as client:
        owner = client.get("/api/health").headers["x-asfb-session"]
        main.assets["plan-target"] = {"id": "plan-target", "owner": owner,
            "name": "https://example.org/", "compatibility": "web"}
        body = {"asset_id": "plan-target", "policy_confirmed": True, "active_confirmed": True,
                "modules": ["sqlmap", "arjun", "gau"],
                "options": {"order_mode": "guided", "coverage_profile": "balanced"}}
        response = client.post("/api/scans", json=body)
        assert response.status_code == 200
        job = main.jobs[response.json()["id"]]
        assert job["modules"] == ["gau", "arjun", "sqlmap"]
        assert job["plan"]["requested"] == body["modules"]
        body["options"]["order_mode"] = "manual"
        response = client.post("/api/scans", json=body)
        assert main.jobs[response.json()["id"]]["modules"] == body["modules"]


def test_worker_reuses_archive_inventory_as_katana_seeds_when_opted_in():
    run, job = run_job(["gau", "katana"])
    # The test helper queues a ScanRequest; use the actual production worker but
    # supply the opt-in option by intercepting the first queued request.
    async def gau(*args):
        return {"status": "completed", "endpoints": ["https://example.com/help"]}
    async def katana(*args, **kwargs):
        assert "https://example.com/help" in kwargs["seed_urls"]
        return {"status": "completed", "endpoints": [], "seed_count": 2}
    original_put = main.queue.put
    async def put(item):
        key, spec = item
        spec.options.reuse_discovery = True
        await original_put((key, spec))
    with patch.object(main, "public_host"), patch.object(main, "gau", gau), \
         patch.object(main, "katana", katana), patch.object(main.queue, "put", put):
        asyncio.run(run())
    assert job["status"] == "completed"
    assert any(event["event"] == "data_handoff" for event in main.scan_events)


@pytest.mark.parametrize("name", ["quick", "balanced", "thorough"])
def test_dalfox_profiles_balance_payloads_and_internal_external_deadlines(name):
    settings = profile(name)
    args = review.command("dalfox", "https://example.org/?q=1", "example.org", name)
    assert int(args[args.index("--max-payloads-per-param") + 1]) == settings["dalfox_payloads"]
    assert int(args[args.index("--scan-timeout") + 1]) == settings["dalfox_scan_seconds"]
    assert settings["dalfox_timeout"] > settings["dalfox_scan_seconds"]
    assert "--skip-mining" in args and "--skip-waf-probe" in args


def test_invalid_profile_or_mode_is_rejected():
    for options in ({"coverage_profile": "unlimited"}, {"order_mode": "guess"}):
        with pytest.raises(ValidationError):
            main.PipelineOptions(**options)

def test_equivalent_root_urls_do_not_consume_the_extra_archive_seed_slot():
    assert planning.crawl_seeds("https://example.org", [
        "https://example.org/", "https://example.org/#top", "https://example.org:443/",
        "https://example.org/help"], maximum=2) == ["https://example.org", "https://example.org/help"]

def test_katana_stays_on_exact_origin_without_discovery_reuse():
    async def execute(args, timeout):
        assert "-dr" in args
        scope = args[args.index("-cs") + 1]
        import re
        assert re.search(scope, "https://example.org/help")
        assert not re.search(scope, "http://example.org/help")
        assert not re.search(scope, "https://example.org:8080/help")
        assert not re.search(scope, "https://other.example.org/help")
        return [], "completed"
    with patch.object(pipeline, "execute", execute):
        asyncio.run(pipeline.katana("https://example.org/", "example.org", "Fixture"))
