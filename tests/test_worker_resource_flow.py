"""Real worker handoffs with private in-memory fixtures, no HTTP/scanner execution."""
import asyncio
import json
from unittest.mock import patch

from app import main
from app.resource_flow import Flow
from test_worker_pipeline import run_job


def test_checked_javascript_reaches_sast_and_retire_inventory_reaches_sca():
    run, job = run_job(["retirejs", "semgrep", "osv-scanner"])
    original_put = main.queue.put
    observed = []
    async def put(item):
        key, spec = item
        spec.options.reuse_discovery = True
        spec.options.resource_handoffs = True
        await original_put((key, spec))
    def flow_factory(url, maximum):
        flow = Flow(url, maximum)
        flow.samples["https://example.com/app.js"] = (
            b"const example = 'fixture-private-source';", "application/javascript", "https://example.com/app.js")
        return flow
    async def web(module, url, host, agent, delay, discovered, inputs, **kwargs):
        observed.append(module)
        if module == "retirejs":
            return {"status": "completed", "alerts": [], "components": [{"component": "jquery", "version": "3.6.0"}]}
        if module == "semgrep":
            assert "fixture-private-source" in inputs.source_text
            assert inputs.sast_language == "javascript" and inputs.trufflehog_verify is False
        if module == "osv-scanner":
            assert json.loads(inputs.sbom_text)["components"][0]["purl"] == "pkg:npm/jquery@3.6.0"
        return {"status": "completed", "alerts": [], "output": "fixture"}
    with patch.object(main, "public_host"), patch.object(main, "Flow", flow_factory), \
         patch.object(main, "run_web_module", web), patch.object(main.queue, "put", put):
        asyncio.run(run())
    assert observed == ["retirejs", "semgrep", "osv-scanner"]
    assert job["status"] == "completed"
    assert job["discovery"]["dependency_candidates"] == 1
    assert "fixture-private-source" not in json.dumps(job)
    assert job["stage_details"]["semgrep"]["reason"].endswith("evidence remains unverified")
