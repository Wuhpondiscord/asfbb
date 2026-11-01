import asyncio
import json
from unittest.mock import patch
from app import main, review
from test_worker_pipeline import run_job

def test_ffuf_keeps_only_observed_in_scope_successes():
    lines = [json.dumps({"status":200,"url":"https://example.org/health"}),
             json.dumps({"status":301,"url":"https://example.org/admin",
                         "redirectlocation":"https://other.org/"}),
             json.dumps({"status":200,"url":"https://other.org/private"})]
    assert review.ffuf_discoveries(lines, "example.org") == ["https://example.org/health"]

def test_ffuf_urls_feed_later_passive_probe_stage():
    execute_job, job = run_job(["ffuf", "httpx"])
    async def fake_review(*args):
        return {"status":"completed","source":"ffuf","output":"",
                "endpoints":["https://example.com/health",
                             "https://other.org/bad"]}
    async def fake_probe(targets, host, agent, limit):
        assert "https://example.com/health" in targets
        assert "https://other.org/bad" not in targets
        return {"status":"completed","probes":[]}
    with patch.object(main,"public_host",return_value=None), \
         patch.object(main,"review",fake_review), \
         patch.object(main,"probe",fake_probe):
        asyncio.run(execute_job())
    assert job["status"] == "completed", job["error"]
    assert job["endpoint_sources"]["https://example.com/health"] == ["ffuf"]
