import asyncio
from unittest.mock import patch

from app import main
from test_worker_pipeline import run_job


def test_program_origin_filters_archive_handoffs_before_http_probes():
    run, job = run_job(["gau", "httpx"])
    original_put = main.queue.put
    async def put(item):
        key, spec = item
        spec._program_origin = True
        await original_put((key, spec))
    async def gau(*args):
        return {"status": "completed", "endpoints": [
            "https://example.com/help", "http://example.com/wrong-scheme",
            "https://example.com:8080/wrong-port", "https://other.example.com/wrong-host"]}
    async def probe(urls, *args):
        assert urls == ["https://example.com", "https://example.com/help"]
        return {"status": "completed", "probes": []}
    with patch.object(main, "public_host"), patch.object(main, "gau", gau), \
         patch.object(main, "probe", probe), patch.object(main.queue, "put", put):
        asyncio.run(run())
    assert job["status"] == "completed"
    assert job["endpoints"] == ["https://example.com/help"]
