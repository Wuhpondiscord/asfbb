import asyncio
from unittest.mock import patch

from app import main
from test_worker_pipeline import run_job


def test_mismatched_account_skips_zap_but_continues_active_stage():
    run, job = run_job(["zap-passive", "arjun"])
    original_put = main.queue.put
    async def put(item):
        key, spec = item
        spec._zap_skip_reason = "Selected account belongs to another hostname"
        await original_put((key, spec))
    async def review(*args, **kwargs):
        return {"status": "completed", "output": "fixture", "parameters": [], "metadata": {}}
    with patch.object(main, "public_host"), patch.object(main, "review", review), \
         patch.object(main.queue, "put", put), patch.object(main.httpx, "AsyncClient") as client:
        asyncio.run(run())
    assert job["pipeline"] == {"zap-passive": "skipped", "arjun": "completed"}
    assert job["status"] == "completed" and not client.called
