import asyncio
from unittest.mock import patch

import httpx
import pytest

from app import main
from test_worker_pipeline import run_job


@pytest.mark.parametrize("failed_action", ["view/recordsToScan", "view/alerts"])
def test_zap_api_failure_records_stage_failure_and_runs_next_module(failed_action):
    execute_job, job = run_job(["zap-passive", "httpx"])

    class Response:
        status_code = 200

    class Client:
        async def __aenter__(self):
            return self
        async def __aexit__(self, *args):
            return False
        async def get(self, *args, **kwargs):
            return Response()

    async def zap_call(client, component, action, params):
        if action == failed_action:
            raise httpx.ReadTimeout("mock local ZAP timeout")
        return {"recordsToScan": 0, "alerts": []}

    async def probe(*args):
        return {"status": "completed", "probes": []}

    async def no_sleep(*args):
        pass

    with patch.object(main, "public_host", return_value=None), \
         patch.object(main.httpx, "AsyncClient", return_value=Client()), \
         patch.object(main, "zap_call", zap_call), \
         patch.object(main, "probe", probe), \
         patch.object(main.asyncio, "sleep", no_sleep):
        asyncio.run(execute_job())

    assert job["status"] == "partial"
    assert job["pipeline"] == {"zap-passive": "failed", "httpx": "completed"}
    details = job["stage_details"]["zap-passive"]
    assert details["reason"] == "Module exception: ReadTimeout"
    assert "global queued passive records: unknown" in details["summary"]
    assert "Module exception: ReadTimeout" in details["summary"]
    assert any(event["event"] == "stage_finished" and
               event.get("module") == "httpx" for event in main.scan_events)
