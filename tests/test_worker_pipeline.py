import asyncio
from unittest.mock import AsyncMock, patch
from app import main

def run_job(modules):
    main.assets.clear()
    main.jobs.clear()
    main.scan_events.clear()
    main.queue = asyncio.Queue()
    owner = "unit-session"
    asset_id = "unit-target"
    main.assets[asset_id] = {"id": asset_id, "name": "https://example.com",
                            "compatibility": "web", "owner": owner}
    spec = main.ScanRequest(asset_id=asset_id, modules=modules)
    job_id = "unit-job"
    main.jobs[job_id] = {"owner": owner, "id": job_id, "asset_id": asset_id,
        "target": "https://example.com", "status": "queued", "alerts": [],
        "error": None, "request_count": 0, "cancelled": False,
        "modules": modules, "endpoints": [], "pipeline": {}, "probes": [],
        "reviews": [], "progress": 0, "stage": "queued"}
    async def execute_job():
        await main.queue.put((job_id, spec))
        task = asyncio.create_task(main.worker())
        try:
            await asyncio.wait_for(main.queue.join(), timeout=5)
        finally:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    return execute_job, main.jobs[job_id]

def test_worker_discovery_and_probe():
    execute_job, job = run_job(["gau", "katana", "httpx"])
    async def gau(*args):
        return {"status":"completed","endpoints":["https://example.com/a"]}
    async def katana(*args):
        return {"status":"completed","endpoints":["https://example.com/b"]}
    async def probe(*args):
        assert "https://example.com/a" in args[0]
        assert "https://example.com/b" in args[0]
        return {"status":"completed","probes":[{"url":"https://example.com/a"}]}
    with patch.object(main,"public_host", return_value=None), patch.object(main,"gau",gau), patch.object(main,"katana",katana),patch.object(main,"probe",probe):
        asyncio.run(execute_job())
    assert job["status"] == "completed", job["error"]
    assert job["progress"] == 100
    assert job["endpoint_sources"]["https://example.com/a"] == ["gau"]
    assert len(job["probes"]) == 1

def test_worker_zap_stage_resolves_scope_checker():
    execute_job, job = run_job(["zap-passive"])
    class MockResponse:
        status_code = 200
    class AsyncClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **kw): return MockResponse()
    async def zap_call(*args, **kwargs):
        return {"alerts":[{"name":"Mock alert","risk":"Low","confidence":"High","url":"https://example.com/"}]}
    with patch.object(main,"public_host",return_value=None),patch.object(main.httpx,"AsyncClient",return_value=AsyncClient()),patch.object(main,"zap_call",zap_call),patch.object(main.asyncio,"sleep",new_callable=AsyncMock):
        asyncio.run(execute_job())
    assert job["status"] == "completed", job["error"]
    assert job["request_count"] == 1
    assert job["alerts"][0]["source"] == "zap"

def test_worker_combined_modules_and_sources():
    execute_job, job = run_job(["katana","nuclei"])
    async def katana(*args):
        return {"status":"completed","endpoints":["https://example.com/a"]}
    async def nuclei(*args):
        return {"status":"completed","alerts":[{"source":"nuclei","name":"Technology","url":"https://example.com/"}]}
    with patch.object(main,"public_host",return_value=None),patch.object(main,"katana",katana),patch.object(main,"nuclei",nuclei):
        asyncio.run(execute_job())
    assert job["status"] == "completed", job["error"]
    assert job["pipeline"] == {"katana":"completed","nuclei":"completed"}
    assert job["alerts"][0]["source"] == "nuclei"
