import asyncio
from unittest.mock import AsyncMock, patch
from app import main
from test_worker_pipeline import run_job

def test_zap_polling_reports_incomplete_passive_results():
    execute_job, job = run_job(["zap-passive"])
    class Response:
        status_code = 200
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def get(self, *a, **kw): return Response()
    async def api(*args, **kwargs):
        if args[1] == "pscan":
            return {"recordsToScan": "3"}
        return {"alerts": []}
    with patch.object(main, "public_host", return_value=None), \
         patch.object(main.httpx, "AsyncClient", return_value=Client()), \
         patch.object(main, "zap_call", api), \
         patch.object(main.asyncio, "sleep", new_callable=AsyncMock):
        asyncio.run(execute_job())
    assert job["pipeline"]["zap-passive"] == "partial"
    assert job["status"] == "partial"
    assert "pending" in job["stage_details"]["zap-passive"]["reason"]

def test_arjun_parameter_data_stored_in_job():
    execute_job, job = run_job(["arjun"])
    async def fake(module, url, host):
        return {"source": module, "status":"completed", "output":"",
                "parameters":[{"url":"https://example.com/path","method":"GET",
                               "name":"page","source":"arjun"},
                              {"url":"https://other.com/","method":"GET",
                               "name":"secret","source":"arjun"}]}
    with patch.object(main,"public_host",return_value=None), \
         patch.object(main,"review",fake):
        asyncio.run(execute_job())
    assert len(job["parameters"]) == 1
    assert job["parameters"][0]["name"] == "page"
