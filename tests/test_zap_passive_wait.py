import asyncio
from unittest.mock import AsyncMock, patch
from app import main


def test_zap_waits_for_passive_queue_and_queries_origin_with_pagination():
    from test_worker_pipeline import run_job
    run,job=run_job(["zap-passive"])
    queries=[]
    class FakeResponse:
        status_code=200
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self,*args): return False
        async def get(self,*args,**kwargs): return FakeResponse()
    pending=[2,1,0]
    async def fake_zap_call(client,component,endpoint,params):
        queries.append((component,endpoint,params))
        if endpoint=="view/recordsToScan":
            return {"recordsToScan": pending.pop(0)}
        if endpoint=="view/alerts":
            assert params["baseurl"]=="https://example.com/"
            return {"alerts":[{"name":"Potential exposure","risk":"Low",
                               "confidence":"Low","url":"https://example.com/.git/HEAD",
                               "pluginId":"123"}]}
        return {}
    with patch.object(main,"public_host",return_value=None),         patch.object(main.httpx,"AsyncClient",return_value=Client()),         patch.object(main,"zap_call",fake_zap_call),         patch.object(main.asyncio,"sleep",new_callable=AsyncMock):
        asyncio.run(run())
    assert job["status"]=="completed"
    assert job["stage_details"]["zap-passive"]["status"]=="completed"
    assert len(job["alerts"])==1
    assert len([q for q in queries if q[1]=="view/recordsToScan"])==3


def test_zap_global_pending_queue_is_not_misreported_as_missing_host_results():
    from test_worker_pipeline import run_job
    run,job=run_job(["zap-passive"])
    class FakeResponse:
        status_code=200
    class Client:
        async def __aenter__(self):return self
        async def __aexit__(self,*args):return False
        async def get(self,*args,**kwargs):return FakeResponse()
    async def fake_zap_call(client,component,endpoint,params):
        return {"recordsToScan":1} if endpoint=="view/recordsToScan" else {"alerts":[]}
    with patch.object(main,"public_host",return_value=None),         patch.object(main.httpx,"AsyncClient",return_value=Client()),         patch.object(main,"zap_call",fake_zap_call),         patch.object(main.asyncio,"sleep",new_callable=AsyncMock):
        asyncio.run(run())
    assert job["status"]=="partial"
    assert "global passive queue" in job["stage_details"]["zap-passive"]["reason"]


def test_zap_collects_late_alerts_after_passive_wait_and_records_progress():
    from test_worker_pipeline import run_job
    run, job = run_job(["zap-passive"])
    finished = []
    class Response:
        status_code = 200
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def get(self, *args, **kwargs): return Response()
    async def wait(client, call, host, **kwargs):
        assert kwargs["timeout_seconds"] == 120 and kwargs["limit"] > 30
        kwargs["on_progress"]({"remaining": 1, "checks": 40, "host_tasks_running": 1,
                               "global_tasks_running": 1, "elapsed_seconds": 30,
                               "deadline_seconds": 120, "deadline_reached": False})
        finished.append(True)
        return {"remaining": 0, "checks": 66, "stalled": False, "host_tasks_running": 0,
                "global_tasks_running": 0, "elapsed_seconds": 49.5,
                "deadline_seconds": 120, "deadline_reached": False, "reason": ""}
    async def zap(client, component, action, params):
        if action == "view/alerts":
            assert finished
            return {"alerts": [{"name": "Late passive alert", "risk": "Low",
                               "confidence": "Low", "url": "https://example.com/large",
                               "pluginId": "late"}]}
        return {}
    with patch.object(main, "public_host"), patch.object(main.httpx, "AsyncClient", return_value=Client()), \
         patch.object(main, "zap_call", zap), patch("app.zap_control.wait_for_passive_queue", wait), \
         patch.object(main.asyncio, "sleep", new_callable=AsyncMock):
        asyncio.run(run())
    assert job["status"] == "completed"
    assert job["alerts"][0]["name"] == "Late passive alert"
    assert any(event["event"] == "passive_queue_wait" for event in main.scan_events)
    final = next(event for event in main.scan_events if event["event"] == "stage_finished")
    assert final["diagnostics"]["passive_wait"]["checks"] == 66
