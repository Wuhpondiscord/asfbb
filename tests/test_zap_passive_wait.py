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
