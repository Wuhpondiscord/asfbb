import asyncio
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import main, review

def test_repeat_queue_reuses_pending_job():
    with TestClient(main.app) as client:
        sid=client.get("/api/health").headers["X-ASFB-Session"]
        asset="repeat-target"
        main.assets[asset]={"id":asset,"owner":sid,"name":"https://example.org",
                            "type":"URL","compatibility":"web"}
        payload={"asset_id":asset,"policy_confirmed":True,"modules":["httpx"]}
        with patch.object(main,"public_host",return_value=None), patch.object(main,"target_url",return_value=("https://example.org","example.org")):
            first=client.post("/api/scans",json=payload)
            second=client.post("/api/scans",json=payload)
        assert first.status_code==200 and second.status_code==200
        assert first.json()["id"]==second.json()["id"]
        assert second.json()["reused"] is True

def test_failed_review_retains_diagnostic():
    async def fake(*args):
        return ["[stderr] invalid option"],"failed"
    with patch.object(review,"execute",fake):
        result=asyncio.run(review.review("dalfox","https://example.org","example.org"))
    assert result["status"]=="failed"
    assert "invalid option" in result["reason"]

def test_failed_review_without_stderr_has_reason():
    async def fake(*args):
        return ["[POC] unverified"],"failed"
    with patch.object(review,"execute",fake):
        result=asyncio.run(review.review("dalfox","https://example.org","example.org"))
    assert result["status"]=="failed"
    assert "exit status" in result["reason"]
    assert "[POC]" in result["output"]
