import asyncio
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import main, pipeline, review

def test_stale_batch_asset_returns_conflict_without_enqueuing():
    main.assets.clear()
    main.jobs.clear()
    with TestClient(main.app) as client:
        response=client.post("/api/scans/batch",json={"asset_ids":["expired-asset"],"policy_confirmed":True})
        assert response.status_code == 409
        assert "stale" in response.json()["detail"].lower()
        assert not main.jobs

def test_dalfox_cli_is_supported_v3_shape():
    cmd=review.command("dalfox","https://example.org/?q=x","example.org")
    assert cmd[1]=="scan"
    assert "--workers" in cmd
    assert "--worker" not in cmd

def test_nuclei_failure_reason_preserved():
    async def fake(args,timeout):
        return ["[stderr] failed to load templates"],"failed"
    with patch.object(pipeline,"execute",fake):
        result=asyncio.run(pipeline.nuclei("https://example.org/","example.org","Test"))
    assert result["status"]=="failed"
    assert "templates" in result["reason"]

def test_exact_host_scope_rejects_sibling():
    assert pipeline.in_host("https://example.org/a","example.org")
    assert not pipeline.in_host("https://a.example.org/a","example.org")

def test_gau_timeout_is_nonfatal():
    async def fake(args,timeout):
        return ["Stage timed out"],"timeout"
    with patch.object(pipeline,"execute",fake):
        result=asyncio.run(pipeline.gau("https://example.org/","example.org"))
    assert result["status"]=="timeout"
    assert result["endpoints"]==[]
