import asyncio
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient
from app import config, main, pipeline


def reset_health():
    pipeline._gau_failures=0
    pipeline._gau_disabled_until=0
    pipeline._gau_provider_failures.clear()
    pipeline._gau_provider_disabled_until.clear()


def test_balanced_gau_never_calls_slow_provider_on_empty_archives():
    seen=[]
    async def fake(args, deadline):
        seen.append(args[args.index("--providers")+1])
        return [],"completed"
    reset_health()
    with patch.object(pipeline,"execute",fake):
        result=asyncio.run(pipeline.gau("https://example.org/","example.org"))
    assert seen==["otx","urlscan"]
    assert result["status"]=="completed"
    assert result["coverage"]=="no-archive-hits"
    assert "responded: 2" in result["summary"]
    assert "exact-host URLs: 0" in result["summary"]
    assert "does not imply" in result["reason"]


def test_expanded_queries_commoncrawl_after_fast_archives_yield_no_urls():
    seen=[]
    async def fake(args, deadline):
        provider=args[args.index("--providers")+1]
        seen.append((provider,deadline))
        if provider=="commoncrawl":
            return ["[diagnostic] Deadline exceeded"],"timeout"
        return [],"completed"
    reset_health()
    with patch.object(pipeline,"execute",fake):
        result=asyncio.run(pipeline.gau("https://example.org/","example.org",mode="expanded"))
    assert [name for name,_ in seen]==["otx","urlscan","commoncrawl"]
    assert seen[-1][1]==config.GAU_SLOW_PROVIDER_DEADLINE_SECONDS
    assert result["status"]=="partial"
    assert result["coverage"]=="degraded"
    assert "commoncrawl: timeout" in result["reason"]
    reset_health()


def test_balanced_returns_first_successful_provider_without_unneeded_calls():
    calls=[]
    async def fake(args,deadline):
        calls.append(args[args.index("--providers")+1])
        return ["https://example.org/a"],"completed"
    reset_health()
    with patch.object(pipeline,"execute",fake):
        result=asyncio.run(pipeline.gau("https://example.org","example.org"))
    assert calls==["otx"]
    assert result["coverage"]=="found"


def test_invalid_gau_mode_is_rejected_by_api_model():
    from pydantic import ValidationError
    try:
        main.PipelineOptions(gau_mode="everywhere")
    except ValidationError:
        pass
    else:
        raise AssertionError("Unknown GAU modes must fail validation")


def test_gau_mode_available_in_dashboard():
    html=Path("app/index.html").read_text()
    assert 'id="settingsGauMode"' in html
    assert 'gau_mode:el("settingsGauMode").value' in html
