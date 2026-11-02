import asyncio
from unittest.mock import patch
from app import config, pipeline


def test_gau_skips_disabled_wayback_and_falls_back_on_failure():
    providers=[]
    async def fake(args, deadline):
        provider=args[args.index("--providers")+1]
        providers.append(provider)
        if provider==config.GAU_PROVIDER:
            return ["[diagnostic] Deadline exceeded"], "timeout"
        return ["https://example.org/path"], "completed"
    pipeline._gau_disabled_until=0
    pipeline._gau_failures=0
    pipeline._gau_provider_failures.clear()
    pipeline._gau_provider_disabled_until.clear()
    with patch.object(config,"GAU_ENABLE_WAYBACK",False),patch.object(pipeline,"execute",fake):
        out=asyncio.run(pipeline.gau("https://example.org/","example.org"))
    assert "wayback" not in providers
    assert out["endpoints"]==["https://example.org/path"]
    assert out["coverage"]=="degraded"
    assert out["status"]=="partial"


def test_gau_fallback_breaker_limits_repeated_timeouts():
    seen=[]
    async def fake(args, deadline):
        provider=args[args.index("--providers")+1]
        seen.append(provider)
        if provider==config.GAU_PROVIDER:
            return [],"completed"
        return ["[diagnostic] timeout"],"timeout"
    pipeline._gau_disabled_until=0
    pipeline._gau_failures=0
    pipeline._gau_provider_failures.clear()
    pipeline._gau_provider_disabled_until.clear()
    with patch.object(config,"GAU_ENABLE_WAYBACK",False),patch.object(pipeline,"execute",fake):
        for _ in range(config.GAU_FALLBACK_BREAKER_FAILURES+1):
            asyncio.run(pipeline.gau("https://example.org/","example.org",mode="expanded"))
    assert seen.count("commoncrawl")==config.GAU_FALLBACK_BREAKER_FAILURES
    assert seen.count("urlscan")==config.GAU_FALLBACK_BREAKER_FAILURES
    pipeline._gau_provider_failures.clear()
    pipeline._gau_provider_disabled_until.clear()


def test_archive_provider_status_exposes_cooldown_and_deadline():
    async def fake(args, deadline):
        return ["[diagnostic] timeout"],"timeout"
    pipeline._gau_disabled_until=0
    pipeline._gau_failures=0
    pipeline._gau_provider_failures.clear()
    pipeline._gau_provider_disabled_until.clear()
    with patch.object(config,"GAU_ENABLE_WAYBACK",False),patch.object(pipeline,"execute",fake):
        for _ in range(config.GAU_FALLBACK_BREAKER_FAILURES+1):
            result=asyncio.run(pipeline.gau("https://example.org/","example.org",mode="expanded"))
    assert result["providers"][1]["status"]=="unavailable"
    assert "cooldown_seconds" in result["providers"][1]
    pipeline._gau_provider_failures.clear()
    pipeline._gau_provider_disabled_until.clear()
