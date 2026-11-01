import asyncio
from unittest.mock import patch
from app import pipeline, config

def test_gau_circuit_breaker_avoids_repeated_provider_timeouts():
    async def run():
        calls = []
        async def fake(args, timeout):
            calls.append(args[args.index("--providers") + 1])
            return ["[diagnostic] Deadline exceeded"], "timeout"
        with patch.object(pipeline, "execute", fake):
            pipeline._gau_failures = 0
            pipeline._gau_disabled_until = 0
            for _ in range(config.GAU_BREAKER_FAILURES):
                result = await pipeline.gau("https://example.org/", "example.org")
                assert result["status"] == "timeout"
            skipped = await pipeline.gau("https://example.org/", "example.org")
            assert skipped["providers"][0]["status"] == "unavailable"
            assert "Circuit breaker cooldown" in skipped["providers"][0]["reason"]
            assert calls.count(config.GAU_PROVIDER) == config.GAU_BREAKER_FAILURES
    try:
        asyncio.run(run())
    finally:
        pipeline._gau_failures = 0
        pipeline._gau_disabled_until = 0

def test_gau_success_resets_error_streak():
    async def output(args, timeout):
        return ["https://example.org/ok"], "completed"
    with patch.object(pipeline, "execute", output):
        pipeline._gau_failures = 1
        pipeline._gau_disabled_until = 0
        result = asyncio.run(pipeline.gau("https://example.org/", "example.org"))
    assert result["status"] == "completed"
    assert pipeline._gau_failures == 0
