import asyncio
from unittest.mock import patch
from app import pipeline, config

def test_gau_uses_fallback_when_primary_times_out():
    async def execute(args, timeout):
        provider = args[args.index("--providers") + 1]
        assert timeout == config.GAU_PROVIDER_DEADLINE_SECONDS
        if provider == config.GAU_PROVIDER:
            return ["[diagnostic] Deadline exceeded"], "timeout"
        return ["https://example.org/api", "https://other.example.org/out"], "completed"
    pipeline._gau_disabled_until = 0
    pipeline._gau_failures = 0
    with patch.object(pipeline, "execute", execute):
        output = asyncio.run(pipeline.gau("https://example.org/", "example.org"))
    assert output["status"] == "partial"
    assert output["endpoints"] == ["https://example.org/api"]
    assert output["providers"][0]["status"] == "timeout"
    assert output["providers"][1]["status"] == "completed"

def test_gau_wont_claim_success_when_all_archive_providers_timeout():
    async def timeout(*args):
        return ["[diagnostic] Provider timeout"], "timeout"
    pipeline._gau_disabled_until = 0
    pipeline._gau_failures = 0
    with patch.object(pipeline, "execute", timeout):
        output = asyncio.run(pipeline.gau("https://example.org/", "example.org"))
    assert output["status"] == "timeout"
    assert len(output["providers"]) >= 2
