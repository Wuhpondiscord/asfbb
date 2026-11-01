import asyncio
from unittest.mock import patch
from app import pipeline

def test_katana_respects_configured_discovery_limit():
    async def fake(*args):
        return [f"https://example.org/path{i}" for i in range(205)], "completed"
    with patch.object(pipeline,"execute",fake):
        result = asyncio.run(pipeline.katana("https://example.org/","example.org",
                                             "Test", depth=1, limit=175))
    assert len(result["endpoints"]) == 175

def test_gau_respects_configured_discovery_limit():
    async def fake(*args):
        return [f"https://example.org/path{i}" for i in range(160)], "completed"
    old_fails, old_disabled = pipeline._gau_failures, pipeline._gau_disabled_until
    try:
        pipeline._gau_disabled_until = 0
        with patch.object(pipeline,"execute",fake):
            result = asyncio.run(pipeline.gau("https://example.org/","example.org",
                                              limit=125))
        assert len(result["endpoints"]) == 125
    finally:
        pipeline._gau_failures = old_fails
        pipeline._gau_disabled_until = old_disabled
