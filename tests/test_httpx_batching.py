import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from app import pipeline

def test_httpx_batches_targets_and_filters_scope():
    calls = []
    async def fake(args, timeout):
        assert "-l" in args and "-u" not in args
        payload = Path(args[args.index("-l") + 1]).read_text().splitlines()
        calls.append(payload)
        assert timeout >= len(payload)
        return [json.dumps({"url": url, "status_code": 200}) for url in payload], "completed"
    targets = [f"https://example.org/page{i}" for i in range(7)]
    targets.append("https://not-example.org/")
    with patch.object(pipeline, "execute", fake):
        result = asyncio.run(pipeline.probe(targets, "example.org", "Test", limit=10))
    assert len(calls) == 1
    assert result["submitted"] == 7
    assert len(result["probes"]) == 7
    assert all(p["url"].startswith("https://example.org/") for p in result["probes"])

def test_httpx_preserves_failed_batch_and_partial_probe_results():
    async def fake(args, timeout):
        return ['{"url": "https://example.org/a", "status_code": 200}',
                "[diagnostic] Deadline exceeded"], "timeout"
    with patch.object(pipeline, "execute", fake):
        result = asyncio.run(pipeline.probe(["https://example.org/a"],
                                             "example.org", "Test"))
    assert result["status"] == "timeout"
    assert len(result["probes"]) == 1
    assert "Deadline exceeded" in result["reason"]
