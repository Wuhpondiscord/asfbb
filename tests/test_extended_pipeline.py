import asyncio
import json
from unittest.mock import patch
from app import pipeline
from app.main import ScanRequest

def run(coro):
    return asyncio.run(coro)

def test_gau_filters_outside_scope():
    async def output(args, timeout):
        return ["https://example.com/a", "https://other.example.com/b",
                "https://example.com/a"], "completed"
    with patch.object(pipeline, "execute", output):
        result = run(pipeline.gau("https://example.com/", "example.com"))
    assert result["endpoints"] == ["https://example.com/a"]
    assert result["status"] == "completed"

def test_httpx_metadata_and_scope():
    value = {"url": "https://example.com", "status_code": 200, "title": "Demo"}
    async def output(args, timeout):
        return [json.dumps(value), json.dumps({"url": "https://other.com"})], "completed"
    with patch.object(pipeline, "execute", output):
        result = run(pipeline.probe(["https://example.com", "https://other.com"], "example.com", "ASFB"))
    assert len(result["probes"]) == 1
    assert result["probes"][0]["status_code"] == 200
    assert result["probes"][0]["source"] == "httpx"

def test_module_order_is_retained():
    order = ["gau", "katana", "httpx", "zap-passive", "nuclei"]
    assert ScanRequest(asset_id="test", modules=order).modules == order
