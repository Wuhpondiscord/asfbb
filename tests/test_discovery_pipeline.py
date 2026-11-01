import asyncio
import json
from unittest.mock import patch

from app import pipeline


def run(coro):
    return asyncio.run(coro)


def test_host_allowlist():
    assert pipeline.in_host("https://example.com/one", "example.com")
    assert not pipeline.in_host("https://else.example.com/one", "example.com")
    assert not pipeline.in_host("file:///tmp/item", "example.com")


def test_katana_deduplicates_and_enforces_host():
    async def output(args, timeout):
        return ["https://example.com/a", "https://example.com/a",
                "https://other.example.com/path"], "completed"
    with patch.object(pipeline, "execute", output):
        result = run(pipeline.katana("https://example.com/", "example.com", "Test-Agent"))
    assert result["status"] == "completed"
    assert result["endpoints"] == ["https://example.com/a"]


def test_nuclei_maps_findings_and_sources():
    detection = {"matched-at": "https://example.com/", "template-id": "tech-demo",
                 "info": {"name": "Test technology", "severity": "info"}}
    async def output(args, timeout):
        return [json.dumps(detection), "invalid json"], "completed"
    with patch.object(pipeline, "execute", output):
        result = run(pipeline.nuclei("https://example.com/", "example.com", "Test-Agent"))
    assert result["alerts"][0]["source"] == "nuclei"
    assert result["alerts"][0]["risk"] == "Informational"
    assert len(result["alerts"]) == 1


def test_combined_stages_offline():
    async def output(args, timeout):
        if args[0].endswith("katana"):
            return ["https://example.com/api"], "completed"
        return [json.dumps({"matched-at": "https://example.com/",
                            "template-id": "tech-demo", "info": {"name": "Test", "severity": "low"}})], "completed"
    with patch.object(pipeline, "execute", output):
        discovery = run(pipeline.katana("https://example.com/", "example.com", "Test-Agent"))
        findings = run(pipeline.nuclei("https://example.com/", "example.com", "Test-Agent"))
    assert discovery["endpoints"] == ["https://example.com/api"]
    assert findings["alerts"][0]["source"] == "nuclei"
