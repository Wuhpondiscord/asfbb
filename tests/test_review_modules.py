import asyncio
from unittest.mock import patch

import pytest
from app import review
from app.main import PipelineOptions, ScanRequest, BatchRequest

def test_review_command_scope_and_flags():
    for tool in ("ffuf", "arjun", "dalfox"):
        cmd = review.command(tool, "https://example.org/path", "example.org")
        assert isinstance(cmd, list) and cmd
        assert "https://example.org/path" in " ".join(cmd)
    with pytest.raises(ValueError):
        review.command("ffuf", "https://evil.example.org/", "example.org")
    with pytest.raises(ValueError):
        review.command("sqlmap", "https://example.org/", "example.org")

def test_sqlmap_bounded_detection_flags():
    cmd = review.command("sqlmap", "https://example.org/?id=1", "example.org")
    assert "--level=1" in cmd and "--risk=1" in cmd
    assert "--technique=B" in cmd
    assert not any(x in cmd for x in ("--dump", "--os-shell", "--dbs"))

def test_review_output_is_unverified():
    async def fake(args, timeout):
        return ["Sample output"], "completed"
    with patch.object(review, "execute", fake):
        result = asyncio.run(review.review("ffuf", "https://example.org/", "example.org"))
    assert result["status"] == "completed"
    assert result["source"] == "ffuf"
    assert "Unverified" in result["note"]

def test_pipeline_option_validation():
    assert PipelineOptions(endpoint_limit=10, httpx_limit=3).endpoint_limit == 10
    with pytest.raises(ValueError):
        PipelineOptions(endpoint_limit=2001)
    assert PipelineOptions(endpoint_limit=1000).endpoint_limit == 1000
    assert ScanRequest(asset_id="test").active_confirmed is False
    assert BatchRequest(asset_ids=["a"]).modules == ["zap-passive"]
