import asyncio
from unittest.mock import patch
from app import review

def test_dalfox_exit_one_records_findings_not_process_failure():
    async def fake(args, timeout):
        return ["[POC][A][GET][DOM-XSS] https://example.org/?q=test",
                "[diagnostic] Process exit code: 1"], "failed"
    with patch.object(review, "execute", fake):
        result = asyncio.run(review.review("dalfox", "https://example.org/", "example.org"))
    assert result["status"] == "findings"
    assert "[POC]" in result["output"]

def test_dalfox_exit_two_is_failed():
    async def fake(args, timeout):
        return ["[stderr] bad configuration",
                "[diagnostic] Process exit code: 2"], "failed"
    with patch.object(review, "execute", fake):
        result = asyncio.run(review.review("dalfox", "https://example.org/", "example.org"))
    assert result["status"] == "failed"
    assert "bad configuration" in result["reason"]

def test_ffuf_uses_real_line_breaks():
    import json
    lines = [json.dumps({"status": 200, "url": "https://example.org/a"}),
             json.dumps({"status": 302, "url": "https://example.org/b"})]
    rendered = review.summarize_review("ffuf", lines)
    assert "\n" in rendered
    assert "\\n" not in rendered

def test_arjun_progress_removed_and_summary_preserved():
    rendered = review.summarize_review("arjun", [
        "[*] Scanning 0/1", "[!] Processing chunks: 1/103",
        "[+] Found parameters: id"])
    assert "Processing chunks" not in rendered
    assert "Found parameters: id" in rendered
