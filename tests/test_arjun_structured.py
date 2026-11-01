import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from app import review

def test_arjun_json_result_is_in_scope_and_structured(tmp_path):
    path = tmp_path / "parameters.json"
    path.write_text(json.dumps({
        "https://example.org/api": {
            "method": "GET",
            "params": [{"name": "id", "reason": "body differs"},
                       {"name": "debug"}]},
        "https://other.example.org/api": {
            "params": [{"name": "private"}]},
    }))
    output = review.read_arjun_results(str(path), "example.org")
    assert [x["name"] for x in output] == ["id", "debug"]
    assert all(x["url"] == "https://example.org/api" for x in output)

def test_arjun_review_consumes_json_export():
    async def fake(args, timeout):
        assert "-oJ" in args
        path = Path(args[args.index("-oJ")+1])
        path.write_text(json.dumps({"https://example.org/path": {
            "method": "GET", "params": [{"name": "page"}]}}))
        return ["[+] Found parameters"], "completed"
    with patch.object(review, "execute", fake):
        result = asyncio.run(review.review("arjun", "https://example.org/path",
                                           "example.org"))
    assert result["status"] == "completed"
    assert result["parameters"][0]["name"] == "page"
