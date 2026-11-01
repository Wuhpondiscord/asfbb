import asyncio
from pathlib import Path
from unittest.mock import patch
from app import pipeline

def test_broad_nuclei_profile_reduces_targets_to_request_budget():
    async def fake(args, timeout):
        urls=Path(args[args.index("-l")+1]).read_text().splitlines()
        assert len(urls)<=3
        return [], "completed"
    targets=[f"https://example.org/path{x}" for x in range(10)]
    with patch.object(pipeline,"execute",fake):
        output=asyncio.run(pipeline.nuclei("https://example.org/","example.org",
            "Test", targets, ["bounty-ultimate-large"], {}, []))
    assert output["requested_targets"]==10
    assert output["targets_checked"]<=3
    assert output["status"]=="partial"
    assert "budget limited" in output["reason"]
