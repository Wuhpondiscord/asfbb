import asyncio
from pathlib import Path
from unittest.mock import patch
from app import pipeline

def test_broad_nuclei_profile_checks_origin_without_repeating_file_exposure_paths():
    async def fake(args, timeout):
        urls=Path(args[args.index("-l")+1]).read_text().splitlines()
        assert urls == ["https://example.org/"]
        return [], "completed"
    targets=[f"https://example.org/path{x}" for x in range(10)]
    with patch.object(pipeline,"execute",fake):
        output=asyncio.run(pipeline.nuclei("https://example.org/","example.org",
            "Test", targets, ["bounty-ultimate-large"], {}, []))
    assert output["inventory_urls"]==10
    assert output["requested_targets"]==1
    assert output["targets_checked"]==1
    assert output["status"]=="completed"
    assert "web origin" in output["reason"]
