import asyncio
from pathlib import Path
from unittest.mock import patch
from app import pipeline

def test_nuclei_has_explicit_bundled_template():
    async def fake(args, timeout):
        assert "-t" in args
        path=args[args.index("-t")+1]
        assert path=="/app/app/nuclei-templates/technology-headers.yaml"
        return [],"completed"
    with patch.object(pipeline,"execute",fake):
        output=asyncio.run(pipeline.nuclei("https://example.org","example.org","Test"))
    assert output["status"]=="completed"
    template=Path("app/nuclei-templates/technology-headers.yaml").read_text()
    assert "severity: info" in template

def test_gau_has_short_bounded_lookup():
    async def fake(args,timeout):
        assert "--providers" in args and "wayback" in args
        assert timeout==25
        return ["[diagnostic] Stage exceeded its execution deadline; no complete output was available"],"timeout"
    with patch.object(pipeline,"execute",fake):
        output=asyncio.run(pipeline.gau("https://example.org","example.org"))
    assert output["status"]=="timeout"
    assert output["reason"]
