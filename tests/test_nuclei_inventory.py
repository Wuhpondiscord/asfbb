import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from app import pipeline, config

def test_nuclei_probes_scoped_inventory_using_curated_templates():
    async def fake(args, timeout):
        assert args.count("-t") == len(config.NUCLEI_TEMPLATE_PATHS)
        assert "-l" in args and "-dr" in args
        urls = Path(args[args.index("-l") + 1]).read_text().splitlines()
        assert urls == ["https://example.org/", "https://example.org/a"]
        return [
            json.dumps({"matched-at":"https://example.org/a",
                        "template-id":"asfb-csp-missing",
                        "info":{"name":"CSP absent","severity":"info"}}),
            json.dumps({"matched-at":"https://other.example.org/bad",
                        "info":{"name":"Out of scope","severity":"critical"}})
        ], "completed"
    with patch.object(pipeline, "execute", fake):
        result = asyncio.run(pipeline.nuclei(
            "https://example.org/","example.org","Test",
            ["https://example.org/","https://other.example.org/",
             "https://example.org/a"]))
    assert result["targets_checked"] == 2
    assert len(result["templates"]) == len(config.NUCLEI_TEMPLATE_PATHS)
    assert len(result["alerts"]) == 1
    assert result["alerts"][0]["risk"] == "Informational"

def test_curated_template_files_exist():
    for path in config.NUCLEI_TEMPLATE_PATHS:
        local = Path("app/nuclei-templates") / Path(path).name
        assert local.exists()
        assert "severity: info" in local.read_text()
