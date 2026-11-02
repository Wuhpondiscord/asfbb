import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from app import pipeline, review


def test_exposure_profiles_probes_root_not_static_manifest_path():
    async def fake(args, timeout):
        urls=Path(args[args.index("-l")+1]).read_text().splitlines()
        assert urls == ["https://example.org/"]
        return [json.dumps({
            "matched-at": "https://example.org/.git/config",
            "template-id": "bounty-ultimate-large",
            "matcher-name": "git-config-exposed",
            "info": {"name": "Potential exposed git config", "severity": "info"}
        })], "completed"
    with patch.object(pipeline, "execute", fake):
        result=asyncio.run(pipeline.nuclei(
            "https://example.org/manage/","example.org","ASFB",
            ["https://example.org/manage/","https://example.org/manage/manifest.json"],
            ["bounty-ultimate-large"]))
    assert result["status"] == "completed"
    assert result["scope_strategy"] == "origin-only exposure profile"
    assert result["inventory_urls"] == 2
    assert result["alerts"][0]["potential_file_exposure"] is True
    assert result["alerts"][0]["matcher_name"] == "git-config-exposed"


def test_default_header_templates_prioritize_root_and_html_before_static():
    async def fake(args, timeout):
        urls=Path(args[args.index("-l")+1]).read_text().splitlines()
        assert urls[0] == "https://example.org/"
        assert urls.index("https://example.org/docs/login") < urls.index("https://example.org/main.js")
        return [], "completed"
    with patch.object(pipeline, "execute", fake):
        result=asyncio.run(pipeline.nuclei(
            "https://example.org/manage/","example.org","ASFB",
            ["https://example.org/main.js","https://example.org/docs/login"],
            ["hsts-missing"]))
    assert result["scope_strategy"] == "prioritized page sample"


def test_arjun_does_not_target_manifest_instead_of_root():
    assert review.choose_arjun_target(
        "https://example.org/",["https://example.org/manage/manifest.json",
        "https://example.org/static/main.js"],"example.org") == "https://example.org/"
    assert review.choose_arjun_target(
        "https://example.org/",["https://example.org/manage/manifest.json",
        "https://example.org/api/search"],"example.org") == "https://example.org/api/search"
