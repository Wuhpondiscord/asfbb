import asyncio
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import main
from app.scope import target_url
from app.target_import import parse_targets, target_key


@pytest.mark.parametrize("text,filename,expected", [
    ("https://example.org/search?q=test#results", "", "text"),
    ("# Targets\nhttps://example.org/\napi.example.org\n", "targets.txt", "text"),
    ("url,description\nhttps://example.org/,Main app\n", "targets.csv", "csv"),
    ("target\tdescription\nhttps://example.org/\tMain app\n", "targets.tsv", "tsv"),
    ('["https://example.org/", "api.example.org"]', "targets.json", "json"),
    ('{"url":"https://example.org/","description":"Main app"}', "", "json"),
    ('{"targets":[{"url":"https://example.org/"},"api.example.org"]}', "", "json"),
    ('{"url":"https://example.org/"}\n{"url":"https://api.example.org/"}', "targets.jsonl", "jsonl"),
    ('"https://example.org/"\n"https://api.example.org/"', "", "jsonl"),
    ('"https://example.org/"\n"https://api.example.org/"', "targets.csv", "csv"),
    ("- https://example.org/\n* https://api.example.org/", "", "text"),
])
def test_common_target_formats(text, filename, expected):
    result = parse_targets(text, filename)
    assert result["format"] == expected
    assert result["assets"]
    assert all(asset["compatibility"] == "web" for asset in result["assets"])


def test_hackerone_metadata_and_manual_assets_remain_supported():
    content = "Asset name,Type,Max. severity,Bounty,Resolved Reports\nexample.org,Domain,High,Yes,12\n*.example.org,Other,Low,Yes,1\n"
    result = parse_targets(content, "scope.csv")
    assert result["assets"][0]["bounty"] is True
    assert result["assets"][0]["resolved_reports"] == 12
    assert result["assets"][1]["compatibility"] == "manual"


def test_windows_utf16_and_utf8_bom_target_lists():
    assert len(parse_targets("https://example.org/".encode("utf-16"), "targets.txt")["assets"]) == 1
    assert len(parse_targets(b"\xef\xbb\xbfhttps://example.org/")["assets"]) == 1


def test_query_values_are_retained_fragments_ignored_and_equivalent_roots_deduplicated():
    result = parse_targets("example.org\nhttps://EXAMPLE.org/\nhttps://example.org:443/#top\nhttps://example.org/search?q=one,two#part")
    assert result["duplicates"] == 2
    assert len(result["assets"]) == 2
    url, host = target_url(result["assets"][1])
    assert url == "https://example.org/search?q=one,two" and host == "example.org"


def test_json_cannot_supply_owner_ids_or_compatibility():
    result = parse_targets('{"url":"https://example.org/","id":"spoof","owner":"someone","compatibility":"manual"}')
    row = result["assets"][0]
    assert row["id"] == "asset-1" and "owner" not in row
    assert row["compatibility"] == "web"


@pytest.mark.parametrize("text,filename", [
    ("", ""), ("# comments only", ""), ("not a URL", ""), ("https://name:password@example.org", ""),
    ('{"url":42}', "targets.json"), ('["https://example.org/",42]', "targets.json"),
    ('{"url":"https://example.org/"}\ninvalid', "targets.jsonl"),
    ("url\nhttps://example.org/?q=one,two", "targets.csv"),
])
def test_invalid_inputs_fail_without_partial_import(text, filename):
    with pytest.raises(ValueError):
        parse_targets(text, filename)


def test_size_and_target_count_limits_are_enforced():
    with pytest.raises(ValueError, match="2 MB"):
        parse_targets("x" * 2_000_001)
    with pytest.raises(ValueError, match="3000"):
        parse_targets("\n".join("https://h" + str(i) + ".example.org/" for i in range(3001)))


def test_import_endpoints_merge_deduplicate_and_do_not_resolve_or_scan():
    main.assets.clear()
    main.jobs.clear()
    main.queue = asyncio.Queue()
    with patch.object(main, "public_host") as dns, patch.object(main, "run_scan_job") as run, \
         TestClient(main.app) as client:
        first = client.post("/api/import/text", json={"text": "https://example.org/search?q=test#top"})
        assert first.status_code == 200
        result = first.json()
        assert result["imported"] == 1 and result["web_asset_ids"]
        second = client.post("/api/import", files={
            "file": ("targets.txt", b"https://example.org/search?q=test\nhttps://api.example.org/", "text/plain")})
        assert second.status_code == 200
        assert second.json()["imported"] == 1 and second.json()["duplicates"] == 1
        assets = client.get("/api/assets").json()["assets"]
        assert len(assets) == 2
        assert main.queue.empty() and not main.jobs
        assert not dns.called and not run.called
        invalid = client.post("/api/import/text", json={"text": '["https://new.example.org/", 42]'})
        assert invalid.status_code == 422
        assert len(client.get("/api/assets").json()["assets"]) == 2
        other = TestClient(main.app)
        try:
            assert other.get("/api/assets").json()["assets"] == []
        finally:
            other.close()


def test_single_parameterized_url_can_be_queued_with_existing_policy_checks():
    main.assets.clear()
    main.jobs.clear()
    main.queue = asyncio.Queue()
    async def no_scan(*args): pass
    with patch.object(main, "public_host"), patch.object(main, "run_scan_job", no_scan), \
         TestClient(main.app) as client:
        imported = client.post("/api/import/text", json={"text": "https://example.org/search?q=test#part"}).json()
        identifier = imported["web_asset_ids"][0]
        body = {"asset_id": identifier, "modules": ["sqlmap"], "policy_confirmed": False, "active_confirmed": True}
        assert client.post("/api/scans", json=body).status_code == 422
        body["policy_confirmed"] = True
        response = client.post("/api/scans", json=body)
        assert response.status_code == 200
        assert main.jobs[response.json()["id"]]["target"] == "https://example.org/search?q=test"

def test_parameterized_url_does_not_turn_ffuf_path_discovery_into_query_fuzzing():
    from app.review import command
    args = command("ffuf", "https://example.org/search?q=test", "example.org")
    assert args[args.index("-u") + 1] == "https://example.org/search/FUZZ"

def test_unterminated_csv_quote_is_reported_as_invalid_input():
    with pytest.raises(ValueError, match="Malformed"):
        parse_targets('url,description\n"https://example.org/,unfinished', "targets.csv")
