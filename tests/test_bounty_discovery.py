"""Discovery contract, rule extraction, owned scope and queue enforcement; no live HTTP."""
import asyncio
import json
import time
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from app import bounty_discovery as discovery, main, review


RULES = "User-Agent: HackerOne-<username>\nYou must use your @wearehackerone.com email for testing accounts."
ROW = {"identifier": "example.org", "type": "domain", "instructions": None, "eligible_for_bounty": True, "raw": {}}


@pytest.fixture(autouse=True)
def clean_discovery_state():
    discovery._documents.clear()
    discovery._bindings.clear()


def fixture_page(rules=RULES, rows=None, exclusions=None, partial=False):
    return {"ok": True, "partial": partial, "in_scope": [ROW] if rows is None else rows,
            "out_of_scope": exclusions or [], "rules": {"policy": rules},
            "total": len([ROW] if rows is None else rows), "next_offset": None,
            "source": {"mode": "live", "source_url": "https://hackerone.com/example", "fetched_at": "2026-11-03T12:00:00Z"}}


def test_extracts_identity_domain_and_source_evidence():
    analysis = discovery.policy_analysis({"policy": RULES})
    assert analysis["user_agents"][0]["value"] == "HackerOne-<username>"
    assert analysis["email_domains"] == ["wearehackerone.com"]
    assert not analysis["review_required"]
    configured = discovery.configure(analysis, discovery.PolicySettings(
        researcher="fixture", test_email="fixture@wearehackerone.com", test_account_confirmed=True))
    assert configured["user_agent"] == "HackerOne-fixture"
    assert "test_email" not in configured


@pytest.mark.parametrize("policy,settings", [
    (RULES, {}),
    (RULES, {"researcher": "fixture", "test_email": "fixture@example.org", "test_account_confirmed": True}),
    (RULES, {"researcher": "fixture", "test_email": "fixture@wearehackerone.com"}),
    ("No special identification requirements.", {}),
    ("Automated scanning is prohibited.", {"rules_reviewed": True}),
    ("Do not use automated scanners.", {"rules_reviewed": True}),
])
def test_missing_review_identity_or_prohibited_automation_cannot_import(policy, settings):
    with pytest.raises(ValueError):
        discovery.configure(discovery.policy_analysis({"policy": policy}), discovery.PolicySettings(**settings))


def test_unavailable_or_partial_rules_require_review_checkbox():
    for rules, partial in ((None, False), ({"policy": "User-Agent: Fixture"}, True)):
        analysis = discovery.policy_analysis(rules, partial=partial)
        assert analysis["review_required"]
        with pytest.raises(ValueError):
            discovery.configure(analysis, discovery.PolicySettings())
        assert discovery.configure(analysis, discovery.PolicySettings(rules_reviewed=True))


@pytest.mark.parametrize("identifier,url,expected", [
    ("*.example.org", "https://api.example.org/", True),
    ("*.example.org", "https://example.org/", False),
    ("*.example.org", "https://example.org.evil.org/", False),
    ("example.org", "https://sub.example.org/", False),
    ("https://example.org/app/", "https://example.org/app/item", True),
    ("https://example.org/app/", "https://example.org/application", False),
    ("https://example.org/app/", "http://example.org/app/", False),
    ("/admin", "https://example.org/admin/item", True),
    ("https://example.org/app/", "https://example.org/app/%252e%252e/admin", False),
    ("example.org", "https://example.org@evil.org/", False),
])
def test_scope_boundaries_and_exclusion_patterns(identifier, url, expected):
    assert discovery.matches(identifier, url) is expected


def test_policy_html_is_text_and_script_content_is_ignored():
    analysis = discovery.policy_analysis({"policy": '<p>User-Agent: <code>Fixture</code></p><script>User-Agent: Evil</script>'})
    assert analysis["user_agents"][0]["value"] == "Fixture"
    assert "Evil" not in analysis["text"]


def test_custom_identity_header_and_rate_are_extracted():
    analysis = discovery.policy_analysis({"policy": "Use header X-Bug-Bounty: <username>\nMaximum 30 requests per minute."})
    assert analysis["headers"][0]["name"] == "X-Bug-Bounty"
    assert analysis["max_rps"] == .5


async def no_scan(*args):
    pass


def load_program(client, page):
    async def fetch(path, params=None):
        assert path.endswith("/assets")
        assert params["limit"] == 1000
        return page
    with patch.object(discovery, "fetch_json", fetch):
        response = client.get("/api/discovery/programs/hackerone/example")
    assert response.status_code == 200, response.text
    return response.json()


def import_program(client, document, settings=None, selected=None, concrete=None):
    return client.post("/api/discovery/import", json={"programs": [{
        "review_id": document["review_id"],
        "asset_ids": selected if selected is not None else [document["assets"][0]["id"]],
        "concrete_urls": concrete or [],
        "settings": settings or {"researcher": "fixture", "test_email": "fixture@wearehackerone.com",
                                 "test_account_confirmed": True}}]})


def test_browse_filters_follow_public_summary_contract_without_details():
    async def fetch(path, params=None):
        assert path == "/programs" and params["include_details"] == "false"
        assert params["platforms"] == "hackerone,bugcrowd" and params["currency"] == "USD"
        assert params["reward_at_least"] == 1000 and params["offset"] == 25
        return {"ok": True, "total": 50, "next_offset": None, "offset": 25, "partial": False, "programs": [{
            "id": "hackerone:example", "platform": "hackerone", "handle": "example", "name": "Example",
            "max_bounty": None, "currency": None, "rules": "not fetched"}]}
    with TestClient(main.app) as client, patch.object(discovery, "fetch_json", fetch):
        response = client.get("/api/discovery/programs?platforms=hackerone,bugcrowd&currency=usd&reward_at_least=1000&offset=25")
        assert response.status_code == 200
        assert response.json()["programs"][0]["max_bounty"] is None
        assert "rules" not in response.json()["programs"][0]
        assert client.get("/api/discovery/programs?sort_by=max_bounty").status_code == 422
        assert client.get("/api/discovery/programs?platforms=unknown").status_code == 422


def test_program_import_applies_agent_on_regular_queue_and_omits_unsupported_profiles():
    main.assets.clear(); main.jobs.clear(); main.queue = asyncio.Queue()
    with TestClient(main.app) as client, patch.object(main, "run_scan_job", no_scan), patch.object(main, "public_host"):
        document = load_program(client, fixture_page())
        response = import_program(client, document)
        assert response.status_code == 200, response.text
        asset = response.json()["web_asset_ids"][0]
        queued = client.post("/api/scans", json={"asset_id": asset, "policy_confirmed": True,
            "active_confirmed": True, "modules": ["arjun", "testssl"], "user_agent": "wrong-global-agent"})
        assert queued.status_code == 200, queued.text
        job = main.jobs[queued.json()["id"]]
        assert job["user_agent"] == "HackerOne-fixture" and job["modules"] == ["arjun"]
        assert job["program"]["omitted_modules"] == ["testssl"]
        assert "fixture@wearehackerone.com" not in json.dumps(job)
        assert job["program"]["policy_revision"]


def test_path_scope_and_exclusions_use_exact_url_profile():
    main.assets.clear(); main.jobs.clear(); main.queue = asyncio.Queue()
    rows = [dict(ROW, identifier="https://example.org/app/", type="url")]
    with TestClient(main.app) as client, patch.object(main, "run_scan_job", no_scan), patch.object(main, "public_host"):
        document = load_program(client, fixture_page("User-Agent: Fixture", rows))
        imported = import_program(client, document, settings={})
        assert imported.status_code == 200, imported.text
        queued = client.post("/api/scans", json={"asset_id": imported.json()["web_asset_ids"][0],
            "policy_confirmed": True, "active_confirmed": True, "modules": ["zap-passive", "nikto", "katana"],
            "options": {"reuse_discovery": True, "zap_endpoint_limit": 5}})
        assert queued.status_code == 200, queued.text
        job = main.jobs[queued.json()["id"]]
        assert job["modules"] == ["zap-passive"]
        assert job["options"]["zap_endpoint_limit"] == 1 and job["options"]["reuse_discovery"] is False


def test_explicit_exclusion_and_missing_review_are_atomic():
    main.assets.clear()
    with TestClient(main.app) as client:
        doc = load_program(client, fixture_page("Review all testing requirements.", exclusions=[dict(ROW)]))
        response = import_program(client, doc, settings={"rules_reviewed": True})
        assert response.status_code == 422 and not main.assets
        doc = load_program(client, fixture_page("Review all testing requirements."))
        skipped = import_program(client, doc, settings={})
        assert skipped.status_code == 200 and skipped.json()["imported"] == 0
        assert len(skipped.json()["skipped"]) == 1
        assert not main.assets


def test_wildcard_needs_concrete_scoped_host_and_excludes_apex():
    main.assets.clear()
    with TestClient(main.app) as client:
        doc = load_program(client, fixture_page("User-Agent: Fixture", [dict(ROW, identifier="*.example.org", type="wildcard")]))
        assert import_program(client, doc, settings={}).status_code == 422
        assert import_program(client, doc, settings={}, concrete=["https://example.org/"]).status_code == 422
        response = import_program(client, doc, settings={}, concrete=["https://api.example.org/"])
        assert response.status_code == 200, response.text


def test_owned_review_and_expiry_cannot_be_bypassed():
    main.assets.clear()
    with TestClient(main.app) as client:
        doc = load_program(client, fixture_page("User-Agent: Fixture"))
        record = next(iter(discovery._documents.values()))
        with pytest.raises(ValueError):
            discovery.document("another-session", doc["review_id"])
        record["stored"] = time.monotonic() - discovery.TTL - 1
        assert import_program(client, doc, settings={}).status_code == 422


@pytest.mark.parametrize("module,flag", [("ffuf", "-H"), ("arjun", "--headers"), ("dalfox", "--user-agent"), ("sqlmap", "-A")])
def test_active_review_commands_carry_required_agent(module, flag):
    args = review.command(module, "https://example.org/?id=1", "example.org", agent="Fixture")
    assert flag in args
    assert "Fixture" in " ".join(args)


@pytest.mark.parametrize("agent", ["Injected\r\nX-Test: secret", "Foo\\nX-Test: value", ""])
def test_agent_header_injection_is_rejected(agent):
    with pytest.raises(ValueError):
        review.command("arjun", "https://example.org/", "example.org", agent=agent)


def test_mixed_program_batch_keeps_distinct_agents_and_validates_before_queue():
    main.assets.clear(); main.jobs.clear(); main.queue = asyncio.Queue()
    async def fetch(path, params=None):
        return fixture_page("User-Agent: Program-Two" if "/second/" in path else "User-Agent: Program-One")
    with TestClient(main.app) as client, patch.object(discovery, "fetch_json", fetch), \
         patch.object(main, "run_scan_job", no_scan), patch.object(main, "public_host"):
        first = client.get("/api/discovery/programs/hackerone/first").json()
        second = client.get("/api/discovery/programs/bugcrowd/second").json()
        body = {"programs": [{"review_id": doc["review_id"], "asset_ids": [doc["assets"][0]["id"]], "settings": {}}
                             for doc in (first, second)]}
        response = client.post("/api/discovery/import", json=body)
        assert response.status_code == 200, response.text
        queued = client.post("/api/scans/batch", json={"asset_ids": response.json()["web_asset_ids"],
            "policy_confirmed": True, "active_confirmed": True, "modules": ["arjun"]})
        assert queued.status_code == 200, queued.text
        assert {job["user_agent"] for job in main.jobs.values()} == {"Program-One", "Program-Two"}


def test_wildcard_path_keeps_suffix_and_deep_encoded_traversal_is_rejected():
    assert discovery.matches("https://example.org/app/*/status", "https://example.org/app/v1/status")
    assert not discovery.matches("https://example.org/app/*/status", "https://example.org/app/v1/admin")
    assert not discovery.matches("https://example.org/app/", "https://example.org/app/%25252e%25252e/admin")


def test_fixed_api_transport_forwards_no_browser_or_account_credentials():
    seen = []
    class Response:
        status_code = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def aiter_bytes(self): yield b'{"ok":true,"programs":[]}'
    class Client:
        def __init__(self, **kwargs):
            assert kwargs["trust_env"] is False and kwargs["follow_redirects"] is False
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        def stream(self, method, url, **kwargs):
            seen.append(url)
            assert method == "GET" and kwargs["headers"] == {"Accept": "application/json"}
            return Response()
    with patch.object(discovery.httpx, "AsyncClient", Client):
        assert asyncio.run(discovery.fetch_json("/programs"))["ok"]
    assert seen == [discovery.BASE + "/programs"]


@pytest.mark.parametrize("text,expected", [
    ("User-Agent: 'HackerOne-<username>' for all requests.", "HackerOne-<username>"),
    ("User-Agent: HackerOne-<username>. This is mandatory.", "HackerOne-<username>"),
    ('User-Agent: "Mozilla/5.0 (X11; Linux x86_64) Fixture/1.0"', "Mozilla/5.0 (X11; Linux x86_64) Fixture/1.0"),
])
def test_user_agent_quotes_and_following_prose_are_not_sent_as_header(text, expected):
    assert discovery.policy_analysis({"policy": text})["user_agents"][0]["value"] == expected


def test_explicit_no_automated_scanning_rule_blocks_import():
    analysis = discovery.policy_analysis({"policy": "No automated scanning is allowed."})
    assert analysis["automation_prohibited"]
    with pytest.raises(ValueError):
        discovery.configure(analysis, discovery.PolicySettings(rules_reviewed=True))


def test_url_scope_origin_constraints_keep_exact_url_profile_even_at_root():
    main.assets.clear(); main.jobs.clear(); main.queue = asyncio.Queue()
    with TestClient(main.app) as client, patch.object(main, "run_scan_job", no_scan), patch.object(main, "public_host"):
        doc = load_program(client, fixture_page("User-Agent: Fixture", [dict(ROW, identifier="https://example.org/", type="url")]))
        response = import_program(client, doc, settings={})
        assert response.status_code == 200
        queued = client.post("/api/scans", json={"asset_id": response.json()["web_asset_ids"][0],
            "policy_confirmed": True, "active_confirmed": True, "modules": ["zap-passive", "httpx", "nuclei"]})
        assert queued.status_code == 200, queued.text
        assert main.jobs[queued.json()["id"]]["modules"] == ["zap-passive"]

def test_escaped_23andme_style_header_is_deduplicated_and_resolves_username():
    policy = ("Requests must include header X-HackerOne-Research: " + chr(92) + "<YOUR-USERNAME>\n") * 2
    policy += "You must use your @wearehackerone.com email for testing accounts."
    analysis = discovery.policy_analysis({"policy": policy})
    assert len(analysis["headers"]) == 1 and not analysis["user_agents"]
    configured = discovery.configure(analysis, discovery.PolicySettings(
        researcher="wuhp", test_email="wuhp@wearehackerone.com",
        test_account_confirmed=True, custom_agent="Researcher-wuhp"))
    assert configured["headers"] == {"X-HackerOne-Research": "wuhp"}
    assert configured["user_agent"] == "Researcher-wuhp"


def test_header_example_inside_user_agent_is_not_a_duplicate_required_header():
    analysis = discovery.policy_analysis({"policy": "User-Agent: X-HackerOne-Research: " + chr(92) + "<YOUR-USERNAME>"})
    assert len(analysis["user_agents"]) == 1 and analysis["headers"] == []
    configured = discovery.configure(analysis, discovery.PolicySettings(researcher="wuhp"))
    assert configured["user_agent"] == "X-HackerOne-Research: wuhp"


@pytest.mark.parametrize("template", ["<YOUR-USERNAME>", "{username}", "[username]", "YOUR-USERNAME", "{{USERNAME}}"])
def test_common_username_aliases_replace_the_entire_placeholder(template):
    assert discovery.substitute("Research-" + template, "wuhp") == "Research-wuhp"


def test_custom_replacements_and_domain_email_work_without_duplicating_inputs():
    analysis = discovery.policy_analysis({"policy": "Use header X-Bug-Bounty: <TEAM>-<YOUR-USERNAME>\nUse your @wearehackerone.com email for testing accounts."})
    configured = discovery.configure(analysis, discovery.PolicySettings(
        researcher="wuhp", replacements={"TEAM": "Research", "@wearehackerone.com": "wuhp@wearehackerone.com"},
        test_account_confirmed=True))
    assert configured["headers"]["X-Bug-Bounty"] == "Research-wuhp"


def test_missing_identity_program_is_skipped_while_ready_program_imports():
    main.assets.clear()
    async def fetch(path, params=None):
        if "/missing/" in path:
            return fixture_page(RULES)
        return fixture_page("User-Agent: Ready-Researcher")
    with TestClient(main.app) as client, patch.object(discovery, "fetch_json", fetch):
        ready = client.get("/api/discovery/programs/hackerone/ready").json()
        missing = client.get("/api/discovery/programs/hackerone/missing").json()
        response = client.post("/api/discovery/import", json={"programs": [
            {"review_id": doc["review_id"], "asset_ids": [doc["assets"][0]["id"]], "settings": {}}
            for doc in (ready, missing)]})
        assert response.status_code == 200, response.text
        data = response.json()
        assert data["imported"] == 1 and data["programs"] == 1
        assert data["skipped"][0]["program_id"] == "hackerone:missing"
        assert len(main.assets) == 1


def test_setup_preview_uses_same_checks_and_values_as_import():
    main.assets.clear()
    with TestClient(main.app) as client:
        doc = load_program(client, fixture_page(RULES))
        settings = {"researcher": "wuhp", "test_email": "wuhp@wearehackerone.com"}
        body = {"programs": [{"review_id": doc["review_id"], "settings": settings}]}
        preview = client.post("/api/discovery/resolve", json=body).json()["programs"][0]
        assert not preview["ready"] and "Confirm" in preview["reason"]
        settings["test_account_confirmed"] = True
        preview = client.post("/api/discovery/resolve", json=body).json()["programs"][0]
        assert preview["ready"] and preview["user_agent"] == "HackerOne-wuhp"
        imported = import_program(client, doc, settings=settings)
        assert imported.json()["imported"] == 1


def test_reviewed_header_override_is_available_when_a_custom_token_is_missing():
    analysis = discovery.policy_analysis({"policy": "Use header X-Bug-Bounty: <TEAM-NAME>"})
    settings = discovery.PolicySettings(rules_reviewed=True, header_values={"X-Bug-Bounty": "Reviewed-Team"})
    assert discovery.configure(analysis, settings)["headers"] == {"X-Bug-Bounty": "Reviewed-Team"}


def test_missing_review_is_skipped_but_invalid_ready_scope_stays_atomic():
    main.assets.clear()
    with TestClient(main.app) as client:
        doc = load_program(client, fixture_page("User-Agent: Fixed"))
        response = client.post("/api/discovery/import", json={"programs": [
            {"review_id": doc["review_id"], "asset_ids": [doc["assets"][0]["id"]]},
            {"review_id": doc["review_id"], "asset_ids": ["forged-scope-id"]}]})
        assert response.status_code == 422 and not main.assets


@pytest.mark.parametrize("value", ["bad\r\nInjected: value", "bad" + chr(92) + "nInjected: value"])
def test_custom_replacements_cannot_inject_headers(value):
    with pytest.raises(ValueError):
        discovery.substitute("<TEAM>", "wuhp", {"TEAM": value})
