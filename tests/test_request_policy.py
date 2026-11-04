import asyncio
from unittest.mock import patch

import httpx
import pytest
import requests

from app import request_policy as policy, policy_entry
from app.main import ScanRequest
from app import bounty_discovery as discovery

POLICY = {"target": "https://example.org/app/", "path": "/app/", "query": "",
          "exclusions": ["/app/private/"], "headers": {"X-HackerOne-Research": "fixture"},
          "agent": "Required-Fixture", "delay": 2}


@pytest.mark.parametrize("url,allowed", [
    ("https://example.org/app/page", True), ("https://example.org/app/page?id=1", True),
    ("https://example.org/application", False), ("https://example.org/app/private/item", False),
    ("http://example.org/app/page", False), ("https://example.org:8080/app/", False),
    ("https://other.example.org/app/", False), ("https://example.org/app/%252e%252e/outside", False),
])
def test_policy_path_origin_exclusions_and_encoded_traversal(url, allowed):
    assert policy.allows(url, POLICY) is allowed


def test_required_headers_override_conflicting_identity_without_touching_other_headers():
    assert policy.headers({"user-agent": "Wrong", "x-hackerone-research": "Wrong", "Accept": "text/html"}, POLICY) == {
        "Accept": "text/html", "User-Agent": "Required-Fixture", "X-HackerOne-Research": "fixture"}


@pytest.mark.parametrize("module,flag", [
    ("nuclei", "-H"), ("katana", "-H"), ("httpx", "-H"), ("ffuf", "-H"),
    ("nikto", "-Add-header"), ("dalfox", "--headers"), ("kiterunner", "--header"), ("sqlmap", "--headers")
])
def test_native_header_options_are_applied_per_module(module, flag):
    args = policy.command(["engine"], {**POLICY, "module": module})
    assert flag in args and any("X-HackerOne-Research: fixture" in value for value in args)


def test_path_capability_does_not_reduce_entire_pipeline_to_zap():
    assert policy.stage_reason("retirejs", POLICY) == ""
    assert policy.stage_reason("semgrep", POLICY) == ""
    assert policy.stage_reason("arjun", POLICY) == ""
    assert policy.stage_reason("nikto", POLICY)
    assert policy.stage_reason("nikto", {**POLICY, "path": "/", "exclusions": []}) == ""


def test_python_entry_adds_mandatory_headers_and_blocks_before_http(monkeypatch):
    try:
        import aiohttp
        monkeypatch.setattr(aiohttp.ClientSession, "_request", aiohttp.ClientSession._request)
    except ImportError:
        pass
    seen = []
    def transport(session, request, **kwargs):
        seen.append(request)
        assert request.headers["User-Agent"] == "Required-Fixture"
        assert request.headers["X-HackerOne-Research"] == "fixture"
        assert kwargs["allow_redirects"] is False
        return requests.Response()
    token = policy.CURRENT.set(POLICY)
    with patch.object(requests.sessions.Session, "send", transport), \
         patch.object(httpx.Client, "send", httpx.Client.send), \
         patch.object(httpx.AsyncClient, "send", httpx.AsyncClient.send):
        policy_entry.install()
        session = requests.Session()
        session.send(requests.Request("GET", "https://example.org/app/page").prepare())
        with pytest.raises(policy.PolicyBlocked):
            session.send(requests.Request("GET", "https://example.org/app/private/item").prepare())
    policy.CURRENT.reset(token)
    assert len(seen) == 1


def test_query_scope_cannot_gain_unreviewed_parameters():
    p = {**POLICY, "query": "id=1"}
    assert policy.allows("https://example.org/app/page?id=1", p)
    assert not policy.allows("https://example.org/app/page?id=1&extra=2", p)


@pytest.mark.parametrize("module,flag", [("ffuf", "-H"), ("dalfox", "--user-agent"), ("sqlmap", "-A")])
def test_default_literal_agent_is_explicit_even_when_native_tool_has_its_own_default(module, flag):
    args = policy.command(["engine"], {**POLICY, "module": module, "agent": "ASFB-Research/0.1"})
    assert flag in args
    assert any("ASFB-Research/0.1" in value for value in args)
