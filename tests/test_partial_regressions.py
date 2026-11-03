"""Reproduce attached partial results with offline tool and HTTP fixtures."""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app import client_modules, coverage, review


async def no_sleep(*args):
    pass


async def clean_retire(args, timeout):
    Path(args[args.index("--outputpath") + 1]).write_text(json.dumps({"data": [], "errors": []}))
    return [], "completed"


def test_thorough_samples_all_44_files_from_reported_page():
    html = ("<html>" + "<script>const fixture=1;</script>" * 5 +
            "".join('<script src="/s' + str(i) + '.js"></script>' for i in range(39)) + "</html>").encode()
    async def fetch(url, agent, cap):
        return (html, "text/html", url) if url == "https://example.org/" else (b"/* fixture */", "text/javascript", url)
    with patch.object(client_modules, "fetch_sample", fetch), patch.object(client_modules, "execute", clean_retire), \
         patch.object(client_modules.asyncio, "sleep", no_sleep):
        result = asyncio.run(client_modules.retirejs("https://example.org/", "example.org", "Test", 1, [], profile="thorough"))
    assert result["status"] == "completed" and result["sampled_files"] == 44
    assert result["coverage"]["sampled_bytes"] <= 67108864
    assert not result["coverage"]["coverage_limited"]


@pytest.mark.parametrize("current_reference,expected", [(True, "partial"), (False, "completed")])
def test_missing_inventory_script_is_excluded_but_current_page_404_stays_a_gap(current_reference, expected):
    html = b'<html><script src="/good.js"></script>' + (b'<script src="/gone.js"></script>' if current_reference else b"") + b"</html>"
    async def fetch(url, agent, cap):
        if url == "https://example.org/":
            return html, "text/html", url
        if url.endswith("gone.js"):
            raise client_modules.FetchProblem("HTTP 404")
        return b"/* fixture */", "text/javascript", url
    with patch.object(client_modules, "fetch_sample", fetch), patch.object(client_modules, "execute", clean_retire), \
         patch.object(client_modules.asyncio, "sleep", no_sleep):
        result = asyncio.run(client_modules.retirejs("https://example.org/", "example.org", "Test", 1,
                                                  ["https://example.org/gone.js"], profile="thorough"))
    assert result["status"] == expected and result["sampled_files"] == 1
    assert result["coverage"]["fetch_failures"] == int(current_reference)
    assert result["coverage"]["missing_inventory_scripts"] == int(not current_reference)


def test_retire_aggregate_byte_limit_is_enforced_and_marked_as_policy_stop():
    settings = coverage.profile("thorough")
    settings["retire_total_bytes"] = 15
    async def fetch(url, agent, cap):
        if url == "https://example.org/":
            return b'<html><script src="/a.js"></script><script src="/b.js"></script></html>', "text/html", url
        return b"0123456789", "text/javascript", url
    with patch.object(client_modules, "coverage_settings", return_value=settings), \
         patch.object(client_modules, "fetch_sample", fetch), patch.object(client_modules, "execute", clean_retire), \
         patch.object(client_modules.asyncio, "sleep", no_sleep):
        result = asyncio.run(client_modules.retirejs("https://example.org/", "example.org", "Test", 1, [], profile="thorough"))
    assert result["status"] == "completed" and result["early_stop"]
    assert result["coverage"]["sampled_bytes"] == 10 and result["sampled_files"] == 1
    assert result["coverage_complete"] is False and "total_bytes" in result["coverage"]["policy_limits"]


@pytest.mark.parametrize("marker,failed,error_code,process_status,expected", [
    (True, 0, None, "completed", "completed"),
    (False, 0, None, "completed", "partial"),
    (True, 1, None, "completed", "partial"),
    (True, 0, "SESSION_LOST", "completed", "partial"),
    (True, 0, None, "timeout", "timeout"),
])
def test_dalfox_requires_native_budget_evidence_without_transport_errors(marker, failed, error_code, process_status, expected):
    async def execute(args, timeout):
        assert timeout == 420
        target = {"status": "incomplete"}
        if error_code:
            target["error_code"] = error_code
        Path(args[args.index("-o") + 1]).write_text(json.dumps({
            "meta": {"incomplete": True, "failed_requests": failed, "target_summary": [target]},
            "findings": []}))
        return ["[asfb] dalfox_scan_budget"] if marker else [], process_status
    with patch.object(review, "execute", execute):
        result = asyncio.run(review.review("dalfox", "https://example.org/?q=fixture", "example.org", profile="thorough"))
    assert result["status"] == expected
    assert result.get("early_stop", False) is (expected == "completed")
    if expected == "completed":
        assert result["coverage_complete"] is False and "Early stop" in result["reason"]


def test_dalfox_parameterless_review_keeps_ast_without_unrelated_injection():
    args = review.command("dalfox", "https://example.org/", "example.org", "thorough")
    assert "--skip-discovery" in args and "--skip-xss-scanning" in args
    assert "--skip-ast-analysis" not in args and "--silence" not in args
    assert "--skip-discovery" not in review.command("dalfox", "https://example.org/?q=a", "example.org")


@pytest.mark.parametrize("code,early,status", [(400, False, "partial"), (429, False, "partial"), (302, True, "completed")])
def test_guarded_arjun_adapter_reports_http_condition_instead_of_traceback(code, early, status):
    async def execute(args, timeout):
        assert "app.arjun_runner" in args and "--disable-redirects" in args
        Path(args[args.index("--asfb-report") + 1]).write_text(json.dumps({
            "status": status, "early_stop": early, "coverage_complete": False,
            "http_status": code, "requests": 2,
            "stop_reason": "redirect_not_followed" if early else "http_unavailable"}))
        return [], "completed"
    with patch.object(review, "execute", execute):
        result = asyncio.run(review.review("arjun", "https://example.org/?id=1", "example.org"))
    assert result["status"] == status and result.get("early_stop", False) is early
    assert "HTTP " + str(code) in result["reason"] and "Traceback" not in result["output"]
