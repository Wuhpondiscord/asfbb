import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app import main, web_modules as web
from test_worker_pipeline import run_job


@pytest.mark.parametrize("html, expected", [
    ('<meta name="generator" content="WordPress 6.8">', "https://example.org/"),
    ('<script src="/blog/wp-includes/js/a.js"></script>', "https://example.org/blog/"),
    ('<link href="/wp-content/themes/theme/style.css">', "https://example.org/"),
    ('<script src="https://outside.org/wp-includes/a.js"></script>', None),
    ('<script src="https://example.org:8443/wp-includes/a.js"></script>', None),
    ('<p>This tutorial describes WordPress and wp-content.</p>', None),
    ('<html><title>Static website</title></html>', None),
])
def test_wordpress_evidence_requires_current_page_markers(html, expected):
    parser = web.WordPressEvidence("https://example.org/")
    parser.feed(html)
    assert parser.install_url == expected


def test_wpscan_non_wordpress_never_spawns_scanner():
    class Response:
        status_code = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        async def aiter_bytes(self, **kwargs):
            yield b"<html>Not a WordPress site</html>"
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        def stream(self, *args, **kwargs): return Response()
    with patch.object(web, "public_host"), \
         patch.object(web.httpx, "AsyncClient", return_value=Client()) as client, \
         patch.object(web, "execute") as execute:
        result = asyncio.run(web.run_web_module("wpscan", "https://example.org/", "example.org", "Test"))
    assert result["status"] == "skipped"
    assert "no current-page" in result["reason"]
    assert not execute.called
    assert client.call_args.kwargs["follow_redirects"] is False


def test_wordpress_preflight_does_not_follow_external_redirect():
    class Response:
        status_code = 302
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return False
        def stream(self, *args, **kwargs): return Response()
    with patch.object(web, "public_host"), \
         patch.object(web.httpx, "AsyncClient", return_value=Client()):
        target, reason = asyncio.run(web.wordpress_preflight("https://example.org/", "example.org", "Test"))
    assert target is None
    assert "302" in reason
    assert "not followed" in reason


def test_preflight_network_failure_skips_with_unknown_coverage():
    class Client:
        async def __aenter__(self): raise httpx.ReadTimeout("mock")
        async def __aexit__(self, *args): return False
    with patch.object(web, "public_host"), \
         patch.object(web.httpx, "AsyncClient", return_value=Client()), \
         patch.object(web, "execute") as execute:
        result = asyncio.run(web.run_web_module("wpscan", "https://example.org/", "example.org", "Test"))
    assert result["status"] == "skipped"
    assert "unconfirmed" in result["reason"]
    assert "ReadTimeout" in result["reason"]
    assert not execute.called


def test_tls_http_target_skips_without_dns_or_process():
    with patch.object(web, "public_host") as dns, patch.object(web, "execute") as execute:
        result = asyncio.run(web.run_web_module("testssl", "http://example.org/", "example.org", "Test"))
    assert result["status"] == "skipped"
    assert not dns.called and not execute.called


def test_json_parsers_scope_and_tls_severity():
    report = [{"vulnerabilities": [
        {"url": "/a", "id": "1", "msg": "candidate"},
        {"url": "https://outside.org/a", "msg": "outside"},
        {"url": "https://example.org:8443/a", "msg": "wrong origin"}]}]
    assert len(web.parse_nikto(report, "https://example.org/")) == 1
    tls = web.parse_testssl([{"id": "good", "severity": "OK", "finding": "fine"},
                            {"id": "cert", "severity": "HIGH", "finding": "expired"}],
                           "https://example.org/")
    assert len(tls) == 1 and tls[0]["risk"] == "High"
    wp = web.parse_wpscan({"version": {"vulnerabilities": [{"title": "core candidate"}]},
                          "interesting_findings": [{"url": "https://outside.org/", "to_s": "bad"}]},
                         "https://example.org/")
    assert len(wp) == 1 and wp[0]["source"] == "wpscan"


def test_wpscan_exit_five_is_findings_and_token_is_not_persisted(monkeypatch):
    monkeypatch.setenv("WPSCAN_API_TOKEN", "secret-test-token")
    async def preflight(*args): return "https://example.org/", "WordPress marker"
    async def execute(args, deadline):
        assert "--api-token" not in args
        assert "--no-update" in args and "--max-threads" in args
        assert "--passwords" not in args and "--users" not in args
        path = args[args.index("--output") + 1]
        Path(path).write_text(json.dumps({"version": {"vulnerabilities": [{"title": "candidate"}]}}))
        return ["[diagnostic] Process exit code: 5"], "failed"
    with patch.object(web, "public_host"), patch.object(web, "wordpress_preflight", preflight), \
         patch.object(web, "execute", execute):
        result = asyncio.run(web.run_web_module("wpscan", "https://example.org/", "example.org", "Test"))
    assert result["status"] == "findings"
    assert len(result["alerts"]) == 1
    assert "secret-test-token" not in json.dumps(result)
    assert "Process exit code" not in result["reason"]


@pytest.mark.parametrize("module", ["nikto", "wpscan", "testssl"])
def test_scanner_deadline_preserves_report_findings(module):
    async def preflight(*args): return "https://example.org/", "WordPress marker"
    async def execute(args, deadline):
        flag = {"nikto": "-output", "wpscan": "--output", "testssl": "--jsonfile"}[module]
        report = {
            "nikto": [{"vulnerabilities": [{"url": "/a", "id": "x", "msg": "candidate"}]}],
            "wpscan": {"interesting_findings": [{"url": "https://example.org/", "to_s": "candidate"}]},
            "testssl": [{"id": "cert", "severity": "WARN", "finding": "candidate"}],
        }[module]
        Path(args[args.index(flag) + 1]).write_text(json.dumps(report))
        return ["[diagnostic] Deadline exceeded"], "timeout"
    with patch.object(web, "public_host"), patch.object(web, "wordpress_preflight", preflight), \
         patch.object(web, "execute", execute):
        result = asyncio.run(web.run_web_module(module, "https://example.org/", "example.org", "Test"))
    assert result["status"] == "timeout"
    assert len(result["alerts"]) == 1
    assert "Deadline exceeded" in result["reason"]


def test_nikto_internal_deadline_is_partial_not_completed():
    async def execute(args, deadline):
        Path(args[args.index("-output") + 1]).write_text("[]")
        return ["Host maximum execution time of 45 seconds reached"], "completed"
    with patch.object(web, "public_host"), patch.object(web, "execute", execute):
        result = asyncio.run(web.run_web_module("nikto", "https://example.org/", "example.org", "Test"))
    assert result["status"] == "partial"


def test_missing_json_cannot_claim_success():
    async def execute(*args): return [], "completed"
    with patch.object(web, "public_host"), patch.object(web, "execute", execute):
        result = asyncio.run(web.run_web_module("nikto", "https://example.org/", "example.org", "Test"))
    assert result["status"] == "failed"


def test_worker_dispatches_new_modules_and_continues_after_skip():
    execute_job, job = run_job(["wpscan", "testssl", "httpx"])
    async def module(name, *args):
        return {"status": "skipped" if name == "wpscan" else "completed",
                "alerts": [], "reason": "Not applicable" if name == "wpscan" else "",
                "output": name}
    async def probe(*args): return {"status": "completed", "probes": []}
    with patch.object(main, "public_host"), patch.object(main, "run_web_module", module), \
         patch.object(main, "probe", probe):
        asyncio.run(execute_job())
    assert job["status"] == "completed"
    assert job["pipeline"] == {"wpscan": "skipped", "testssl": "completed", "httpx": "completed"}


@pytest.mark.parametrize("module", ["nikto", "wpscan", "testssl"])
def test_new_modules_require_existing_active_authorization(module):
    with TestClient(main.app) as client:
        result = client.post("/api/scans", json={"asset_id": "absent", "modules": [module],
                                               "policy_confirmed": True})
    assert result.status_code == 422
    assert "Explicit permission" in result.json()["detail"]


def test_report_size_is_bounded(tmp_path):
    report = tmp_path / "report.json"
    report.write_text('["too long"]')
    with patch.object(web.config, "WEB_REPORT_MAX_BYTES", 2):
        assert web.read_report(report) is None
@pytest.mark.parametrize("token,enumeration", [("", "p,t"), ("   ", "p,t"), ("fixture-token", "vp,vt")])
def test_wpscan_selects_keyless_inventory_without_vulnerable_enumeration(monkeypatch, token, enumeration):
    monkeypatch.setenv("WPSCAN_API_TOKEN", token)
    args = web.command("wpscan", "https://example.org/", "example.org", "Fixture", "/tmp/report.json", 1.5)
    assert args[args.index("--enumerate") + 1] == enumeration
    assert args[args.index("--user-agent") + 1] == "Fixture"
    assert "--api-token" not in args
    for option in ("--detection-mode", "--plugins-detection", "--themes-detection"):
        assert args[args.index(option) + 1] == "passive"


def test_wpscan_keyless_valid_report_completes_with_coverage_limitation(monkeypatch):
    monkeypatch.delenv("WPSCAN_API_TOKEN", raising=False)
    async def preflight(*args): return "https://example.org/", "WordPress marker"
    async def execute(args, deadline):
        assert args[args.index("--enumerate") + 1] == "p,t"
        Path(args[args.index("--output") + 1]).write_text(json.dumps({
            "interesting_findings": [{"url": "https://example.org/", "to_s": "WordPress observation"}],
            "plugins": {"fixture-plugin": {"version": {"number": "1.0"}}}}))
        return [], "completed"
    with patch.object(web, "public_host"), patch.object(web, "wordpress_preflight", preflight), patch.object(web, "execute", execute):
        result = asyncio.run(web.run_web_module("wpscan", "https://example.org/", "example.org", "Test"))
    assert result["status"] == "completed" and len(result["alerts"]) == 1
    assert "Keyless passive" in result["reason"] and "database coverage is unavailable" in result["reason"]
