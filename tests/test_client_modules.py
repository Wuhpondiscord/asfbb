import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from app import client_modules as tools, config, main, nuclei_catalog, pipeline, web_modules
from test_worker_pipeline import run_job


def test_script_inventory_keeps_same_origin_and_javascript_inline_only():
    parser = tools.ScriptInventory("https://example.org/")
    parser.feed('<script src="/app.js"></script><script src="https://outside.org/a.js"></script>'
                '<script src="https://example.org:8443/a.js"></script>'
                '<script>/*! jQuery v1.6.1 */</script><script type="application/ld+json">{}</script>')
    assert parser.urls == ["https://example.org/app.js"]
    assert len(parser.inline) == 1


def test_retire_no_javascript_skips_without_starting_node():
    async def fetch(*args): return b"<html>No scripts</html>", "text/html", "https://example.org/"
    with patch.object(tools, "fetch_sample", fetch), patch.object(tools, "execute") as execute:
        result = asyncio.run(tools.retirejs("https://example.org/", "example.org", "Test", 1.5, []))
    assert result["status"] == "skipped"
    assert not execute.called


def test_retire_fetch_failure_does_not_claim_a_clean_scan():
    async def fetch(*args): raise httpx.ReadTimeout("mock")
    with patch.object(tools, "fetch_sample", fetch), patch.object(tools, "execute") as execute:
        result = asyncio.run(tools.retirejs("https://example.org/", "example.org", "Test", 1.5, []))
    assert result["status"] == "skipped"
    assert "ReadTimeout" in result["reason"]
    assert not execute.called


def test_retire_samples_bounded_files_uses_bundled_database_and_maps_findings():
    fetches = []
    async def fetch(url, *args):
        fetches.append(url)
        if url == "https://example.org/":
            scripts = "".join(f'<script src="/jquery-{i}.js"></script>' for i in range(8))
            return scripts.encode(), "text/html", url
        return b"/* sample */", "application/javascript", url
    async def execute(args, timeout):
        assert "--includeOsv" not in args
        assert args[args.index("--jsrepo") + 1] == "/opt/retire-db/jsrepository-v5.json"
        root = Path(args[args.index("--path") + 1])
        files = sorted(root.rglob("*.js"))
        assert len(files) == config.RETIRE_MAX_FILES
        assert files[0].name == "jquery-0.js"
        report = {"data": [{"file": str(files[0]), "results": [
            {"component": "jquery", "version": "1.6.1", "vulnerabilities": [
                {"severity": "high", "identifiers": {"CVE": ["CVE-TEST"], "summary": "Mock candidate"}}]}]}],
                  "errors": []}
        Path(args[args.index("--outputpath") + 1]).write_text(json.dumps(report))
        return ["[diagnostic] Process exit code: 13"], "failed"
    async def sleep(*args): pass
    with patch.object(tools, "fetch_sample", fetch), patch.object(tools, "execute", execute), \
         patch.object(tools.asyncio, "sleep", sleep):
        result = asyncio.run(tools.retirejs("https://example.org/", "example.org", "Test", 1.5,
                                           ["https://outside.org/out.js"]))
    assert result["status"] == "partial"  # More JS existed than the configured sample.
    assert result["sampled_files"] == 4
    assert result["alerts"][0]["url"] == "https://example.org/jquery-0.js"
    assert result["alerts"][0]["risk"] == "High"
    assert len(fetches) == 5
    assert "Process exit code: 13" not in result["reason"]


def test_retire_unknown_report_path_is_never_assigned_to_the_target(tmp_path):
    known = str((tmp_path / "known.js").resolve())
    report = {"data": [{"file": str(tmp_path / "outside.js"), "results": [
        {"component": "x", "version": "1", "vulnerabilities": [{"severity": "high"}]}]}]}
    assert tools.parse_retire(report, {known: "https://example.org/a.js"}) == []


@pytest.mark.parametrize("guard_stats,expected", [
    ({"requests": 2}, "completed"),
    ({"requests": 12, "limit_reached": True}, "partial"),
    ({"requests": 1, "blocked": 1}, "partial"),
])
def test_wapiti_cli_profile_and_coverage(guard_stats, expected):
    async def execute(args, timeout):
        assert args[args.index("-m") + 1] == "csp,http_headers,cookieflags"
        assert args[args.index("--scope") + 1] == "url"
        assert args[args.index("--headless") + 1] == "no"
        assert "--no-bugreport" in args
        Path(args[args.index("-o") + 1]).write_text(json.dumps({
            "vulnerabilities": {"Header": [{"method": "GET", "path": "/",
                                           "level": 1, "info": "missing", "module": "http_headers"}]}}))
        Path(args[args.index("--asfb-stats") + 1]).write_text(json.dumps(guard_stats))
        return [], "completed"
    with patch.object(tools, "execute", execute):
        result = asyncio.run(tools.wapiti("https://example.org/", "example.org", "Test", 1.5))
    assert result["status"] == expected
    assert result["alerts"][0]["source"] == "wapiti"


def test_wapiti_missing_report_is_failed():
    async def execute(*args): return [], "completed"
    with patch.object(tools, "execute", execute):
        result = asyncio.run(tools.wapiti("https://example.org/", "example.org", "Test", 1.5))
    assert result["status"] == "failed"


def test_wapiti_parser_filters_other_origins_and_methods():
    report = {"vulnerabilities": {"Mock": [
        {"method": "GET", "path": "https://outside.org/", "info": "outside"},
        {"method": "POST", "path": "/", "info": "wrong method"},
        {"method": "GET", "path": "/", "info": "kept", "level": 1}]}}
    findings = tools.parse_wapiti(report, "https://example.org/")
    assert len(findings) == 1 and findings[0]["description"] == "kept"


def test_new_module_dispatch_receives_discovery_inventory():
    seen = []
    async def retire(*args):
        seen.extend(args[-1])
        return {"status": "skipped", "alerts": [], "reason": "No JS"}
    with patch.object(tools, "retirejs", retire):
        result = asyncio.run(web_modules.run_web_module(
            "retirejs", "https://example.org/", "example.org", "Test",
            discovered=["https://example.org/a.js"]))
    assert result["status"] == "skipped"
    assert seen == ["https://example.org/a.js"]


def test_worker_new_modules_and_skip_are_isolated():
    run, job = run_job(["retirejs", "wapiti", "httpx"])
    async def module(name, *args):
        return {"status": "skipped" if name == "retirejs" else "completed", "alerts": [], "output": name}
    async def probe(*args): return {"status": "completed", "probes": []}
    with patch.object(main, "public_host"), patch.object(main, "run_web_module", module), \
         patch.object(main, "probe", probe):
        asyncio.run(run())
    assert job["status"] == "completed"
    assert job["pipeline"]["retirejs"] == "skipped"
    assert job["pipeline"]["httpx"] == "completed"


def test_optional_nuclei_templates_validate_and_do_not_change_defaults():
    for name in ("directory-listing", "openapi-json"):
        assert name in nuclei_catalog.builtins()
        assert name not in config.NUCLEI_DEFAULT_IDS
        content = nuclei_catalog.bundled_content(name)
        nuclei_catalog.validate_template(content)
        assert nuclei_catalog.estimate_requests(content) <= 2


def test_openapi_fixed_paths_run_only_at_origin():
    async def execute(args, deadline):
        targets = Path(args[args.index("-l") + 1]).read_text().splitlines()
        assert targets == ["https://example.org/"]
        return [], "completed"
    with patch.object(pipeline, "execute", execute):
        result = asyncio.run(pipeline.nuclei("https://example.org/", "example.org", "Test",
                            ["https://example.org/app.js"], default_ids=["openapi-json"]))
    assert result["targets_checked"] == 1
