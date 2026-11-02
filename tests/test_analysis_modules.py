import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app import analysis_modules as analysis, planning, main
from app.module_inputs import ModuleInputs
from app.waf_runner import Guard, ProfileStopped, run as run_waf
from test_worker_pipeline import run_job


def test_semgrep_requires_source_and_explicit_language_without_launching_process():
    for inputs in (ModuleInputs(), ModuleInputs(source_text="source"), ModuleInputs(sast_language="python")):
        with patch.object(analysis, "execute") as execute:
            result = asyncio.run(analysis.run("semgrep", "https://example.org", "example.org", "Test", 1, inputs))
        assert result["status"] == "skipped" and not execute.called


def test_semgrep_uses_bundled_rules_and_omits_source_context_from_results():
    secret = "fixture-private-source"
    paths = []
    async def execute(args, timeout):
        assert args[args.index("--metrics") + 1] == "off"
        assert "--disable-version-check" in args and "--oss-only" in args
        assert "--config" in args and args[args.index("--config") + 1].endswith("review.yaml")
        assert "--autofix" not in args and "--allow-local-builds" not in args
        assert "--no-git-ignore" in args and timeout == 75
        source = Path(args[-1]);paths.append(source)
        assert source.suffix == ".py" and source.read_text() == secret
        assert source.stat().st_mode & 0o777 == 0o600
        Path(args[args.index("--output") + 1]).write_text(json.dumps({
            "results": [{"check_id": "prefix.asfb-python-dynamic-code", "start": {"line": 3},
                         "extra": {"message": secret, "lines": secret, "metavars": {"value": secret}}}],
            "errors": [], "paths": {"scanned": [str(source)]}}))
        return [], "completed"
    with patch.object(analysis, "execute", execute):
        result = asyncio.run(analysis.run("semgrep", "https://example.org", "example.org", "Test", 1,
                             ModuleInputs(source_text=secret, sast_language="python")))
    assert result["status"] == "findings" and result["alerts"][0]["source_line"] == 3
    assert secret not in json.dumps(result)
    assert all(not path.exists() for path in paths)


@pytest.mark.parametrize("report", [
    {"results": [], "errors": [{"message": "fixture-private-error"}], "paths": {"scanned": []}},
    {"results": [], "errors": [], "paths": {"scanned": []}},
    {},
])
def test_semgrep_errors_or_skipped_file_cannot_claim_clean(report):
    async def execute(args, timeout):
        Path(args[args.index("--output") + 1]).write_text(json.dumps(report))
        return [], "completed"
    with patch.object(analysis, "execute", execute):
        result = asyncio.run(analysis.run("semgrep", "https://example.org", "example.org", "Test", 1,
                             ModuleInputs(source_text="fixture-private-source", sast_language="python")))
    assert result["status"] == "failed"
    assert "fixture-private" not in json.dumps(result)


def test_semgrep_unknown_rule_messages_and_lines_are_never_trusted():
    report = {"results": [{"check_id": "fixture-private-native-rule", "start": {"line": 1},
                           "extra": {"message": "fixture-private-message"}},
                          {"check_id": "asfb-python-dynamic-code", "start": {"line": True}}]}
    assert analysis.normalized_sast(report, "https://example.org") == []


class FakeResponse:
    status_code = 200
    def __init__(self, body=b"fixture-private-body"):
        self.body, self._content = body, b""
    def __enter__(self): return self
    def __exit__(self, *args): return False
    def iter_content(self, size): yield self.body


class FakeSession:
    def __init__(self, response=None):
        self.calls, self.response, self.trust_env = [], response or FakeResponse(), True
    def get(self, target, **kwargs):
        self.calls.append((target, kwargs))
        assert kwargs["allow_redirects"] is False and kwargs["verify"] is True
        assert kwargs["headers"] == {"User-Agent": "Test"}
        return self.response
    def close(self): pass


SPEC = {"target": "https://example.org/app?q=1", "host": "example.org", "agent": "Test", "delay": 1}


def test_waf_guard_preserves_scope_revalidates_dns_paces_and_caps_requests():
    session, pauses = FakeSession(), []
    with patch("app.waf_runner.public_host") as public:
        guard = Guard(SPEC, session, pauses.append)
        for _ in range(8):
            guard.request(params={"probe": "value"})
        with pytest.raises(ProfileStopped, match="request_budget"):
            guard.request()
    assert len(session.calls) == 8 and public.call_count == 8 and len(pauses) == 7
    assert session.trust_env is False
    assert all(target == SPEC["target"] for target, _ in session.calls)


@pytest.mark.parametrize("path", ["//outside.org/", "https://outside.org/", "/bad\nheader"])
def test_waf_guard_rejects_out_of_scope_request_paths(path):
    session = FakeSession()
    with patch("app.waf_runner.public_host"):
        guard = Guard(SPEC, session)
        with pytest.raises(ProfileStopped, match="scope_blocked"):
            guard.request(path=path)
    assert not session.calls


@pytest.mark.parametrize("probe", ["SLEEP(5)", "curl outside.org", "file:///etc/passwd", "/bin/cat"])
def test_waf_profile_does_not_forward_time_based_or_command_probes(probe):
    session = FakeSession()
    guard = Guard(SPEC, session)
    with pytest.raises(ProfileStopped, match="probe_blocked"):
        guard.request(params={"probe": probe})
    assert not session.calls


def test_waf_rate_limit_stops_the_profile_without_retries():
    response = FakeResponse();response.status_code = 429
    session = FakeSession(response)
    with patch("app.waf_runner.public_host"):
        guard = Guard(SPEC, session)
        with pytest.raises(ProfileStopped, match="rate_limited"):
            guard.request()
    assert len(session.calls) == 1


def test_waf_response_size_is_bounded_and_reported_partial():
    class Engine:
        def __init__(self, *args, **kwargs): self.rq = self.Request()
        def identwaf(self, **kwargs): return ["Mock vendor"], "fixture-private-trigger"
    session = FakeSession(FakeResponse(b"x" * 262145))
    with patch("app.waf_runner.public_host"):
        result = run_waf(SPEC, Engine, session)
    assert result["status"] == "partial" and result["stop_reason"] == "response_limit"
    assert result["vendors"] == ["Mock vendor"]
    assert "fixture-private" not in json.dumps(result)


def test_guided_waf_inventory_precedes_web_reviews_but_manual_order_remains_exact():
    requested = ["nuclei", "semgrep", "ffuf", "wafw00f", "httpx"]
    guided = planning.plan(requested, "guided")
    assert guided["effective"].index("wafw00f") < guided["effective"].index("ffuf")
    assert guided["effective"].index("wafw00f") < guided["effective"].index("nuclei")
    assert any(h["data"] == "WAF inventory / scan context" for h in guided["handoffs"])
    manual = planning.plan(requested, "manual")
    assert manual["effective"] == requested and manual["warnings"]


def test_worker_retains_waf_inventory_and_later_stage_context():
    run, job = run_job(["wafw00f", "semgrep"])
    async def module(name, *args, **kwargs):
        return {"status": "completed", "alerts": [], "waf": {"vendors": ["Mock vendor"], "requests": 2}} if name == "wafw00f" else {"status": "skipped", "alerts": []}
    with patch.object(main, "public_host"), patch.object(main, "run_web_module", module):
        asyncio.run(run())
    assert job["waf"]["vendors"] == ["Mock vendor"]
    event = next(e for e in main.scan_events if e["event"] == "stage_finished" and e["module"] == "semgrep")
    assert event["diagnostics"]["waf_context"] == ["Mock vendor"]


def test_source_language_is_public_but_source_is_not():
    summary = ModuleInputs(source_text="fixture-private-source", sast_language="typescript").public_summary()
    assert summary["sast_language"] == "typescript" and "fixture-private" not in json.dumps(summary)
