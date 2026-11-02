"""Offline status semantics: planned stops complete; actual failures stay visible."""
import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from app import final_modules, main, protocol_modules
from test_worker_pipeline import run_job


@pytest.mark.parametrize("status,rows,expected", [
    ("failed", ["[stderr] context deadline exceeded", "[diagnostic] Process exit code: 1"], True),
    ("completed", ["context deadline exceeded"], True),
    ("completed", [], False),
    ("failed", ["[diagnostic] Process exit code: 1"], False),
    ("failed", ["[stderr] provider: context deadline exceeded", "[diagnostic] Process exit code: 1"], False),
    ("failed", ["[stderr] context deadline exceeded", "[diagnostic] Process exit code: 2"], False),
    ("timeout", ["[stderr] context deadline exceeded", "[diagnostic] Deadline exceeded"], False),
    ("unavailable", ["context deadline exceeded"], False),
])
def test_only_explicit_native_deadline_is_an_amass_intentional_stop(status, rows, expected):
    assert final_modules.amass_internal_stop(rows, status) is expected


@pytest.mark.parametrize("native_status,expected", [("failed", "completed"), ("timeout", "timeout")])
def test_amass_retains_inventory_and_distinguishes_native_stop_from_forced_timeout(native_status, expected):
    async def execute(args, timeout):
        assert timeout == 600 and args[args.index("-timeout") + 1] == "5"
        Path(args[args.index("-o") + 1]).write_text("a.example.org\n")
        return ["[stderr] context deadline exceeded", "[diagnostic] Process exit code: 1"], native_status
    with patch.object(final_modules, "execute", execute):
        result = asyncio.run(final_modules.run("amass", "https://example.org/", "example.org", "Test", 1,
                                              profile="thorough"))
    assert result["status"] == expected and result["hosts"] == ["a.example.org"]
    assert result.get("early_stop", False) is (expected == "completed")
    if expected == "completed":
        assert result["coverage_complete"] is False
        assert result["stop_reason"] == "native_time_budget" and "Early stop" in result["reason"]


@pytest.mark.parametrize("reason,process_status,report_status,expected,early", [
    ("redirect_not_followed", "completed", "partial", "completed", True),
    ("scope_blocked", "completed", "partial", "completed", True),
    ("request_budget", "completed", "partial", "completed", True),
    ("response_limit", "completed", "partial", "completed", True),
    ("deadline", "completed", "partial", "partial", False),
    ("rate_limited", "completed", "partial", "partial", False),
    ("request_failed", "completed", "partial", "partial", False),
    ("dns_inconclusive", "completed", "partial", "partial", False),
    ("engine_error", "completed", "failed", "failed", False),
    ("unknown", "completed", "partial", "partial", False),
    ("redirect_not_followed", "timeout", "partial", "timeout", False),
    ("redirect_not_followed", "failed", "partial", "failed", False),
    ("redirect_not_followed", "completed", "running", "partial", False),
])
def test_protocol_adapter_requires_finished_report_and_recognized_policy_stop(
        reason, process_status, report_status, expected, early):
    async def execute(args, timeout):
        Path(args[-1]).write_text(json.dumps({"profile": "corsy", "status": report_status,
            "stop_reason": reason, "requests": 1, "observations": [], "raw": "fixture-private"}))
        return ["fixture-private"], process_status
    with patch.object(protocol_modules, "execute", execute):
        result = asyncio.run(protocol_modules.run("corsy", "https://example.org/", "example.org", "Test", 1))
    assert result["status"] == expected and result.get("early_stop", False) is early
    assert "fixture-private" not in json.dumps(result)
    if early:
        assert result["coverage_complete"] is False and result["stop_reason"] == reason
        assert result["reason"].startswith("Early stop:")


def test_policy_stop_preserves_findings():
    async def execute(args, timeout):
        Path(args[-1]).write_text(json.dumps({"profile": "corsy", "status": "partial",
            "stop_reason": "request_budget", "requests": 12,
            "observations": [{"kind": "cors_observation", "category": "origin reflected",
                              "credential_candidate": True}]}))
        return [], "completed"
    with patch.object(protocol_modules, "execute", execute):
        result = asyncio.run(protocol_modules.run("corsy", "https://example.org/", "example.org", "Test", 1))
    assert result["status"] == "findings" and len(result["alerts"]) == 1 and result["early_stop"]


def test_completed_policy_stop_is_recorded_without_degrading_job():
    run, job = run_job(["corsy"])
    async def module(*args, **kwargs):
        return {"status": "completed", "alerts": [], "early_stop": True,
                "stop_reason": "redirect_not_followed", "coverage_complete": False,
                "reason": "Early stop: redirect not followed; coverage is incomplete"}
    with patch.object(main, "public_host"), patch.object(main, "run_web_module", module):
        asyncio.run(run())
    assert job["status"] == "completed"
    assert job["stage_details"]["corsy"]["early_stop"] is True
    assert job["stage_details"]["corsy"]["coverage_complete"] is False
    event = next(e for e in main.scan_events if e.get("event") == "stage_finished")
    assert event["diagnostics"]["stop_reason"] == "redirect_not_followed"
    assert event["diagnostics"]["early_stop"] is True
