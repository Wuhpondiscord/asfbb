import asyncio
import json
from unittest.mock import patch

import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient

from app import idor_module, idor_runner, main
from app.module_inputs import ModuleInputs


def inputs(**overrides):
    return ModuleInputs(idor_path="/api/item", idor_parameter="item_id",
                        idor_baseline="reference-private", idor_values=["other-private"], **overrides)


@pytest.mark.parametrize("path", ["//outside.org/api", "https://outside.org/api", "/../api", "/api?token=x", "/api#x"])
def test_idor_path_is_same_origin_only(path):
    with pytest.raises(ValidationError):
        ModuleInputs(idor_path=path)


@pytest.mark.parametrize("values", [["a"] * 4, ["a", "a"], ["../secret"], ["a&admin=true"], [""]])
def test_reference_values_are_bounded_and_not_payloads(values):
    with pytest.raises(ValidationError):
        ModuleInputs(idor_values=values)


def test_missing_context_skips_without_starting_a_process():
    with patch.object(idor_module, "execute") as execute:
        result = asyncio.run(idor_module.run("https://example.org", "example.org", "Test", 1.5))
    assert result["status"] == "skipped"
    assert not execute.called


def test_reference_values_never_enter_public_job_options():
    summary = json.dumps(inputs().public_summary())
    assert "reference-private" not in summary and "other-private" not in summary
    assert "item_id" not in summary
    assert inputs().public_summary()["idor_value_count"] == 1


def test_adapter_does_not_expose_raw_process_output():
    async def execute(args, timeout):
        assert timeout == 55
        report = {"profile": "idor-forge-get-comparison", "status": "completed", "requests": 2,
                  "comparisons": [{"index": 1, "http_status": 200, "candidate": True,
                                   "similarity": {"text_similarity": 0.9}}]}
        return ["[stderr] private-response-body", json.dumps(report)], "completed"
    with patch.object(idor_module, "execute", execute):
        result = asyncio.run(idor_module.run("https://example.org", "example.org", "Test", 1.5, inputs()))
    serialized = json.dumps(result)
    assert result["status"] == "findings"
    assert result["alerts"][0]["confidence"] == "Low"
    assert all(value not in serialized for value in ("private-response-body", "reference-private", "other-private"))
    assert result["alerts"][0]["url"] == "https://example.org/api/item"


def test_missing_native_report_cannot_claim_clean_scan():
    async def execute(*args): return ["private response"], "completed"
    with patch.object(idor_module, "execute", execute):
        result = asyncio.run(idor_module.run("https://example.org", "example.org", "Test", 1.5, inputs()))
    assert result["status"] == "failed"
    assert "private response" not in json.dumps(result)


def test_rate_limit_stops_remaining_comparisons_and_redacts_error_context():
    class Checker:
        pass
    calls = []
    def fetch(*args):
        calls.append(args)
        if len(calls) == 1:
            return 200, "baseline-private-body"
        raise idor_runner.ProfileStopped("Rate limited; remaining comparisons skipped")
    spec = {"target": "https://example.org", "host": "example.org", "agent": "Test", "delay": 1,
            "inputs": inputs().model_dump()}
    with patch.object(idor_runner, "fetch", fetch):
        report = idor_runner.run(spec, Checker(), session=type("Session", (), {})(), pause=lambda _: None)
    assert len(calls) == 2 and report["status"] == "partial"
    assert "baseline-private-body" not in json.dumps(report)


def test_logs_have_levels_retention_metadata_and_remain_owner_scoped():
    main.scan_events.clear()
    main.queue = asyncio.Queue()
    main.jobs.clear()
    with TestClient(main.app) as a:
        owner_a = a.get("/api/health").headers["x-asfb-session"]
        owner_b = "different-owner"
        main.log_event({"owner": owner_a, "id": "a", "target": "https://example.org"}, "stage_finished",
                       module="idor-forge", status="skipped", elapsed_ms=12, reason="Inputs missing")
        main.log_event({"owner": owner_b, "id": "b", "target": "https://other.org"}, "failed")
        result = a.get("/api/logs").json()
    assert result["total"] == 1 and result["returned"] == 1 and not result["truncated"]
    assert result["events"][0]["level"] == "warning"
    assert result["events"][0]["event_id"]
    assert "owner" not in result["events"][0] and "other.org" not in json.dumps(result)

def test_batch_reference_comparisons_reach_normal_asset_validation():
    main.queue = asyncio.Queue()
    main.jobs.clear()
    with TestClient(main.app) as client:
        response = client.post("/api/scans/batch", json={
            "asset_ids": ["a", "b"], "policy_confirmed": True, "active_confirmed": True,
            "modules": ["idor-forge"], "options": {"inputs": inputs().model_dump()}})
    assert response.status_code == 409
    assert "scope" in response.json()["detail"].lower()
    assert main.queue.empty()