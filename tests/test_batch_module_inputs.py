"""Batch inputs and credentials route per target; no scanner/network execution."""
import asyncio
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from app import main
from test_replay_modules import RACE, NOSQL


@pytest.fixture
def batch_client():
    main.assets.clear(); main.jobs.clear(); main.accounts.clear(); main.queue = asyncio.Queue()
    captured = {}
    async def put(item):
        _, spec = item
        captured[spec.asset_id] = spec
    with TestClient(main.app) as client, patch.object(main, "public_host"), patch.object(main.queue, "put", put):
        owner = client.get("/api/health").headers["x-asfb-session"]
        for key, name in (("a", "https://example.org/"), ("b", "https://other.example.org/")):
            main.assets[key] = {"id": key, "name": name, "owner": owner, "compatibility": "web"}
        yield client, captured, owner


def body(**changes):
    return {"asset_ids": ["a", "b"], "policy_confirmed": True, "active_confirmed": True,
            "modules": ["race-replay", "nosql", "idor-forge", "semgrep", "osv-scanner"], **changes}


def test_shared_replay_idor_source_and_sbom_do_not_block_batch(batch_client):
    client, captured, _ = batch_client
    sbom = json.dumps({"bomFormat": "CycloneDX", "components": [
        {"name": "fixture", "version": "1.0", "purl": "pkg:npm/fixture@1.0"}]})
    result = client.post("/api/scans/batch", json=body(options={"inputs": {
        "race": RACE, "nosql": NOSQL, "idor_path": "/api/items", "idor_baseline": "first",
        "idor_values": ["second"], "source_text": "fixture-private-source", "sast_language": "python",
        "sbom_text": sbom}}, max_requests=3))
    assert result.status_code == 200, result.text
    assert result.json()["queued"] == 2
    assert set(captured) == {"a", "b"}
    for spec in captured.values():
        assert spec.options.inputs.race and spec.options.inputs.nosql
        assert spec.options.inputs.idor_values == ["second"]
        assert spec.options.inputs.source_text == "fixture-private-source"
        assert spec.options.inputs.sbom_text and spec.max_requests == 3
    public = client.get("/api/scans").text
    assert "fixture-private-source" not in public and RACE["parallel_value"] not in public


def test_per_target_overrides_merge_without_mutating_shared_inputs(batch_client):
    client, captured, _ = batch_client
    second_race = {**RACE, "control_value": "OTHER_CONTROL", "parallel_value": "OTHER_PARALLEL"}
    result = client.post("/api/scans/batch", json=body(
        options={"inputs": {"race": RACE, "source_text": "shared-private", "sast_language": "python"}},
        inputs_by_asset={"b": {"race": second_race, "source_text": "other-private"}}))
    assert result.status_code == 200, result.text
    assert captured["a"].options.inputs.race.control_value == RACE["control_value"]
    assert captured["b"].options.inputs.race.control_value == "OTHER_CONTROL"
    assert captured["a"].options.inputs.source_text == "shared-private"
    assert captured["b"].options.inputs.source_text == "other-private"
    assert captured["b"].options.inputs.sast_language == "python"
    assert "other-private" not in client.get("/api/scans").text


def test_per_target_null_and_empty_values_can_clear_shared_inputs(batch_client):
    client, captured, _ = batch_client
    result = client.post("/api/scans/batch", json=body(
        options={"inputs": {"race": RACE, "source_text": "shared-private"}},
        inputs_by_asset={"b": {"race": None, "source_text": ""}}))
    assert result.status_code == 200
    assert captured["a"].options.inputs.race and captured["a"].options.inputs.source_text
    assert captured["b"].options.inputs.race is None and captured["b"].options.inputs.source_text == ""


def test_unselected_override_is_rejected_before_any_job_is_created(batch_client):
    client, captured, _ = batch_client
    result = client.post("/api/scans/batch", json=body(inputs_by_asset={"foreign": {"source_text": "private"}}))
    assert result.status_code == 422 and not captured and not main.jobs


def test_malformed_private_override_is_redacted_and_atomic(batch_client):
    client, captured, _ = batch_client
    result = client.post("/api/scans/batch", json=body(inputs_by_asset={
        "b": {"nosql": {**NOSQL, "request": {**NOSQL["request"], "path": "https://private-secret.example/"}}}}))
    assert result.status_code == 422 and not captured and not main.jobs
    assert "private-secret" not in result.text


def test_saved_zap_account_applies_only_to_matching_host_without_blocking_other_modules(batch_client):
    client, captured, owner = batch_client
    main.accounts["account"] = {"id": "account", "owner": owner, "host": "example.org",
                                "headers": {}, "cookie": "session=fixture-private-cookie"}
    result = client.post("/api/scans/batch", json=body(
        modules=["zap-passive", "arjun"], account_id="account"))
    assert result.status_code == 200, result.text
    assert captured["a"].account_id == "account" and captured["a"]._zap_skip_reason == ""
    assert captured["b"].account_id is None and "another hostname" in captured["b"]._zap_skip_reason
    assert "arjun" in captured["b"].modules
    assert "fixture-private-cookie" not in client.get("/api/scans").text


def test_foreign_account_cannot_be_used_in_batch(batch_client):
    client, captured, _ = batch_client
    main.accounts["account"] = {"owner": "other-session", "host": "example.org", "headers": {}, "cookie": "private"}
    result = client.post("/api/scans/batch", json=body(account_id="account"))
    assert result.status_code == 422 and not captured


def test_single_target_zap_identity_can_coexist_with_anonymous_active_modules(batch_client):
    client, captured, owner = batch_client
    main.accounts["account"] = {"owner": owner, "host": "example.org", "headers": {}, "cookie": "private"}
    result = client.post("/api/scans", json={"asset_id": "a", "policy_confirmed": True,
        "active_confirmed": True, "modules": ["zap-passive", "arjun"], "account_id": "account"})
    assert result.status_code == 200, result.text
    assert captured["a"].account_id == "account"
