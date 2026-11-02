from app import config, main
from fastapi.testclient import TestClient
import pytest

def test_config_defaults_match_models():
    opts=main.PipelineOptions()
    assert opts.endpoint_limit==config.ENDPOINT_LIMIT_DEFAULT
    assert opts.gau_mode=="balanced"
    assert opts.httpx_limit==config.HTTPX_LIMIT_DEFAULT
    assert opts.katana_depth==config.KATANA_DEPTH_DEFAULT
    assert opts.zap_endpoint_limit==config.ZAP_ENDPOINT_LIMIT_DEFAULT
    assert opts.request_budget==config.ZAP_REQUEST_BUDGET_DEFAULT

def test_hundred_active_targets_reach_scope_check():
    with TestClient(main.app) as client:
        payload={"asset_ids":[f"expired-{i}" for i in range(config.ACTIVE_BATCH_LIMIT)],
                 "modules":["ffuf"],"active_confirmed":True,"policy_confirmed":True}
        response=client.post("/api/scans/batch",json=payload)
        assert response.status_code == 409

def test_over_hundred_active_targets_rejected():
    with TestClient(main.app) as client:
        payload={"asset_ids":[f"expired-{i}" for i in range(config.ACTIVE_BATCH_LIMIT+1)],
                 "modules":["ffuf"],"active_confirmed":True,"policy_confirmed":True}
        response=client.post("/api/scans/batch",json=payload)
        assert response.status_code == 422
        assert "100" in response.json()["detail"]
