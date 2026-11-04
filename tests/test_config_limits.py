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

def test_queue_capacity_replaces_the_separate_active_batch_cap():
    assert config.QUEUE_CAPACITY == 1000
    assert not hasattr(config, "ACTIVE_BATCH_LIMIT")


def test_passive_wait_budget_defaults_to_two_minutes_and_is_bounded():
    assert main.PipelineOptions().zap_wait_seconds == 120
    assert main.PipelineOptions(zap_wait_seconds=300).zap_wait_seconds == 300
    for value in (0, 14, 301):
        with pytest.raises(ValueError):
            main.PipelineOptions(zap_wait_seconds=value)