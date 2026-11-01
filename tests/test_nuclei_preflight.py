import asyncio
from unittest.mock import patch

from fastapi.testclient import TestClient
from app import config, main, nuclei_catalog, pipeline


def test_bundled_request_count_matches_optional_profile():
    count=nuclei_catalog.estimate_requests(nuclei_catalog.bundled_content("bounty-ultimate-large"))
    assert count==20


def test_preflight_accepts_multiple_profiles_and_estimates_traffic():
    with TestClient(main.app) as client:
        response=client.post("/api/nuclei/validate",json={"default_ids":["bounty-ultimate-lite","bounty-ultimate-medium"],"community_paths":[],"custom_templates":[]})
    assert response.status_code==200
    assert response.json()["valid"] is True
    assert response.json()["per_target_requests"]==18


def test_preflight_rejects_excessive_template_volume_without_target_requests():
    with patch.object(config, "NUCLEI_MAX_REQUEST_BUDGET", 5):
        with TestClient(main.app) as client:
            response=client.post("/api/nuclei/validate",json={"default_ids":["bounty-ultimate-lite"],"community_paths":[],"custom_templates":[]})
        assert response.status_code==200
        assert response.json()["valid"] is False
        assert response.json()["max_targets_within_budget"]==0


def test_nuclei_does_not_exceed_budget_even_for_one_target():
    async def unexpected(*args,**kwargs):
        raise AssertionError("The scanner must not execute over-budget selections")
    with patch.object(config,"NUCLEI_MAX_REQUEST_BUDGET",1),patch.object(pipeline,"execute",unexpected):
        result=asyncio.run(pipeline.nuclei("https://example.org","example.org","ASFB"))
    assert result["status"]=="failed"
    assert result["targets_checked"]==0
    assert "Reduce template selections" in result["reason"]


def test_preflight_rejects_duplicate_bundled_templates():
    with TestClient(main.app) as client:
        response=client.post("/api/nuclei/validate",json={"default_ids":["hsts-missing","hsts-missing"],"community_paths":[],"custom_templates":[]})
    assert response.status_code==422
