import asyncio
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from app import main


@pytest.mark.parametrize("count", [100, 101, 1000])
def test_active_batch_reaches_scope_validation_up_to_queue_capacity(count):
    main.assets.clear(); main.queue = asyncio.Queue()
    with TestClient(main.app) as client:
        payload = {"asset_ids": [f"missing-{i}" for i in range(count)],
                   "policy_confirmed": True, "active_confirmed": True, "modules": ["ffuf"]}
        result = client.post("/api/scans/batch", json=payload)
        assert result.status_code == 409
        assert "scope" in result.json()["detail"].lower()


def test_101_authorized_targets_queue_all_requested_modules_and_remain_visible():
    main.assets.clear(); main.jobs.clear(); main.queue = asyncio.Queue()
    async def no_scan(*args): pass
    with TestClient(main.app) as client, patch.object(main, "run_scan_job", no_scan), patch.object(main, "public_host"):
        owner = client.get("/api/health").headers["x-asfb-session"]
        ids = [f"target-{i}" for i in range(101)]
        for identifier in ids:
            main.assets[identifier] = {"id": identifier, "owner": owner,
                "name": "https://" + identifier + ".example.org/", "compatibility": "web"}
        result = client.post("/api/scans/batch", json={"asset_ids": ids, "policy_confirmed": True,
            "active_confirmed": True, "modules": ["ffuf", "arjun"]})
        assert result.status_code == 200, result.text
        assert result.json()["queued"] == 101
        assert all(set(job["modules"]) == {"ffuf", "arjun"} for job in main.jobs.values())
        assert len(client.get("/api/scans").json()) == 101


def test_queue_capacity_and_active_authorization_still_apply():
    main.queue = asyncio.Queue()
    with TestClient(main.app) as client:
        payload = {"asset_ids": [f"missing-{i}" for i in range(101)],
                   "policy_confirmed": True, "modules": ["ffuf"]}
        assert client.post("/api/scans/batch", json=payload).status_code == 422
        payload.update(active_confirmed=True, asset_ids=[f"missing-{i}" for i in range(1001)])
        assert client.post("/api/scans/batch", json=payload).status_code == 422
