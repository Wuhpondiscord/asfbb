from fastapi.testclient import TestClient
from app import main

def test_active_batch_of_100_reaches_asset_validation():
    main.assets.clear()
    with TestClient(main.app) as client:
        payload={"asset_ids":[f"missing-{i}" for i in range(100)],
                 "policy_confirmed":True,"active_confirmed":True,
                 "modules":["ffuf"]}
        result=client.post("/api/scans/batch",json=payload)
        assert result.status_code == 409
        assert "scope" in result.json()["detail"].lower()

def test_active_batch_above_100_rejected():
    with TestClient(main.app) as client:
        payload={"asset_ids":[f"missing-{i}" for i in range(101)],
                 "policy_confirmed":True,"active_confirmed":True,
                 "modules":["ffuf"]}
        response=client.post("/api/scans/batch",json=payload)
        assert response.status_code == 422
        assert "100" in response.json()["detail"]
