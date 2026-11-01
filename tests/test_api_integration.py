import asyncio
from unittest.mock import patch
import httpx
from fastapi.testclient import TestClient
from app import main


def test_zap_api_transport_offline():
    def responder(req):
        assert req.url.path == "/JSON/core/view/alerts/"
        assert req.url.params["apikey"] == "test-key"
        return httpx.Response(200, json={"alerts": [{"name": "Test"}]})
    async def check():
        transport = httpx.MockTransport(responder)
        async with httpx.AsyncClient(transport=transport) as client:
            with patch.object(main, "ZAP_KEY", "test-key"):
                result = await main.zap_call(client, "core", "view/alerts")
                assert result["alerts"][0]["name"] == "Test"
    asyncio.run(check())


def test_import_session_and_report_isolation():
    main.assets.clear()
    main.jobs.clear()
    with TestClient(main.app) as client:
        csv = b"Asset name,Type,Max. severity,Bounty\nexample.com,Domain,High,Yes\n"
        result = client.post("/api/import", files={"file": ("scope.csv", csv, "text/csv")})
        assert result.status_code == 200
        assert result.json()["imported"] == 1
        a = client.get("/api/assets")
        assert len(a.json()["assets"]) == 1
        other = TestClient(main.app)
        try:
            assert other.get("/api/assets").json()["assets"] == []
        finally:
            other.close()


def test_policy_rejects_unconfirmed_scans():
    main.assets.clear()
    with TestClient(main.app) as client:
        response = client.post("/api/scans", json={"asset_id": "missing", "policy_confirmed": False})
        assert response.status_code == 422


def test_clear_findings_preserves_jobs():
    main.jobs.clear()
    with TestClient(main.app) as client:
        session = client.get("/api/assets").headers["X-ASFB-Session"]
        main.jobs["test"] = {"id": "test", "owner": session, "status": "completed",
                             "alerts": [{"name": "Mock ZAP alert", "source": "zap"}], "endpoints": []}
        report = client.get("/api/report").json()
        assert report["total_alerts"] == 1
        clear = client.delete("/api/findings")
        assert clear.json()["cleared"] == 1
        assert main.jobs["test"]["alerts"] == []
    main.jobs.clear()
