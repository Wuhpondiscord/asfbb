from unittest.mock import patch

from fastapi.testclient import TestClient
from app import main


def test_clear_scope_deletes_only_session_assets_preserves_findings():
    original_assets, original_jobs = main.assets, main.jobs
    main.assets, main.jobs = {}, {}
    try:
        with TestClient(main.app) as first, TestClient(main.app) as second:
            sid_a = first.get("/api/assets").headers["X-ASFB-Session"]
            sid_b = second.get("/api/assets").headers["X-ASFB-Session"]
            assert sid_a != sid_b
            main.assets["a1"] = {"id": "a1", "owner": sid_a, "name": "https://a.example"}
            main.assets["a2"] = {"id": "a2", "owner": sid_a, "name": "https://b.example"}
            main.assets["b1"] = {"id": "b1", "owner": sid_b, "name": "https://other.example"}
            main.jobs["historical"] = {
                "id": "historical", "owner": sid_a, "asset_id": "a1",
                "status": "completed", "alerts": [{"source": "zap", "name": "example"}],
            }
            result = first.delete("/api/assets")
            assert result.status_code == 200
            assert result.json()["cleared"] == 2
            assert first.get("/api/assets").json()["assets"] == []
            assert len(second.get("/api/assets").json()["assets"]) == 1
            assert main.jobs["historical"]["alerts"][0]["name"] == "example"
            assert main.jobs["historical"]["status"] == "completed"
            assert first.delete("/api/assets").json()["cleared"] == 0
    finally:
        main.assets, main.jobs = original_assets, original_jobs


def test_scope_clear_only_cancels_jobs_referencing_removed_assets():
    original_assets, original_jobs = main.assets, main.jobs
    main.assets, main.jobs = {}, {}
    try:
        with TestClient(main.app) as client:
            sid = client.get("/api/assets").headers["X-ASFB-Session"]
            main.assets["target"] = {"id": "target", "owner": sid, "name": "https://example.org"}
            main.jobs["queued"] = {
                "id": "queued", "owner": sid, "asset_id": "target", "status": "queued"
            }
            main.jobs["other"] = {
                "id": "other", "owner": sid, "asset_id": "unrelated", "status": "queued"
            }
            with patch.object(main, "cancel_owned_jobs", return_value={
                "cancelled_queued": 1, "cancellation_requested_running": 0
            }) as cancel:
                result = client.delete("/api/assets")
            assert result.status_code == 200
            assert result.json()["cancelled_queued"] == 1
            cancel.assert_called_once_with(sid, {"queued"})
            assert "target" not in main.assets
    finally:
        main.assets, main.jobs = original_assets, original_jobs


def test_scope_clear_dashboard_button_is_distinct_from_clear_selection():
    from pathlib import Path
    source = Path("app/index.html").read_text()
    assert 'id="clearScope"' in source
    assert "async function clearScope()" in source
    assert "api('/assets',{method:'DELETE'})" in source
    assert "function clearSelection()" in source
