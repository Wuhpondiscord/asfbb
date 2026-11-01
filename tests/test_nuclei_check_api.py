from unittest.mock import patch
from fastapi.testclient import TestClient
from app import main


def test_nuclei_template_check_reports_supported_and_unsupported():
    async def fake(paths):
        if paths[0].endswith("bad.yaml"):
            raise ValueError("Only GET/HEAD templates supported")
        return {paths[0]: "safe"}
    with patch.object(main.nuclei_catalog, "community_files", fake):
        with TestClient(main.app) as client:
            res=client.post("/api/nuclei/check",json={"paths":["http/web/a.yaml","http/web/bad.yaml"]})
    assert res.status_code==200
    assert res.json()["compatible"]==["http/web/a.yaml"]
    assert len(res.json()["rejected"])==1


def test_nuclei_template_check_rejects_disallowed_repo_paths():
    with TestClient(main.app) as client:
        response=client.post("/api/nuclei/check",json={"paths":["http/../../etc/passwd"]})
    assert response.status_code==422


def test_nuclei_template_check_rejects_duplicate_paths():
    with TestClient(main.app) as client:
        response=client.post("/api/nuclei/check",json={"paths":["http/a.yaml","http/a.yaml"]})
    assert response.status_code==422
