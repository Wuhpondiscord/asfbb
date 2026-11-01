from app import config, nuclei_catalog, main
from fastapi.testclient import TestClient


def test_nuclei_optional_profiles_are_opt_in():
    names = nuclei_catalog.builtins()
    for name in ("bounty-ultimate-lite", "bounty-ultimate-medium", "bounty-ultimate-large"):
        assert name in names
        assert name not in config.NUCLEI_DEFAULT_IDS
    assert set(config.NUCLEI_DEFAULT_IDS).issubset(names)


def test_nuclei_template_profiles_available_in_settings_metadata():
    with TestClient(main.app) as client:
        info = client.get("/api/nuclei/defaults")
        assert info.status_code == 200
        assert len(info.json()["templates"]) >= 7
        assert set(info.json()["default_ids"]) == set(config.NUCLEI_DEFAULT_IDS)
        assert info.json()["max_custom"] == config.NUCLEI_CUSTOM_MAX


def test_nuclei_request_default_settings_do_not_enable_optional_profiles():
    opts = main.PipelineOptions()
    assert opts.nuclei.default_ids == list(config.NUCLEI_DEFAULT_IDS)
    assert opts.nuclei.community_paths == []
    assert opts.nuclei.custom_templates == []
