import asyncio
import json
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import final_modules as modules, main, template_builder
from app.module_inputs import ModuleInputs, clean_sbom
from test_worker_pipeline import run_job


BOM = json.dumps({"bomFormat": "CycloneDX", "components": [
    {"type": "library", "name": "jquery", "version": "1.6.1", "purl": "pkg:npm/jquery@1.6.1",
     "externalReferences": [{"url": "http://127.0.0.1/secret"}]}]})


@pytest.mark.parametrize("name", ["trufflehog", "depscan", "trivy", "osv-scanner", "kiterunner", "garak"])
def test_missing_required_context_skips_without_process_or_database(name):
    with patch.object(modules, "execute") as execute, patch.object(modules, "prepare_database") as prepare:
        result = asyncio.run(modules.run(name, "https://example.org/", "example.org", "Test", 1.5))
    assert result["status"] == "skipped"
    assert not execute.called and not prepare.called


def test_sbom_is_sanitized_and_external_urls_are_removed():
    result = clean_sbom(BOM)
    assert "externalReferences" not in result and "127.0.0.1" not in result
    assert json.loads(result)["components"][0]["purl"] == "pkg:npm/jquery@1.6.1"


@pytest.mark.parametrize("text", ['{}', '{"bomFormat":"SPDX"}', '{"bomFormat":"CycloneDX","components":[]}'])
def test_incompatible_sboms_are_rejected(text):
    with pytest.raises(ValueError):
        clean_sbom(text)


@pytest.mark.parametrize("path", ["//other.org/api", "https://outside.org/", "/api?token=secret", "/../api"])
def test_llm_endpoint_cannot_change_origin_or_embed_credentials(path):
    with pytest.raises(ValidationError):
        ModuleInputs(llm_path=path)


def test_no_source_or_sbom_content_in_public_options():
    inputs = ModuleInputs(source_text="my-private-source-value", sbom_text=BOM)
    summary = json.dumps(inputs.public_summary())
    assert "my-private-source-value" not in summary
    assert "jquery" not in summary
    assert inputs.public_summary()["sbom_components"] == 1


def test_trufflehog_redacts_secret_and_context_everywhere():
    secret = "super-secret-material-do-not-return"
    rows = [json.dumps({"DetectorName": "MockDetector", "Raw": secret, "RawV2": secret,
                        "ExtraData": {"credential": secret}, "Redacted": secret})]
    async def execute(args, timeout):
        assert "--no-verification" in args and "--no-update" in args
        assert "--force-skip-archives" in args
        root = Path(args[args.index("filesystem") + 1])
        assert (root / "source.txt").read_text() == secret
        return rows, "completed"
    with patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run("trufflehog", "https://example.org/", "example.org", "Test", 1.5,
                                         ModuleInputs(source_text=secret)))
    assert result["status"] == "findings"
    assert secret not in json.dumps(result)
    assert len(result["alerts"]) == 1


@pytest.mark.parametrize("name", ["depscan", "trivy"])
def test_database_failure_is_unavailable_not_clean(name):
    async def prepare(module): return False, "Database download timeout"
    with patch.object(modules, "prepare_database", prepare), patch.object(modules, "execute") as execute:
        result = asyncio.run(modules.run(name, "https://example.org/", "example.org", "Test", 1.5,
                                         ModuleInputs(sbom_text=BOM)))
    assert result["status"] == "unavailable"
    assert not execute.called


def test_amass_inventory_filters_unrelated_domains_without_expanding_scope():
    async def execute(args, timeout):
        assert "-passive" in args and "-active" not in args
        Path(args[args.index("-o") + 1]).write_text("a.example.org\nexample.org.evil.org\nexample.org\n")
        return [], "completed"
    with patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run("amass", "https://example.org/", "example.org", "Test", 1.5))
    assert result["hosts"] == ["a.example.org", "example.org"]
    assert result["endpoints"] == []


def test_kiterunner_uses_only_small_get_dictionary_and_parses_upstream_hit_shape():
    async def execute(args, timeout):
        assert args[args.index("--max-redirects") + 1] == "0"
        assert args[args.index("--force-method") + 1] == "GET"
        assert args[args.index("--delay") + 1] == "1.5s"
        assert "127.0.0.1" not in " ".join(args)
        assert len(Path(args[args.index("-w") + 1]).read_text().splitlines()) == 8
        return [json.dumps({"method": "GET", "target": "https://example.org", "path": "/api/v1", "responses": []}),
                json.dumps({"method": "GET", "target": "https://outside.org", "path": "/api"})], "completed"
    with patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run("kiterunner", "https://example.org/", "example.org", "Test", 1.5,
                                         ModuleInputs(api_target=True)))
    assert result["endpoints"] == ["https://example.org/api/v1"]


@pytest.mark.parametrize("name,payload", [
    ("trivy", {"SchemaVersion": 2, "Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "CVE-TEST", "PkgName": "package", "Severity": "HIGH"}]}]}),
    ("osv-scanner", {"results": [{"packages": [{"package": {"name": "package", "version": "1"},
                                              "vulnerabilities": [{"id": "GHSA-test"}]}]}]}),
    ("depscan", {"bomFormat": "CycloneDX", "vulnerabilities": [{"id": "CVE-TEST", "ratings": [{"severity": "high"}]}]}),
])
def test_dependency_json_is_normalized_and_raw_artifacts_not_returned(name, payload):
    async def prepare(*args): return True, ""
    async def execute(args, timeout):
        if name == "depscan":
            directory = Path(args[args.index("--reports-dir") + 1])
            directory.mkdir()
            (directory / "depscan-universal.vdr.json").write_text(json.dumps(payload))
        else:
            Path(args[args.index("--output") + 1]).write_text(json.dumps(payload))
        return [], "completed"
    with patch.object(modules, "prepare_database", prepare), patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run(name, "https://example.org/", "example.org", "Test", 1.5,
                                         ModuleInputs(sbom_text=BOM)))
    assert result["status"] == "findings"
    assert len(result["alerts"]) == 1
    assert "externalReferences" not in json.dumps(result)


def test_invalid_report_cannot_claim_clean_scan():
    async def execute(args, timeout):
        Path(args[args.index("--output") + 1]).write_text("{}")
        return [], "completed"
    with patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run("osv-scanner", "https://example.org/", "example.org", "Test", 1.5,
                                         ModuleInputs(sbom_text=BOM)))
    assert result["status"] == "failed"


def test_worker_keeps_amass_names_in_inventory_only():
    run, job = run_job(["amass", "httpx"])
    async def module(*args):
        return {"status": "completed", "alerts": [], "hosts": ["a.example.com"], "output": "inventory"}
    async def probe(urls, *args):
        assert all("a.example.com" not in url for url in urls)
        return {"status": "completed", "probes": []}
    with patch.object(main, "public_host"), patch.object(main, "run_web_module", module), \
         patch.object(main, "probe", probe):
        asyncio.run(run())
    assert job["discovered_hosts"] == ["a.example.com"]
    assert job["status"] == "completed"


def test_artifact_input_is_not_returned_in_job_status_and_does_not_reuse_stale_job():
    main.assets.clear()
    main.jobs.clear()
    main.queue = asyncio.Queue()
    async def no_scan(*args):
        return None
    with TestClient(main.app) as client, patch.object(main, "public_host"), patch.object(main, "run_scan_job", no_scan):
        owner = client.get("/api/health").headers["x-asfb-session"]
        main.assets["a"] = {"id": "a", "owner": owner, "name": "https://example.org/", "compatibility": "web"}
        body = {"asset_id": "a", "policy_confirmed": True, "active_confirmed": True,
                "modules": ["trufflehog"], "options": {"inputs": {"source_text": "secret-first"}}}
        response = client.post("/api/scans", json=body)
        assert response.status_code == 200
        first = response.json()["id"]
        body["options"]["inputs"]["source_text"] = "secret-other"
        second = client.post("/api/scans", json=body).json()["id"]
        assert first != second
        assert "secret-first" not in json.dumps(main.jobs)
        assert "secret-other" not in json.dumps(main.jobs)


def test_keyless_builder_cannot_create_payloads_or_external_hosts():
    from app.nuclei_catalog import validate_template
    draft = template_builder.build_draft("Test observation", "/status", "healthy")
    validate_template(draft)
    assert "{{BaseURL}}/status" in draft
    for path in ("//outside.org", "/../secret", "/x?cmd=1"):
        with pytest.raises(ValueError):
            template_builder.build_draft("Test observation", path, "ok")


def test_optional_gemini_without_credentials_is_unavailable_not_required(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_MODEL", raising=False)
    with pytest.raises(RuntimeError):
        asyncio.run(template_builder.gemini_draft("Observation"))


def test_draft_endpoint_validates_but_never_launches_scan():
    async def validate(content):
        return content
    with TestClient(main.app) as client, patch.object(template_builder, "validate_draft", validate):
        response = client.post("/api/nuclei/draft", json={"name": "Observation", "path": "/", "word": "hello"})
    assert response.status_code == 200
    assert response.json()["executed"] is False
