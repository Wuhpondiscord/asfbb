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


# Verification responses are mocked. No test authenticates a real credential.
def run_secret_fixture(rows, reply=None, enabled=True):
    calls = []
    paths = []
    async def execute(args, timeout):
        calls.append((args, timeout))
        assert "--no-update" in args and "--force-skip-archives" in args
        path = Path(args[args.index("filesystem") + 1])
        if "--no-verification" in args:
            return rows, "completed"
        assert "--include-detectors" in args and "--allow-verification-overlap" in args
        assert "--no-verification-cache" in args
        assert args[args.index("--results") + 1] == "verified,unverified,unknown"
        assert timeout <= 12 and (path.stat().st_mode & 0o777) == 0o600
        assert "fixture-private" not in " ".join(args)
        paths.append(path)
        return reply(args, path) if reply else ([], "completed")
    with patch.object(modules, "execute", execute):
        result = asyncio.run(modules.run("trufflehog", "https://example.org/", "example.org", "Test", 1.5,
                            ModuleInputs(source_text="fixture-private-source", trufflehog_verify=enabled)))
    assert all(not path.exists() for path in paths)
    assert "fixture-private" not in json.dumps(result)
    return result, calls


def native_secret(name="Github", raw="fixture-private-key", **fields):
    return json.dumps({"DetectorName": name, "Raw": raw, "Redacted": raw,
                       "ExtraData": {"account": "fixture-private-identity"}, **fields})


@pytest.mark.parametrize("fields,status,expected", [
    ({"Verified": True}, "completed", "verified"),
    ({"Verified": False}, "completed", "unverified"),
    ({"Verified": False, "VerificationError": "fixture-private-provider-error"}, "completed", "unknown"),
    ({"Verified": False}, "timeout", "unknown"),
    ({"Verified": True}, "timeout", "verified"),
    ({}, "completed", "unknown"),
])
def test_trufflehog_verification_labels_and_redaction(fields, status, expected):
    def reply(args, path):
        assert path.read_text() == "github_token = fixture-private-key"
        assert args[args.index("--include-detectors") + 1] == "Github"
        return [native_secret(**fields)], status
    result, calls = run_secret_fixture([native_secret()], reply)
    finding = result["alerts"][0]
    assert len(calls) == 2 and result["verification"]["attempted"] == 1
    assert finding["verification_status"] == expected
    assert finding["confidence"] == ("High" if expected == "verified" else "Low")
    assert finding["risk"] == ("High" if expected == "verified" else "Medium")
    assert result["status"] == ("partial" if expected == "unknown" else "findings")


def test_detection_default_never_contacts_a_provider_even_if_native_claims_verified():
    result, calls = run_secret_fixture([native_secret(Verified=True)], enabled=False)
    assert len(calls) == 1
    assert result["alerts"][0]["verification_status"] == "not_attempted"
    assert result["verification"]["enabled"] is False


def test_unsupported_detectors_and_known_aws_canaries_stay_detection_only():
    aws = native_secret("AWS", raw="AKIAABCDEFGHIJKLMNOP",
                        RawV2="AKIAABCDEFGHIJKLMNOP:" + "a" * 40,
                        ExtraData={"is_canary": "true"})
    result, calls = run_secret_fixture([native_secret("PrivateKey"), native_secret("Postgres"), aws])
    assert len(calls) == 1 and result["verification"]["attempted"] == 0
    assert result["verification"]["not_attempted"] == 3


def test_missing_or_mismatched_verifier_output_is_inconclusive():
    result, _ = run_secret_fixture([native_secret()], lambda *args: (
        [native_secret(raw="fixture-private-other-key", Verified=True)], "completed"))
    assert result["verification"]["unknown"] == 1
    assert result["verification"]["verified"] == 0


def test_verifier_exception_keeps_detection_without_leaking_exception():
    def reply(*args):
        raise RuntimeError("fixture-private-native-error")
    result, _ = run_secret_fixture([native_secret()], reply)
    assert result["status"] == "partial" and len(result["alerts"]) == 1
    assert result["verification"]["unknown"] == 1


def test_verification_is_deduplicated_and_capped_without_hiding_remaining_detections():
    rows = [native_secret(raw="fixture-private-" + str(i)) for i in range(12)]
    result, calls = run_secret_fixture(rows + rows[:1])
    assert len(calls) == 11
    assert result["verification"]["attempted"] == 10
    assert result["verification"]["unknown"] == 10
    assert result["verification"]["not_attempted"] == 2
    assert result["verification"]["budget_limited"] == 2
    assert sum(item["candidate_count"] for item in result["alerts"]) == 12


def test_verification_budget_does_not_start_more_processes_after_expiry():
    # Patch only the module-local clock object, leaving asyncio's clock intact.
    from types import SimpleNamespace
    times = iter([0, 0, 31])
    async def execute(args, timeout):
        return [native_secret()], "completed"
    with patch.object(modules, "time", SimpleNamespace(monotonic=lambda: next(times))), \
         patch.object(modules, "execute", execute):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            states, count = asyncio.run(modules.verify_trufflehog(
                [native_secret(), native_secret(raw="fixture-private-second")], Path(tmp)))
    assert count == 1
    assert list(states.values()) == ["unknown", "not_attempted"]


@pytest.mark.parametrize("name", ["AWS", "Github", "Slack", "HuggingFace", "OpenAI"])
def test_provider_detector_is_explicit_and_never_uses_supplied_custom_endpoints(name):
    key = "AKIAABCDEFGHIJKLMNOP"
    pair = key + ":" + "a" * 40
    row = native_secret(name, raw=key if name == "AWS" else "fixture-private-key",
                        **({"RawV2": pair} if name == "AWS" else {}))
    def reply(args, path):
        assert args[args.index("--include-detectors") + 1] == name
        assert "--verifier" not in args and "--config" not in args
        if name == "AWS":
            assert path.read_text() == pair.replace(":", "\n")
        return [], "completed"
    result, calls = run_secret_fixture([row], reply)
    assert len(calls) == 2 and result["verification"]["unknown"] == 1


def test_verification_flag_is_visible_but_source_stays_private_in_job_options():
    summary = ModuleInputs(source_text="fixture-private-source", trufflehog_verify=True).public_summary()
    assert summary["trufflehog_verify"] is True
    assert "fixture-private" not in json.dumps(summary)


def test_multiple_candidates_of_one_detector_keep_separate_verification_results():
    rows = [native_secret(raw="fixture-private-good"), native_secret(raw="fixture-private-bad")]
    def reply(args, path):
        raw = path.read_text().split(" = ", 1)[1]
        return [native_secret(raw=raw, Verified=raw.endswith("good"))], "completed"
    result, _ = run_secret_fixture(rows, reply)
    assert result["verification"]["verified"] == result["verification"]["unverified"] == 1
    assert {a["verification_status"] for a in result["alerts"]} == {"verified", "unverified"}
