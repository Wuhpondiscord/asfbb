import asyncio
import json
from pathlib import Path
from unittest.mock import patch

from app import main, review, pipeline
from test_worker_pipeline import run_job


def test_sqlmap_prefers_observed_query_values_and_rejects_other_origins():
    urls = ["https://outside.org/?id=1", "http://example.org/?id=1",
            "https://example.org:8080/?id=1", "https://example.org/search?lang=en&sort=up"]
    chosen = review.choose_sqlmap_target("https://example.org/", urls, [], "example.org")
    assert chosen == urls[-1]
    args = review.command("sqlmap", chosen, "example.org")
    assert args[args.index("-p") + 1] == "lang"
    assert "--ignore-redirects" in args and "--delay=1" in args


def test_sqlmap_consumes_only_valid_same_origin_arjun_get_parameters():
    parameters = [{"url": "https://example.org/", "method": "POST", "name": "post_only"},
                  {"url": "https://example.org:8080/", "method": "GET", "name": "other_port"},
                  {"url": "https://outside.org/", "method": "GET", "name": "other_host"},
                  {"url": "https://example.org/search", "method": "GET", "name": "lang"}]
    assert review.choose_sqlmap_target("https://example.org/", [], parameters, "example.org") == \
        "https://example.org/search?lang=asfb-review"
    assert review.choose_sqlmap_target("https://example.org/", [], [], "example.org") == "https://example.org/"


def test_worker_hands_arjun_parameter_to_sqlmap_without_inventing_a_parameter_name():
    run, job = run_job(["arjun", "sqlmap"])
    seen = []
    async def fake(module, url, host):
        seen.append((module, url))
        return {"source": module, "status": "completed", "output": "", "parameters":
                [{"url": "https://example.com/search", "method": "GET", "name": "lang"}] if module == "arjun" else []}
    with patch.object(main, "public_host"), patch.object(main, "review", fake):
        asyncio.run(run())
    assert seen == [("arjun", "https://example.com"),
                    ("sqlmap", "https://example.com/search?lang=asfb-review")]
    assert job["status"] == "completed"


def test_sqlmap_results_use_a_disposable_per_job_output_directory():
    folders = []
    async def execute(args, timeout):
        root = Path(args[args.index("--output-dir") + 1])
        assert root.is_dir() and "--flush-session" in args
        (root / "fixture").write_text("ephemeral")
        folders.append(root)
        return [], "completed"
    with patch.object(review, "execute", execute):
        for _ in range(2):
            asyncio.run(review.review("sqlmap", "https://example.org/?id=1", "example.org"))
    assert folders[0] != folders[1]
    assert all(not folder.exists() for folder in folders)


def test_dalfox_partial_reason_includes_sanitized_coverage_without_raw_target_errors():
    async def execute(args, timeout):
        Path(args[args.index("-o") + 1]).write_text(json.dumps({
            "meta": {"incomplete": True, "total_requests": 30, "failed_requests": 12,
                     "target_summary": [{"status": "incomplete", "error_code": "SCAN_TIMEOUT",
                                         "error_message": "private-response-body", "response": "private-response-body"}]},
            "findings": []}))
        return [], "completed"
    with patch.object(review, "execute", execute):
        result = asyncio.run(review.review("dalfox", "https://example.org/?lang=en", "example.org"))
    assert result["status"] == "partial"
    assert "failed requests=12" in result["reason"] and "SCAN_TIMEOUT" in result["reason"]
    assert "private-response-body" not in json.dumps(result)
    assert result["output"]


def test_dalfox_outer_timeout_is_not_downgraded_to_a_generic_partial_state():
    async def execute(args, timeout):
        Path(args[args.index("-o") + 1]).write_text(json.dumps({"meta": {"incomplete": True}, "findings": []}))
        return ["[diagnostic] Deadline exceeded"], "timeout"
    with patch.object(review, "execute", execute):
        result = asyncio.run(review.review("dalfox", "https://example.org/", "example.org"))
    assert result["status"] == "timeout" and "Deadline" in result["reason"]


def test_gau_problem_is_not_repeated_in_stage_summary():
    run, job = run_job(["gau"])
    async def gau(*args):
        return {"status": "partial", "endpoints": [], "summary": "GAU: otx timeout; degraded",
                "reason": "otx timeout; no archive hits"}
    with patch.object(main, "public_host"), patch.object(main, "gau", gau):
        asyncio.run(run())
    assert job["stage_details"]["gau"]["summary"].count("otx timeout") == 1
