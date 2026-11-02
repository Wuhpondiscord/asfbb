import asyncio
from unittest.mock import patch
from app import review, config


def test_dalfox_bounded_cli_flags_are_supported_in_v3():
    cmd=review.command("dalfox","https://example.org/?p=test","example.org")
    for flag in ("--skip-mining", "--scan-timeout", "--max-payloads-per-param",
                 "--rate-limit", "--skip-waf-probe"):
        assert flag in cmd
    assert cmd[cmd.index("--scan-timeout")+1]==str(config.DALFOX_SCAN_TIMEOUT_SECONDS)


def test_dalfox_uses_only_valid_arjun_get_parameters():
    params=[
      {"url":"https://outside.example.org/","name":"bad","method":"GET"},
      {"url":"https://example.org/api/search","name":"q","method":"POST"},
      {"url":"https://example.org/api/search","name":"q","method":"GET"}]
    output=review.choose_dalfox_target("https://example.org/",params,"example.org")
    assert output=="https://example.org/api/search?q=asfb-review"


def test_dalfox_no_parameter_keeps_dom_ast_stage_and_notes_limited_coverage():
    async def fake(args, timeout):
        assert "--skip-ast-analysis" not in args
        assert "--skip-mining" in args
        return [],"completed"
    with patch.object(review,"execute",fake):
        result=asyncio.run(review.review("dalfox","https://example.org/","example.org"))
    assert result["status"]=="completed"
    assert "no query parameters" in result["reason"]


def test_dalfox_nonzero_exit_with_json_report_keeps_findings():
    async def fake(args, timeout):
        from pathlib import Path
        import json
        path=Path(args[args.index("-o")+1])
        path.write_text(json.dumps({"meta":{},"findings":[
          {"data":"https://example.org/?p=a","type":"V","evidence":"safe"}
        ]}))
        return ["[diagnostic] Process exit code: 1"],"failed"
    with patch.object(review,"execute",fake):
        result=asyncio.run(review.review("dalfox","https://example.org/?p=a","example.org"))
    assert result["status"]=="findings"
    assert len(result["findings"])==1
