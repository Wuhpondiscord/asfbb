import asyncio
import json
from pathlib import Path
from unittest.mock import patch
from app import review, config, main
from test_worker_pipeline import run_job

def test_dalfox_structured_json_filters_out_of_scope(tmp_path):
    report=tmp_path/"result.json"
    report.write_text(json.dumps({
        "meta":{"incomplete":False,"failed_requests":0,"total_requests":5},
        "findings":[
            {"type":"A","data":"https://example.org/?q=a","param":"q",
             "severity":"Medium","confidence":"low","evidence":"AST source to sink"},
            {"type":"V","data":"https://other.example.org/?q=b",
             "severity":"High","evidence":"Out of scope"}]
    }))
    found,meta=review.read_dalfox_report(str(report),"example.org","https://example.org/")
    assert len(found)==1
    assert found[0]["tier"]=="A"
    assert found[0]["confidence"]=="Low"
    assert meta["total_requests"]==5

def test_dalfox_report_integrates_on_exit_one():
    async def fake(args, timeout):
        assert args[args.index("-f")+1]=="json"
        assert "-o" in args
        Path(args[args.index("-o")+1]).write_text(json.dumps({
            "meta":{"incomplete":False,"findings_count":1},
            "findings":[{"type":"V","data":"https://example.org/?q=x",
                         "severity":"High","evidence":"Tool signal"}]}))
        return ["[diagnostic] Process exit code: 1"], "failed"
    with patch.object(review,"execute",fake):
        result=asyncio.run(review.review("dalfox","https://example.org/","example.org"))
    assert result["status"]=="findings"
    assert result["exit_code"]==1
    assert len(result["findings"])==1
    assert "Process exit code: 1" not in result["output"]
    assert "Process exit code: 1" not in result["reason"]

def test_dalfox_marks_incomplete_json_as_partial():
    async def fake(args, timeout):
        Path(args[args.index("-o")+1]).write_text(json.dumps({
            "meta":{"incomplete":True},"findings":[]}))
        return ["[diagnostic] Process exit code: 1"], "failed"
    with patch.object(review,"execute",fake):
        result=asyncio.run(review.review("dalfox","https://example.org/","example.org"))
    assert result["status"]=="partial"
    assert "incomplete" in result["reason"]

def test_arjun_picks_existing_parameterized_or_dynamic_url():
    chosen=review.choose_arjun_target("https://example.org/",[
        "https://example.org/", "https://other.org/api/users",
        "https://example.org/a.js", "https://example.org/api/users",
        "https://example.org/search?q=1"],"example.org")
    assert chosen=="https://example.org/search?q=1"

def test_arjun_uses_focused_wordlist_and_rate_config():
    cmd=review.command("arjun","https://example.org/api","example.org")
    assert cmd[cmd.index("-w")+1]==config.ARJUN_WORDLIST
    assert cmd[cmd.index("-c")+1]==str(config.ARJUN_CHUNK_SIZE)
    assert "--rate-limit" in cmd

def test_worker_adds_dalfox_structured_findings():
    execute_job,job=run_job(["dalfox"])
    async def fake(*args):
        return {"status":"findings","source":"dalfox","output":"candidate",
                "findings":[{"source":"dalfox","name":"XSS candidate",
                             "url":"https://example.com/?q=x","risk":"Medium"}]}
    with patch.object(main,"public_host",return_value=None),patch.object(main,"review",fake):
        asyncio.run(execute_job())
    assert job["status"]=="completed"
    assert job["alerts"][0]["source"]=="dalfox"
