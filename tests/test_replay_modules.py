import asyncio
import json
from pathlib import Path
from unittest.mock import patch
import httpx
import pytest
from pydantic import ValidationError
from fastapi.testclient import TestClient
from app import replay_runner as runner, replay_modules as modules, main, planning
from app.module_inputs import ModuleInputs
from app.replay_inputs import RaceReplay, NoSQLReplay, ReplayRequest, JsonMatch

RACE = {"request":{"path":"/api/test-claim","method":"POST","json_body":{"ticket":"placeholder"}},"field":"ticket","control_value":"CONTROL_TEST_FIXTURE","parallel_value":"RACE_TEST_FIXTURE","success":{"pointer":"/accepted","equals":True},"verification":{"request":{"path":"/api/test-state","query":{"ticket":"placeholder"}},"field":"ticket","pointer":"/accepted_count"}}
NOSQL = {"request":{"path":"/api/test-lookup","method":"POST","json_body":{"reference":"KNOWN_TEST_REFERENCE"}},"field":"reference","success":{"pointer":"/found","equals":True}}

async def noop(*args): pass

def execute(module, config, handler):
    def factory():
        return httpx.AsyncClient(transport=httpx.MockTransport(handler), trust_env=False)
    spec = {"module": module, "config": config, "target": "https://example.org/",
            "host": "example.org", "agent": "Test", "delay": 1, "deadline": 75}
    return asyncio.run(runner.run(spec, factory=factory, check=noop, pause=noop))

@pytest.mark.parametrize("path", ["https://outside.org/", "//outside.org/", "/x?secret=value", "/../x"])
def test_replay_rejects_other_origins_and_embedded_query(path):
    with pytest.raises(ValidationError): ReplayRequest(path=path)

@pytest.mark.parametrize("header", ["Host", "Proxy-Authorization", "Content-Length", "Content-Type", "Connection"])
def test_protected_headers(header):
    with pytest.raises(ValidationError): ReplayRequest(path="/", headers={header:"private"})

def test_operator_and_script_documents_cannot_be_supplied_as_baseline():
    with pytest.raises(ValidationError):
        ReplayRequest(path="/", method="POST", json_body={"x":{"$where":"private"}})

@pytest.mark.parametrize("module", ["race-replay","nosql"])
def test_missing_profiles_skip_without_process(module):
    with patch.object(modules,"execute") as launch:
        result=asyncio.run(modules.run(module,"https://example.org/","example.org","Test",1))
    assert result["status"]=="skipped" and not launch.called

def race_handler(duplicate=False, ack_only=False):
    counters={}
    async def handler(request):
        assert request.url.host=="example.org"
        if request.method=="GET":
            ticket=request.url.params["ticket"]
            return httpx.Response(200,json={"accepted_count":counters.get(ticket,0)})
        ticket=json.loads(request.content)["ticket"]
        old=counters.get(ticket,0)
        if ticket==RACE["parallel_value"]:
            await asyncio.sleep(0.01)
        accepted=old==0
        if duplicate and ticket==RACE["parallel_value"]:
            counters[ticket]=counters.get(ticket,0)+1
        elif accepted:
            counters[ticket]=1
        return httpx.Response(200,json={"accepted":accepted or ack_only and ticket==RACE["parallel_value"]})
    return handler

def test_state_verification_detects_duplicate_effects_and_redacts_values():
    report=execute("race-replay",RACE,race_handler(True))
    assert report["status"]=="completed" and report["requests"]==8
    assert report["observations"]==[{"kind":"race_state_candidate"}]
    assert report["client_overlap"] is True and RACE["parallel_value"] not in json.dumps(report)

def test_idempotent_success_acknowledgements_are_not_a_verified_race():
    report=execute("race-replay",RACE,race_handler(False,True))
    assert report["status"]=="completed" and report["state_overrun"] is False
    assert report["observations"]==[]

def test_without_counter_success_is_only_an_informational_signal():
    config={k:v for k,v in RACE.items() if k!="verification"}
    report=execute("race-replay",config,race_handler(True))
    assert report["requests"]==4
    assert report["observations"]==[{"kind":"race_response_signal"}]

@pytest.mark.parametrize("status", [302,429,500])
def test_stop_on_redirect_rate_limit_or_server_error(status):
    report=execute("nosql",NOSQL,lambda request:httpx.Response(status))
    assert report["status"]=="partial" and report["requests"]==1

@pytest.mark.parametrize("vulnerable", [True,False])
def test_nosql_uses_six_typed_controls(vulnerable):
    calls=[]
    async def handler(request):
        body=json.loads(request.content);value=body["reference"];calls.append(value)
        match=value==NOSQL["request"]["json_body"]["reference"]
        if isinstance(value,dict) and vulnerable:
            match=(value.get("$eq")==NOSQL["request"]["json_body"]["reference"] or "$ne" in value)
        return httpx.Response(200,json={"found":match,"private":"fixture-secret"})
    report=execute("nosql",NOSQL,handler)
    assert report["requests"]==6 and report["status"]=="completed"
    assert bool(report["observations"]) is vulnerable
    assert "fixture-secret" not in json.dumps(report)
    assert all(not isinstance(v,dict) or set(v)<= {"asfb_control","$eq","$ne"} for v in calls)

def test_missing_json_is_not_json_null_success():
    config=json.loads(json.dumps(NOSQL));config["success"]={"pointer":"","equals":None}
    report=execute("nosql",config,lambda request:httpx.Response(200,text="not json"))
    assert report["status"]=="partial" and not report["observations"]

def test_private_profiles_never_appear_in_public_options():
    config=json.loads(json.dumps(NOSQL));config["request"]["headers"]={"Authorization":"fixture-secret"}
    assert "fixture-secret" not in json.dumps(ModuleInputs(nosql=config).public_summary())

def test_validation_errors_do_not_echo_private_inputs():
    with TestClient(main.app) as client:
        response=client.post("/api/scans",json={"asset_id":"none","options":{"inputs":{"nosql":{
            **NOSQL,"request":{**NOSQL["request"],"headers":{"Host":"fixture-secret"}}}}}})
    assert response.status_code==422 and "fixture-secret" not in response.text

def test_native_report_normalization_redacts_raw_diagnostics_and_paths():
    async def launch(args,timeout):
        spec=json.loads(Path(args[-2]).read_text())
        assert Path(args[-2]).stat().st_mode & 0o777 == 0o600
        assert spec["config"]["request"]["headers"]["Authorization"]=="fixture-secret"
        Path(args[-1]).write_text(json.dumps({"profile":"nosql","status":"completed","requests":6,
            "observations":[{"kind":"nosql_operator_candidate","raw":"fixture-secret"}],"extra":"fixture-secret"}))
        return ["fixture-secret"],"completed"
    config=json.loads(json.dumps(NOSQL));config["request"]["headers"]={"Authorization":"fixture-secret"}
    config["request"]["path"]="/fixture-private-path"
    with patch.object(modules,"execute",launch):
        result=asyncio.run(modules.run("nosql","https://example.org/","example.org","Test",1,ModuleInputs(nosql=config)))
    assert result["status"]=="findings"
    assert "fixture-secret" not in json.dumps(result) and "fixture-private-path" not in json.dumps(result)

def test_complete_guided_plan_remains_acyclic_and_manual_order_is_exact():
    order=list(planning.MODULES)
    assert not planning.plan(order,"guided",True)["warnings"]
    assert planning.plan(order,"manual")["effective"]==order
