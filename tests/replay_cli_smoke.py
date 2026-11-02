"""Exercise private replay CLI in the network-disabled CI container."""
import asyncio
import json
import runpy
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch
import httpx
sys.path.insert(0,"/app")
OriginalClient=httpx.AsyncClient

async def handler(request):
    value=json.loads(request.content)["reference"]
    accepted=value=="KNOWN_TEST_REFERENCE"
    if isinstance(value,dict):
        accepted=value.get("$eq")=="KNOWN_TEST_REFERENCE" or "$ne" in value
    return httpx.Response(200,json={"found":accepted,"secret":"fixture-private-response"})

def factory(**kwargs):
    return OriginalClient(transport=httpx.MockTransport(handler),trust_env=False)

with tempfile.TemporaryDirectory() as tmp:
    source,output=Path(tmp)/"private.json",Path(tmp)/"report.json"
    source.write_text(json.dumps({"module":"nosql","target":"https://example.org/","host":"example.org",
        "agent":"Test","delay":1,"deadline":75,"config":{"request":{"path":"/private-test-path","method":"POST",
        "headers":{"Authorization":"fixture-private-credential"},"json_body":{"reference":"KNOWN_TEST_REFERENCE"}},
        "field":"reference","success":{"pointer":"/found","equals":True}}}))
    with patch("httpx.AsyncClient",factory),patch("app.scope.public_host",return_value={"93.184.216.34"}), \
         patch.object(sys,"argv",["app.replay_runner",str(source),str(output)]):
        runpy.run_module("app.replay_runner",run_name="__main__")
    result=json.loads(output.read_text())
    assert result["status"]=="completed" and result["requests"]==6,result
    assert result["observations"]==[{"kind":"nosql_operator_candidate"}],result
    assert "fixture-private" not in json.dumps(result)
print("Private replay CLI offline smoke passed; no network")
