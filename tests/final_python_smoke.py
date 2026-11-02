"""Installed lightweight Python integrations; mocked HTTP only."""
import asyncio
import importlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, "/app/app")
mode = sys.argv[1]
if mode == "garak":
    import requests
    import garak_runner
    from garak.probes.av_spam_scanning import EICAR_SIGNATURE
    calls = []
    def post(url, **kwargs):
        calls.append(url)
        response = requests.Response()
        response.status_code = 200
        response._content = json.dumps({"response": EICAR_SIGNATURE}).encode()
        return response
    with patch.object(requests, "post", post):
        result = garak_runner.profile({"url": "https://example.invalid/llm",
                                       "prompt_field": "prompt", "response_field": "response", "delay": 1})
    assert len(calls) == 2
    assert all(test["matched"] for test in result["tests"]), result
    print("garak installed REST and detector smoke passed")
elif mode == "nettacker":
    import nettacker_runner
    async def no_dns(*args): pass
    class Content:
        async def read(self, count): return b"fixture"
    class Response:
        status = 200
        reason = "OK"
        url = "https://example.invalid/"
        headers = {}
        content = Content()
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
    class Session:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        def get(self, **kwargs):
            assert kwargs["allow_redirects"] is False
            assert kwargs["url"] == "https://example.invalid/"
            return Response()
    with patch.object(nettacker_runner, "validate_public", no_dns), \
         patch.object(nettacker_runner.engine.aiohttp, "ClientSession", Session):
        result = asyncio.run(nettacker_runner.inspect("https://example.invalid/", "Offline-test"))
    assert result["status_code"] == 200 and result["condition_matched"], result
    print("Nettacker installed HTTP engine/module-condition smoke passed")
else:
    raise ValueError("unknown mode")
