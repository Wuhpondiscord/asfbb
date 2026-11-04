"""Installed transport libraries under --network none; no target scans."""
import asyncio
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app import policy_entry, request_policy as policy

p = {"target": "https://example.org/app/", "path": "/app/", "exclusions": ["/app/private/"],
     "headers": {"X-HackerOne-Research": "fixture"}, "agent": "Required-Fixture", "delay": 1}
token = policy.CURRENT.set(p)
kind = sys.argv[1]
if kind == "requests":
    import requests
    seen = []
    def send(session, request, **kwargs):
        seen.append(str(request.url))
        assert request.headers["X-HackerOne-Research"] == "fixture"
        assert request.headers["User-Agent"] == "Required-Fixture"
        assert kwargs["allow_redirects"] is False
        return requests.Response()
    with patch.object(requests.Session, "send", send):
        policy_entry.install()
        requests.Session().send(requests.Request("GET", "https://example.org/app/page").prepare())
        try:
            requests.Session().send(requests.Request("GET", "https://example.org/app/private/page").prepare())
        except policy.PolicyBlocked:
            pass
        else:
            raise AssertionError("Native requests policy allowed an excluded path")
    assert len(seen) == 1
elif kind == "httpx":
    import httpx
    from app.wapiti_guard import RequestGuard
    seen = []
    def transport(request):
        seen.append(str(request.url))
        assert request.headers["X-HackerOne-Research"] == "fixture"
        assert request.headers["User-Agent"] == "Required-Fixture"
        return httpx.Response(200, json={"ok": True})
    async def run():
        policy_entry.install()
        guard = RequestGuard("https://example.org/app/", 1)
        async def no_dns(*args): pass
        with patch("app.wapiti_guard.validate_public", no_dns), patch.object(
                httpx.AsyncClient, "send", guard.wrap(httpx.AsyncClient.send)):
            async with httpx.AsyncClient(transport=httpx.MockTransport(transport)) as client:
                assert (await client.get("https://example.org/app/page")).status_code == 200
                try:
                    await client.get("https://example.org/app/private/page")
                except policy.PolicyBlocked:
                    pass
                else:
                    raise AssertionError("Native Wapiti transport allowed an excluded path")
        assert len(seen) == 1
    asyncio.run(run())
elif kind == "aiohttp":
    import aiohttp
    seen = []
    async def transport(session, method, url, **kwargs):
        seen.append(url)
        assert kwargs["headers"]["X-HackerOne-Research"] == "fixture"
        assert kwargs["headers"]["User-Agent"] == "Required-Fixture"
        assert kwargs["allow_redirects"] is False
        return "fixture"
    async def run():
        with patch.object(aiohttp.ClientSession, "_request", transport):
            policy_entry.install()
            async with aiohttp.ClientSession() as client:
                assert await client._request("GET", "https://example.org/app/page") == "fixture"
                try:
                    await client._request("GET", "https://example.org/app/private/page")
                except policy.PolicyBlocked:
                    pass
                else:
                    raise AssertionError("Native aiohttp policy allowed an excluded path")
        assert len(seen) == 1
    asyncio.run(run())
else:
    raise AssertionError("Unknown installed-library profile")
policy.CURRENT.reset(token)
print("Installed " + kind + " policy headers/path guard passed; network disabled")
