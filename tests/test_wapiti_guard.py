import asyncio
from unittest.mock import patch

import httpx
import pytest

from app import wapiti_guard as module


async def no_dns(*args): pass


@pytest.mark.parametrize("url,method", [
    ("https://outside.org/", "GET"),
    ("https://example.org:8443/", "GET"),
    ("http://example.org/", "GET"),
    ("https://example.org/", "POST"),
])
def test_guard_blocks_unapproved_origin_and_methods(url, method):
    async def scenario():
        guard = module.RequestGuard("https://example.org/", 1.5)
        async def original(*args, **kwargs): raise AssertionError("must not send")
        with pytest.raises(httpx.RequestError):
            await guard.wrap(original)(object(), httpx.Request(method, url))
        assert guard.blocked == 1 and guard.requests == 0
    asyncio.run(scenario())


def test_guard_disables_redirects_and_limits_number_of_requests():
    async def scenario():
        guard = module.RequestGuard("https://example.org/", 1.5, limit=1)
        async def original(client, request, **kwargs):
            assert kwargs["follow_redirects"] is False
            assert kwargs["stream"] is True
            return httpx.Response(302, headers={"location": "https://outside.org/"}, content=b"", request=request)
        request = httpx.Request("GET", "https://example.org/")
        with patch.object(module, "validate_public", no_dns):
            response = await guard.wrap(original)(object(), request, follow_redirects=True)
            assert response.status_code == 302
            with pytest.raises(httpx.RequestError):
                await guard.wrap(original)(object(), request)
        assert guard.requests == 1 and guard.limit_reached
    asyncio.run(scenario())


def test_guard_stops_large_stream():
    async def scenario():
        class Stream(httpx.AsyncByteStream):
            async def __aiter__(self):
                yield b"0123456789"
            async def aclose(self): pass
        guard = module.RequestGuard("https://example.org/", 1.5, max_bytes=3)
        async def original(client, request, **kwargs):
            return httpx.Response(200, stream=Stream(), request=request)
        with patch.object(module, "validate_public", no_dns):
            with pytest.raises(httpx.ReadError):
                await guard.wrap(original)(object(), httpx.Request("GET", "https://example.org/"))
        assert guard.response_limited
    asyncio.run(scenario())
