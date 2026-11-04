"""Install the per-process HTTP guard before loading an existing native runner."""
import runpy
import sys
from pathlib import Path

from . import request_policy as policy


def install():
    pacer = policy.Pacer()
    try:
        import requests
        original = requests.sessions.Session.send
        def send(session, request, **kwargs):
            policy.check(request.url)
            request.headers.update(policy.headers(request.headers))
            pacer.wait()
            kwargs["allow_redirects"] = False
            return original(session, request, **kwargs)
        requests.sessions.Session.send = send
    except ImportError:
        pass
    try:
        import httpx
        original_sync, original_async = httpx.Client.send, httpx.AsyncClient.send
        def sync_send(client, request, **kwargs):
            policy.check(str(request.url))
            request.headers.update(policy.headers(request.headers))
            pacer.wait()
            kwargs["follow_redirects"] = False
            return original_sync(client, request, **kwargs)
        async def async_send(client, request, **kwargs):
            policy.check(str(request.url))
            request.headers.update(policy.headers(request.headers))
            await pacer.await_turn()
            kwargs["follow_redirects"] = False
            return await original_async(client, request, **kwargs)
        httpx.Client.send, httpx.AsyncClient.send = sync_send, async_send
    except ImportError:
        pass
    try:
        import aiohttp
        original_aio = aiohttp.ClientSession._request
        async def aio_request(session, method, url, **kwargs):
            policy.check(str(url))
            kwargs["headers"] = policy.headers(kwargs.get("headers"))
            kwargs["allow_redirects"] = False
            await pacer.await_turn()
            return await original_aio(session, method, url, **kwargs)
        aiohttp.ClientSession._request = aio_request
    except ImportError:
        pass


def main():
    args = sys.argv[1:]
    install()
    sys.path.insert(0, str(Path(__file__).parent))
    if args[0] == "-m":
        sys.argv = args[1:]
        runpy.run_module(args[1], run_name="__main__")
    else:
        sys.argv = args
        runpy.run_path(args[0], run_name="__main__")


if __name__ == "__main__":
    main()
