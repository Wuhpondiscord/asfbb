import asyncio
import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from app import sampling, client_modules, web_modules


class Response:
    def __init__(self, status, body=b"", headers=None):
        self.status_code, self.body, self.headers = status, body, headers or {}
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    async def aiter_bytes(self, **kwargs):
        yield self.body


class Client:
    def __init__(self, routes):
        self.routes, self.calls = routes, []
    async def __aenter__(self): return self
    async def __aexit__(self, *args): pass
    def stream(self, method, url, **kwargs):
        assert method == "GET"
        self.calls.append(url)
        return self.routes[url]


async def no_sleep(*args):
    pass


@pytest.mark.parametrize("destination", [
    "https://other.org/", "http://example.org/", "https://example.org:8443/",
    "https://user:pass@example.org/", "//other.org/"
])
def test_sampling_never_requests_an_off_origin_redirect(destination):
    client = Client({"https://example.org/": Response(301, headers={"location": destination})})
    validator = Mock()
    with patch.object(sampling.httpx, "AsyncClient", return_value=client) as factory:
        with pytest.raises(sampling.FetchProblem, match="not followed"):
            asyncio.run(sampling.fetch_page("https://example.org/", "Test", 100, validator))
    assert client.calls == ["https://example.org/"]
    assert validator.call_count == 1
    assert factory.call_args.kwargs["follow_redirects"] is False


def test_sampling_revalidates_dns_and_obeys_hop_limit():
    routes = {
        "https://example.org/": Response(302, headers={"location": "/one"}),
        "https://example.org/one": Response(302, headers={"location": "/two"}),
        "https://example.org/two": Response(302, headers={"location": "/three"})}
    client, validator = Client(routes), Mock()
    with patch.object(sampling.httpx, "AsyncClient", return_value=client), \
         patch.object(sampling.asyncio, "sleep", no_sleep):
        with pytest.raises(sampling.FetchProblem, match="hop limit"):
            asyncio.run(sampling.fetch_page("https://example.org/", "Test", 100, validator))
    assert len(client.calls) == 3 and validator.call_count == 3
    assert "https://example.org/three" not in client.calls


def test_redirect_loop_is_stopped_without_repeating_a_request():
    client = Client({"https://example.org/": Response(308, headers={"location": "/"})})
    with patch.object(sampling.httpx, "AsyncClient", return_value=client), \
         patch.object(sampling.asyncio, "sleep", no_sleep):
        with pytest.raises(sampling.FetchProblem, match="redirect loop"):
            asyncio.run(sampling.fetch_page("https://example.org/", "Test", 100, Mock()))
    assert len(client.calls) == 1


def test_dns_failure_on_redirect_prevents_the_second_request():
    client = Client({"https://example.org/": Response(301, headers={"location": "/app"})})
    validator = Mock(side_effect=[None, ValueError("Non-public address")])
    with patch.object(sampling.httpx, "AsyncClient", return_value=client), \
         patch.object(sampling.asyncio, "sleep", no_sleep):
        with pytest.raises(ValueError, match="Non-public"):
            asyncio.run(sampling.fetch_page("https://example.org/", "Test", 100, validator))
    assert len(client.calls) == 1 and validator.call_count == 2


def test_final_body_limit_is_preserved_after_a_redirect():
    routes = {"https://example.org/": Response(301, headers={"location": "/app"}),
              "https://example.org/app": Response(200, b"0123456789")}
    with patch.object(sampling.httpx, "AsyncClient", return_value=Client(routes)), \
         patch.object(sampling.asyncio, "sleep", no_sleep):
        with pytest.raises(sampling.FetchProblem, match="byte limit"):
            asyncio.run(sampling.fetch_page("https://example.org/", "Test", 4, Mock()))
        body, _, final = asyncio.run(sampling.fetch_page(
            "https://example.org/", "Test", 4, Mock(), truncate=True))
    assert body == b"0123" and final == "https://example.org/app"


def test_wordpress_uses_the_final_same_origin_installation_url():
    routes = {"https://example.org/": Response(301, headers={"location": "/blog/"}),
              "https://example.org/blog/": Response(200, b'<meta name="generator" content="WordPress 6">')}
    with patch.object(sampling.httpx, "AsyncClient", return_value=Client(routes)), \
         patch.object(web_modules, "public_host"), patch.object(sampling.asyncio, "sleep", no_sleep):
        target, evidence = asyncio.run(web_modules.wordpress_preflight(
            "https://example.org/", "example.org", "Test"))
    assert target == "https://example.org/blog/"
    assert "same-origin redirected" in evidence


def test_retire_relative_script_paths_resolve_against_the_final_page():
    routes = {
        "https://example.org/": Response(301, headers={"location": "/app/"}),
        "https://example.org/app/": Response(200, b'<html><script src="scripts/app.js"></script></html>',
                                           {"content-type": "text/html"}),
        "https://example.org/app/scripts/app.js": Response(200, b"/* fixture */",
                                                          {"content-type": "text/javascript"})}
    client = Client(routes)
    async def execute(args, timeout):
        files = list(Path(args[args.index("--path") + 1]).rglob("*.js"))
        assert len(files) == 1
        Path(args[args.index("--outputpath") + 1]).write_text(json.dumps({"data": [], "errors": []}))
        return [], "completed"
    with patch.object(sampling.httpx, "AsyncClient", return_value=client), \
         patch.object(client_modules, "public_host"), patch.object(client_modules, "execute", execute), \
         patch.object(sampling.asyncio, "sleep", no_sleep):
        result = asyncio.run(client_modules.retirejs(
            "https://example.org/", "example.org", "Test", 1.5, []))
    assert result["status"] == "completed" and result["sampled_files"] == 1
    assert client.calls == list(routes)


def test_skipped_wordpress_result_keeps_its_module_source_label():
    async def preflight(*args): return None, "No WordPress evidence"
    with patch.object(web_modules, "wordpress_preflight", preflight):
        result = asyncio.run(web_modules.run_web_module("wpscan", "https://example.org/", "example.org", "Test"))
    assert result["source"] == "wpscan" and result["status"] == "skipped"
