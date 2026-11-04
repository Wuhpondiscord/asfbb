"""Bounded anonymous GET sampling, with explicit same-origin redirect checks."""
import asyncio
import os
from urllib.parse import urljoin, urlsplit

import httpx

from . import config


class FetchProblem(ValueError):
    pass


def origin(url):
    parts = urlsplit(url)
    if (parts.scheme not in ("http", "https") or not parts.hostname or
            parts.username or parts.password or "\\" in url or
            any(c in url for c in "\r\n\x00")):
        raise ValueError("Invalid sampling URL")
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


async def fetch_page(url, agent, maximum, validate_host, timeout=8, request_timeout=5, truncate=False):
    """At most three GETs, no off-origin hops, one overall deadline and body cap."""
    from .request_policy import current, check, headers as policy_headers, Pacer, SAMPLES
    policy = current()
    pacer = Pacer()
    expected = origin(url)
    cached = (SAMPLES.get() or {}).get(url)
    if cached is not None:
        check(url, policy)
        body, content_type, sampled_url = cached
        if len(body) > maximum and not truncate:
            raise FetchProblem("response exceeds sample byte limit")
        return body[:maximum], content_type, sampled_url
    async def fetch():
        current, seen = url, set()
        async with httpx.AsyncClient(timeout=request_timeout, follow_redirects=False, trust_env=False) as client:
            for hop in range(config.SAMPLE_MAX_REDIRECTS + 1):
                if current in seen:
                    raise FetchProblem("redirect loop; repeated URL not requested")
                seen.add(current)
                check(current, policy)
                await pacer.await_turn(policy)
                validate_host(urlsplit(current).hostname, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
                redirect = None
                async with client.stream("GET", current, headers=policy_headers({"User-Agent": agent}, policy)) as response:
                    headers = getattr(response, "headers", {})
                    if response.status_code in (301, 302, 303, 307, 308):
                        prefix = "HTTP " + str(response.status_code) + "; redirect not followed: "
                        location = headers.get("location")
                        if not location:
                            raise FetchProblem(prefix + "missing Location")
                        if hop >= config.SAMPLE_MAX_REDIRECTS:
                            raise FetchProblem(prefix + "same-origin hop limit reached")
                        try:
                            redirect = urljoin(current, location)
                            if origin(redirect) != expected:
                                raise ValueError("Origin changed")
                            redirect = urlsplit(redirect)._replace(fragment="").geturl()
                        except (TypeError, ValueError):
                            raise FetchProblem(prefix + "destination changes host, scheme or port")
                    elif response.status_code != 200:
                        raise FetchProblem("HTTP " + str(response.status_code))
                    else:
                        data = bytearray()
                        limited = False
                        async for chunk in response.aiter_bytes(chunk_size=16384):
                            if len(data) + len(chunk) > maximum:
                                if not truncate:
                                    raise FetchProblem("response exceeds sample byte limit")
                                limited = True
                                data.extend(chunk[:maximum - len(data)])
                                break
                            data.extend(chunk)
                        result = bytes(data), str(headers.get("content-type", "")).lower(), current
                        cache = SAMPLES.get()
                        if cache is not None and not limited:
                            cache[url] = result
                            cache[current] = result
                        return result
                if redirect is not None:
                    await asyncio.sleep(config.REQUEST_DELAY_MIN)
                    current = redirect
    return await asyncio.wait_for(fetch(), timeout)