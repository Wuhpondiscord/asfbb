"""Request guard installed only inside the dedicated Wapiti subprocess."""
import asyncio
import ipaddress
import os
import socket
import time
from urllib.parse import urlsplit

import httpx


def origin(value):
    p = urlsplit(str(value))
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Invalid HTTP origin")
    return p.scheme, p.hostname, p.port if p.port is not None else (443 if p.scheme == "https" else 80)


async def validate_public(host):
    addresses = await asyncio.to_thread(socket.getaddrinfo, host, None, 0, socket.SOCK_STREAM)
    if not addresses:
        raise ValueError("No DNS addresses")
    if os.environ.get("ALLOW_PRIVATE_TARGETS") != "1":
        if any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
            raise ValueError("Non-public DNS address")


class BoundedStream(httpx.AsyncByteStream):
    def __init__(self, wrapped, limit, guard):
        self.wrapped, self.limit, self.guard = wrapped, limit, guard

    async def __aiter__(self):
        count = 0
        async for chunk in self.wrapped:
            count += len(chunk)
            if count > self.limit:
                self.guard.response_limited = True
                raise httpx.ReadError("ASFB Wapiti response size limit reached")
            yield chunk

    async def aclose(self):
        await self.wrapped.aclose()


class RequestGuard:
    def __init__(self, target, delay, limit=12, max_bytes=1048576):
        self.target_origin = origin(target)
        self.delay, self.limit, self.max_bytes = max(1.0, float(delay)), limit, max_bytes
        self.requests, self.blocked = 0, 0
        self.limit_reached, self.response_limited = False, False
        self.last_started = None
        self.lock = asyncio.Lock()

    def wrap(self, original):
        async def send(client, request, **kwargs):
            try:
                allowed = origin(request.url) == self.target_origin and request.method in ("GET", "HEAD")
            except ValueError:
                allowed = False
            if not allowed:
                self.blocked += 1
                raise httpx.RequestError("ASFB Wapiti request outside the allowed origin/method", request=request)
            async with self.lock:
                if self.requests >= self.limit:
                    self.limit_reached = True
                    raise httpx.RequestError("ASFB Wapiti request budget reached", request=request)
                if self.last_started is not None:
                    await asyncio.sleep(max(0.0, self.delay - (time.monotonic() - self.last_started)))
                try:
                    await validate_public(self.target_origin[1])
                except (OSError, ValueError) as exc:
                    raise httpx.RequestError("ASFB Wapiti DNS validation failed", request=request) from exc
                self.requests += 1
                self.last_started = time.monotonic()
                requested_stream = kwargs.get("stream", False)
                kwargs.update(follow_redirects=False, stream=True)
                response = await original(client, request, **kwargs)
                response.stream = BoundedStream(response.stream, self.max_bytes, self)
                if not requested_stream:
                    try:
                        await response.aread()
                    except BaseException:
                        await response.aclose()
                        raise
                return response
        return send

    def report(self):
        return {"requests": self.requests, "blocked": self.blocked,
                "limit_reached": self.limit_reached, "response_limited": self.response_limited}
