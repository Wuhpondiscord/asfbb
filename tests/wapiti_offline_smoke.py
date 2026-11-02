"""Exercise the real installed Wapiti engine using a mocked HTTP transport."""
import json
import socket
import sys
import tempfile
from pathlib import Path

import httpx

sys.path.insert(0, "/app/app")
import wapiti_guard
import wapiti_runner

calls = []


async def no_dns(*args):
    pass


async def fake_send(client, request, **kwargs):
    calls.append((str(request.url), request.method))
    assert str(request.url).startswith("https://example.invalid/")
    assert request.method in ("GET", "HEAD")
    assert kwargs["follow_redirects"] is False
    return httpx.Response(200, content=b"<html><title>Offline fixture</title></html>",
                          headers={"content-type": "text/html", "set-cookie": "fixture=value; Path=/"},
                          request=request)


wapiti_guard.validate_public = no_dns
httpx.AsyncClient.send = fake_send
socket.gethostbyname = lambda *args: "93.184.216.34"
with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    report, stats = root / "report.json", root / "stats.json"
    sys.argv = ["wapiti_runner.py", "--asfb-stats", str(stats), "--asfb-delay", "1",
                "--asfb-budget", "12", "-u", "https://example.invalid/", "--scope", "url",
                "-m", "csp,http_headers,cookieflags", "--headless", "no", "--tasks", "1",
                "-d", "0", "--max-scan-time", "15", "--max-attack-time", "3",
                "--store-session", str(root / "session"), "--store-config", str(root / "config"),
                "--no-bugreport", "-f", "json", "-o", str(report)]
    wapiti_runner.main()
    result = json.loads(report.read_text())
    assert result["vulnerabilities"], result
    assert any(result["vulnerabilities"].values()), result
    assert calls
    assert json.loads(stats.read_text())["requests"] > 0
print("Wapiti installed-engine offline smoke passed")
