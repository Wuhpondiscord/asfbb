"""Installed native engines, mocked transports only; executed with network disabled."""
import contextlib
import io
import json
import subprocess
import tempfile
import sys
from pathlib import Path
from unittest.mock import patch

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import arjun_runner, dalfox_runner


for code, status, reason in [(400, "partial", "http_unavailable"), (429, "partial", "http_unavailable"),
                              (503, "partial", "http_unavailable"), (302, "completed", "redirect_not_followed")]:
    calls = []
    def transport(session, method, url, **kwargs):
        calls.append(url)
        assert url == "https://example.org/search?id=fixture-private"
        assert kwargs["verify"] is True and kwargs["allow_redirects"] is False
        assert kwargs["headers"]["User-Agent"] == "Fixture-Researcher"
        assert session.trust_env is False
        response = requests.Response()
        response.status_code = 200 if len(calls) == 1 else code
        response.headers["Content-Type"] = "text/html"
        response.url = url
        response._content = b"<html>fixture page</html>"
        response._content_consumed = True
        return response
    with tempfile.TemporaryDirectory() as directory:
        report = Path(directory) / "guard.json"
        with patch.object(arjun_runner, "public_host"), patch.object(requests.sessions.Session, "request", transport):
            result = arjun_runner.run(["-u", "https://example.org/search?id=fixture-private",
                "-w", "small", "-t", "1", "-c", "150", "--rate-limit", "1000",
                "--disable-redirects", "--headers", "User-Agent: Fixture-Researcher", "--asfb-report", str(report)])
        data = json.loads(report.read_text())
        assert result == 0 and len(calls) == 2, (code, data)
        assert data["status"] == status and data["stop_reason"] == reason
        assert data["http_status"] == code
        assert "fixture-private" not in report.read_text()

args = ["/usr/local/bin/dalfox", "scan", "https://example.org?q=fixture-private",
        "--scan-timeout", "300", "-o", "/tmp/fixture-report.json"]
notice = "[scan] https://example.org/?q=fixture-private exceeded --scan-timeout (300s); cancelling target (stops at next checkpoint)"
with patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(args, 0, "fixture-private", notice + "\n")):
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        assert dalfox_runner.run(args) == 0
    assert output.getvalue().strip() == "[asfb] dalfox_scan_budget"
print("Installed Arjun unhealthy-response regression and Dalfox native-budget relay passed; network disabled")

# Parse the installed SQLmap identity option without initializing any scan.
sys.path.insert(0, "/opt/sqlmap")
from lib.parse.cmdline import cmdLineParser
assert cmdLineParser(["sqlmap", "-u", "https://example.org/?id=fixture", "-A", "Fixture-Researcher"]).agent == "Fixture-Researcher"
print("Installed SQLmap User-Agent option parsed offline")
