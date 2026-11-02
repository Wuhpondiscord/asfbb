"""Installed native tools; mock WAF transport and source-only Semgrep, no network."""
import asyncio
import json
import socket
import sys
from unittest.mock import patch

sys.path.insert(0, "/app")
mode = sys.argv[1]
if mode == "wafw00f":
    import requests
    from app.waf_runner import run
    class Session:
        trust_env = True
        def get(self, target, **kwargs):
            assert target == "https://example.org/"
            assert kwargs["allow_redirects"] is False and kwargs["verify"] is True
            assert "SLEEP(" not in json.dumps(kwargs.get("params"))
            response = requests.Response()
            response.status_code = 200
            response.url = target
            response.headers["Server"] = "cloudflare"
            response.headers["CF-RAY"] = "offline-fixture"
            response._content = b"<html>Offline native WAF fixture</html>"
            response._content_consumed = True
            return response
        def close(self): pass
    with patch("app.waf_runner.public_host"), patch.object(socket.socket, "connect", side_effect=AssertionError("Network forbidden")):
        result = run({"target": "https://example.org/", "host": "example.org", "agent": "Test", "delay": 1},
                     session=Session(), pause=lambda seconds: None)
    assert result["status"] == "completed", result
    assert any("cloudflare" in name.lower() for name in result["vendors"]), result
    assert result["requests"] == 2, result
elif mode == "semgrep":
    from app.analysis_modules import run
    from app.module_inputs import ModuleInputs
    for language, source, rule in [
        ("python", "import subprocess\nsubprocess.run('fixture', shell=True)\n", "asfb-python-shell-true"),
        ("javascript", "eval(userInput);\n", "asfb-js-eval"),
        ("typescript", "const value: string = input; eval(value);\n", "asfb-js-eval"),
    ]:
        result = asyncio.run(run("semgrep", "https://example.org/", "example.org", "Test", 1,
                                 ModuleInputs(source_text=source, sast_language=language)))
        assert result["status"] == "findings", (language, result)
        assert rule in {row["rule_id"] for row in result["alerts"]}, (language, result)
    result = asyncio.run(run("semgrep", "https://example.org/", "example.org", "Test", 1,
                             ModuleInputs(source_text="def add(a, b):\n    return a + b\n", sast_language="python")))
    assert result["status"] == "completed" and result["alerts"] == [], result
else:
    raise ValueError(mode)
print(mode + " installed engine offline smoke passed")
