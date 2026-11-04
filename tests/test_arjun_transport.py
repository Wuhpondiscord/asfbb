"""Transport outcomes distinguish baseline availability from parameter responses."""
import json
import sys
import types
from unittest.mock import patch

import pytest
import requests

from app import arjun_runner


@pytest.mark.parametrize("codes,status,reason", [
    ([404], "partial", "endpoint_unavailable"),
    ([410], "partial", "endpoint_unavailable"),
    ([200, 200, 200, 200, 404], "completed", None),
    ([200, 410], "completed", None),
    ([200, 403], "partial", "endpoint_unavailable"),
    ([200, 429], "partial", "http_unavailable"),
    ([200, 503], "partial", "http_unavailable"),
])
def test_parameter_404_does_not_abort_native_review(tmp_path, codes, status, reason):
    utils = types.ModuleType("arjun.core.utils")
    utils.stable_request = lambda *args: None
    arjun = types.ModuleType("arjun")
    core = types.ModuleType("arjun.core")
    arjun.core, core.utils = core, utils
    calls = []
    def transport(session, method, url, **kwargs):
        calls.append(url)
        response = requests.Response()
        response.status_code = codes[len(calls) - 1]
        response.headers["Content-Type"] = "text/html"
        response._content = b"fixture"
        response._content_consumed = True
        return response
    def native(*args, **kwargs):
        utils.stable_request("https://example.org/", {})
        for _ in codes[1:]:
            requests.get("https://example.org/", params={"fixture": "value"})
    report = tmp_path / "guard.json"
    with patch.dict(sys.modules, {"arjun": arjun, "arjun.core": core, "arjun.core.utils": utils}), \
         patch.object(arjun_runner, "public_host"), \
         patch.object(requests.sessions.Session, "request", transport), \
         patch.object(arjun_runner.runpy, "run_module", native):
        assert arjun_runner.run(["-u", "https://example.org/", "--asfb-report", str(report)]) == 0
    data = json.loads(report.read_text())
    assert data["status"] == status and data.get("stop_reason") == reason
    assert data["requests"] == len(codes)
