"""Run installed Arjun with exact-origin, bounded GET transport and fixed telemetry."""
import contextlib
import io
import json
import os
import runpy
import sys
from pathlib import Path
from urllib.parse import urlsplit

import requests

from .scope import public_host
from .sampling import origin


class Stop(BaseException):
    def __init__(self, reason, code=None):
        self.reason, self.code = reason, code


def run(argv):
    args = list(argv)
    index = args.index("--asfb-report")
    report_path = Path(args[index + 1])
    del args[index:index + 2]
    target = args[args.index("-u") + 1]
    expected = origin(target)
    stats = {"status": "running", "requests": 0}
    original = requests.sessions.Session.request

    def request(session, method, url, **kwargs):
        if origin(url) != expected or method.upper() != "GET":
            raise Stop("scope_blocked")
        if stats["requests"] >= 64:
            raise Stop("request_budget")
        public_host(expected[1], os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
        session.trust_env = False
        session.cookies.clear()
        kwargs.update(verify=True, allow_redirects=False, timeout=8, stream=True)
        stats["requests"] += 1
        try:
            response = original(session, method, url, **kwargs)
            code = response.status_code
            if code in (301, 302, 303, 307, 308):
                response.close()
                raise Stop("redirect_not_followed", code)
            if code in (400, 413, 418, 429) or code >= 500:
                response.close()
                raise Stop("http_unavailable", code)
            # A missing baseline is inapplicable. Later 404/410 responses can
            # be parameter-dependent differences for native Arjun to compare.
            if code >= 400 and not (code in (404, 410) and stats["requests"] > 1):
                response.close()
                raise Stop("endpoint_unavailable", code)
            content = bytearray()
            for chunk in response.iter_content(16384):
                if len(content) + len(chunk) > 262144:
                    response.close()
                    raise Stop("response_limit", code)
                content.extend(chunk)
            response._content, response._content_consumed = bytes(content), True
            response.close()
            return response
        except requests.RequestException:
            raise Stop("request_failed")

    # Native stable_request drops the query and may change scheme. Preserve the
    # selected URL and use the same guarded transport instead.
    def stable_request(url, headers):
        response = requests.get(url, headers=headers)
        if not any(kind in response.headers.get("Content-Type", "").lower()
                   for kind in ("text", "html", "json", "xml")):
            raise Stop("content_unavailable")
        return url

    import arjun.core.utils as utils
    old_stable, old_argv = utils.stable_request, sys.argv
    requests.sessions.Session.request = request
    utils.stable_request = stable_request
    sys.argv = ["arjun"] + args
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            runpy.run_module("arjun.__main__", run_name="__main__")
        stats["status"] = "completed"
    except Stop as exc:
        policy = exc.reason in {"scope_blocked", "request_budget", "redirect_not_followed", "response_limit"}
        stats.update(status="completed" if policy else "partial", stop_reason=exc.reason,
                     early_stop=policy, coverage_complete=False)
        if type(exc.code) is int:
            stats["http_status"] = exc.code
    except SystemExit as exc:
        stats["status"] = "completed" if exc.code in (None, 0) else "failed"
    except Exception:
        stats.update(status="failed", stop_reason="native_error")
    finally:
        requests.sessions.Session.request = original
        utils.stable_request, sys.argv = old_stable, old_argv
        report_path.write_text(json.dumps(stats), encoding="utf-8")
    return 0 if stats["status"] in ("completed", "partial") else 2


if __name__ == "__main__":
    raise SystemExit(run(sys.argv[1:]))