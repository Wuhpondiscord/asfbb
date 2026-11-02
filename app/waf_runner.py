"""Native WAFW00F runner with one scoped, paced and bounded HTTP transport."""
import contextlib
import io
import json
import logging
import os
import sys
import time
from urllib.parse import urlsplit, urlunsplit

try:
    from .scope import public_host
except ImportError:
    from scope import public_host


class ProfileStopped(Exception):
    pass


def origin(value):
    parts = urlsplit(value)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password
            or parts.port not in (None, 80, 443, 8080)):
        raise ValueError("Invalid origin")
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


class Guard:
    def __init__(self, spec, session, pause=time.sleep):
        self.target = spec["target"]
        self.scope = origin(self.target)
        if self.scope[1] != spec["host"]:
            raise ValueError("Target host mismatch")
        self.agent = spec["agent"]
        self.delay = max(1.0, min(30.0, float(spec.get("delay", 1.5))))
        self.session, self.pause = session, pause
        self.started, self.last = time.monotonic(), None
        self.requests, self.limited = 0, False
        self.session.trust_env = False

    def request(self, path=None, params=None):
        if self.requests >= 8:
            raise ProfileStopped("request_budget")
        if time.monotonic() - self.started >= 35:
            raise ProfileStopped("deadline")
        parts = urlsplit(self.target)
        if path is not None:
            if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or any(c in path for c in "\r\n\x00"):
                raise ProfileStopped("scope_blocked")
            candidate = urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))
        else:
            candidate = self.target
        if origin(candidate) != self.scope:
            raise ProfileStopped("scope_blocked")
        # Vendor identification needs the native central probe. Do not run OS
        # command/XXE probes if a plugin requests them; no genericdetect().
        encoded = json.dumps(params or {})
        if any(marker in encoded for marker in ("SLEEP(", "/bin/", "file://", "<!ENTITY", "curl ", "ping ")):
            raise ProfileStopped("probe_blocked")
        if self.last is not None:
            self.pause(max(0.0, self.delay - (time.monotonic() - self.last)))
        if time.monotonic() - self.started >= 35:
            raise ProfileStopped("deadline")
        public_host(self.scope[1], os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
        self.requests += 1
        self.last = time.monotonic()
        try:
            response = self.session.get(candidate, params=params or {}, headers={"User-Agent": self.agent},
                                        timeout=(5, 8), allow_redirects=False, stream=True, verify=True)
            with response:
                if response.status_code == 429:
                    raise ProfileStopped("rate_limited")
                body = bytearray()
                for chunk in response.iter_content(8192):
                    if time.monotonic() - self.started >= 35:
                        raise ProfileStopped("deadline")
                    if len(body) + len(chunk) > 262144:
                        self.limited = True
                        body.extend(chunk[:262144 - len(body)])
                        break
                    body.extend(chunk)
                response._content = bytes(body)
                response._content_consumed = True
                return response
        except ProfileStopped:
            raise
        except Exception as exc:
            raise ProfileStopped("request_failed") from exc


def run(spec, engine_cls=None, session=None, pause=time.sleep):
    if engine_cls is None:
        from wafw00f.main import WAFW00F
        engine_cls = WAFW00F
    if session is None:
        import requests
        session = requests.Session()
    guard = Guard(spec, session, pause)
    report = {"profile": "wafw00f-bounded", "status": "completed", "vendors": [],
              "requests": 0, "stop_reason": ""}
    class BoundedWAF(engine_cls):
        def Request(self, headers=None, path=None, params=None, delay=0):
            return guard.request(path, params)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            scanner = BoundedWAF(spec["target"], followredirect=False,
                                 path=urlsplit(spec["target"]).path or "/", timeout=8)
            # The upstream central probe includes a SQL sleep expression. Supply
            # the other native signatures without time-based or command probes.
            scanner.sqlistring = 'UNION SELECT NULL FROM information_schema'
            vendors, _ = scanner.identwaf(findall=False)
        report["vendors"] = [str(name)[:120] for name in vendors][:10]
        if guard.limited:
            report.update(status="partial", stop_reason="response_limit")
    except ProfileStopped as exc:
        report.update(status="partial" if guard.requests else "failed", stop_reason=str(exc))
    except Exception:
        report.update(status="failed", stop_reason="request_failed")
    finally:
        report["requests"] = guard.requests
        session.close()
    return report


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    with open(sys.argv[1], encoding="utf-8") as source:
        spec = json.load(source)
    report = run(spec)
    with open(sys.argv[2], "w", encoding="utf-8") as output:
        json.dump(report, output)
