"""IDOR-Forge comparison profile: four bounded GETs; never emit response bodies.

The pinned upstream comparison engine runs in an isolated HF environment.
Its CLI, payload generator, login, mutation methods, reports and GUI are not used.
"""
import contextlib
import importlib.util
import io
import json
import os
import sys
import time
from urllib.parse import urlsplit, urlunsplit, urlencode

try:
    from .scope import public_host
    from .module_inputs import ModuleInputs
except ImportError:
    from scope import public_host
    from module_inputs import ModuleInputs

MAX_BYTES = 65536


class ProfileStopped(Exception):
    pass


def load_checker():
    os.environ.setdefault("MPLBACKEND", "Agg")
    spec = importlib.util.spec_from_file_location("idor_forge_core", "/opt/idor-forge/IDORChecker.py")
    module = importlib.util.module_from_spec(spec)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        spec.loader.exec_module(module)
    # Comparison methods need only thresholds, not upstream network sessions.
    checker = object.__new__(module.IDORChecker)
    checker.thresholds = {"structure": 0.8, "content": 0.9, "text": 0.8}
    return checker


def endpoint(spec):
    inputs = ModuleInputs(**spec["inputs"])
    parts = urlsplit(spec["target"])
    if (parts.scheme not in ("http", "https") or parts.hostname != spec["host"]
            or parts.username or parts.password or parts.port not in (None, 80, 443, 8080)):
        raise ValueError("Invalid target")
    if not (inputs.idor_path and inputs.idor_baseline and inputs.idor_values):
        raise ValueError("Missing explicit IDOR inputs")
    target = urlunsplit((parts.scheme, parts.netloc, inputs.idor_path, "", ""))
    return target, inputs


def fetch(session, target, host, agent, parameter, value):
    # Revalidate the public host before every request, never follow redirects.
    public_host(host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
    import requests
    with session.get(target, params={parameter: value}, headers={"User-Agent": agent},
                     timeout=(5, 8), allow_redirects=False, stream=True) as response:
        if response.status_code == 429:
            raise ProfileStopped("Rate limited; remaining comparisons skipped")
        data = bytearray()
        for chunk in response.iter_content(8192):
            data.extend(chunk)
            if len(data) > MAX_BYTES:
                raise ProfileStopped("Response exceeded the 64 KiB comparison limit")
        text = bytes(data).decode("utf-8", "replace")
        if "rate limit" in text.lower():
            raise ProfileStopped("Rate-limit response; remaining comparisons skipped")
        return response.status_code, text


def compare(checker, baseline, current, status):
    # Upstream JSON structure methods expect objects. Compare non-object JSON as
    # text to avoid .keys() failures on arrays, numbers and strings.
    try:
        a, b = json.loads(baseline), json.loads(current)
    except (ValueError, TypeError):
        a = b = None
    if not isinstance(a, dict) or not isinstance(b, dict):
        baseline, current = "text:" + baseline, "text:" + current
    values = checker._compare_responses(baseline, current)
    return {key: round(float(value), 4) for key, value in values.items()}, bool(
        status == 200 and baseline != current and
        checker._detect_idor(values, status, {"role": "default"}))


def run(spec, checker=None, session=None, pause=time.sleep):
    target, inputs = endpoint(spec)
    checker = checker or load_checker()
    owns_session = session is None
    if session is None:
        import requests
        session = requests.Session()
    session.trust_env = False
    report = {"profile": "idor-forge-get-comparison", "status": "completed",
              "comparisons": [], "requests": 0, "reason": ""}
    started = time.monotonic()
    delay = max(1.0, min(float(spec.get("delay", 1.5)), 30.0))
    try:
        report["requests"] += 1
        status, baseline = fetch(session, target, spec["host"], spec["agent"],
                                 inputs.idor_parameter, inputs.idor_baseline)
        if status != 200:
            report.update(status="skipped", reason="Baseline HTTP " + str(status) +
                          "; no valid comparison baseline (redirects are not followed)")
            return report
        for value in inputs.idor_values:
            if value == inputs.idor_baseline:
                continue
            if time.monotonic() - started + delay + 8 > 50:
                raise ProfileStopped("Profile deadline; remaining comparisons skipped")
            pause(delay)
            report["requests"] += 1
            code, body = fetch(session, target, spec["host"], spec["agent"],
                               inputs.idor_parameter, value)
            metrics, candidate = compare(checker, baseline, body, code)
            report["comparisons"].append({"index": len(report["comparisons"]) + 1,
                                          "http_status": code, "candidate": candidate,
                                          "similarity": metrics})
    except ProfileStopped as exc:
        report.update(status="partial", reason=str(exc))
    except Exception as exc:
        # Exception messages can embed request URLs or bodies.
        report.update(status="failed", reason="Comparison stopped: " + type(exc).__name__)
    finally:
        if owns_session:
            session.close()
    return report


def main():
    try:
        with open(sys.argv[1], encoding="utf-8") as source:
            report = run(json.load(source))
    except Exception as exc:
        report = {"profile": "idor-forge-get-comparison", "status": "failed",
                  "comparisons": [], "requests": 0, "reason": type(exc).__name__}
    print(json.dumps(report))


if __name__ == "__main__":
    main()
