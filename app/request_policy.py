"""Per-job target HTTP policy; no global target state and no credential logging."""
import asyncio
import contextvars
import fnmatch
import json
import math
import os
import re
import threading
import time
from urllib.parse import parse_qsl, unquote, urlsplit

CURRENT = contextvars.ContextVar("asfb_request_policy", default=None)
SAMPLES = contextvars.ContextVar("asfb_private_samples", default=None)
PYTHON_HTTP = {"arjun", "wafw00f", "wapiti", "graphw00f", "corsy", "takeover",
               "s3-review", "websocket", "vcs-artifacts", "idor-forge", "garak",
               "race-replay", "nosql", "nettacker"}
NON_TARGET_HTTP = {"gau", "amass", "semgrep", "trufflehog", "depscan", "trivy", "osv-scanner", "testssl"}
NARROW_SUPPORTED = PYTHON_HTTP | NON_TARGET_HTTP | {"wpscan", "httpx", "zap-passive", "retirejs"}


class PolicyBlocked(ValueError):
    pass


def current():
    value = CURRENT.get()
    if value is not None:
        return value
    raw = os.environ.get("ASFB_TARGET_POLICY")
    return json.loads(raw) if raw else {}


def origin(value):
    if any(ord(c) < 32 for c in str(value)) or "\\" in str(value):
        raise PolicyBlocked("Invalid target URL")
    p = urlsplit(str(value))
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise PolicyBlocked("Invalid target origin")
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


def path(value):
    result = value or "/"
    for _ in range(2):
        result = unquote(result)
    if (any(part in (".", "..") for part in result.split("/")) or "\\" in result
            or re.search(r"%(?:2e|2f|5c|25)", result, re.I)):
        raise PolicyBlocked("Ambiguous target path")
    return result


def path_matches(rule, candidate):
    return (fnmatch.fnmatchcase(candidate, rule.replace("[", "[[]").replace("?", "[?]")) if "*" in rule else
            rule == "/" or candidate == rule or candidate.startswith(rule.rstrip("/") + "/"))


def allows(value, policy=None):
    policy = current() if policy is None else policy
    if not policy:
        return True
    try:
        if origin(value) != origin(policy["target"]):
            return False
        p = urlsplit(str(value))
        actual = path(p.path)
        if not path_matches(path(policy.get("path", "/")), actual):
            return False
        query = policy.get("query")
        if query and sorted(parse_qsl(p.query, keep_blank_values=True)) != sorted(parse_qsl(query, keep_blank_values=True)):
            return False
        for rule in policy.get("exclusions", []):
            r = urlsplit(rule if "://" in rule else "https://" + rule) if not rule.startswith("/") else None
            if r is not None:
                host = r.hostname or ""
                ours = p.hostname
                if not (ours.endswith(host[1:]) and ours != host[2:] if host.startswith("*.") else ours == host):
                    continue
                if "://" in rule and origin(rule) != origin(value) and not host.startswith("*."):
                    continue
            excluded_path = path(r.path if r is not None else rule)
            if path_matches(excluded_path, actual) and (r is None or not r.query or r.query == p.query):
                return False
        return True
    except (ValueError, TypeError, KeyError):
        return False


def check(value, policy=None):
    if not allows(str(value), policy):
        raise PolicyBlocked("Program request policy blocked an out-of-scope URL")


def headers(existing=None, policy=None):
    policy = current() if policy is None else policy
    forced = {**policy.get("headers", {})}
    if policy.get("agent"):
        forced["User-Agent"] = policy["agent"]
    names = {name.lower() for name in forced}
    result = {k: v for k, v in dict(existing or {}).items() if k.lower() not in names}
    result.update(forced)
    return result


def narrow(policy=None):
    p = current() if policy is None else policy
    return bool(p.get("path", "/") != "/" or p.get("query") or p.get("exclusions"))


def stage_reason(module, policy=None):
    p = current() if policy is None else policy
    if not p:
        return ""
    if narrow(p) and module not in NARROW_SUPPORTED:
        return "Selected module retained, but its native adapter cannot enforce this path/query/exclusion policy; other compatible modules continue"
    if module == "nuclei" and p.get("rate") is not None and p["rate"] < 1:
        return "Native Nuclei cannot guarantee this sub-one-request/second rule; other paced modules continue"
    if module == "race-replay" and p.get("rate") is not None and p["rate"] < 2:
        return "Race burst is incompatible with this program's paced request limit; other modules continue"
    return ""


class Pacer:
    def __init__(self):
        self.last = None
        self.lock = threading.Lock()
        self.async_lock = None

    def wait(self, policy=None):
        p = current() if policy is None else policy
        if not p or p.get("module") == "race-replay":
            return
        with self.lock:
            if self.last is not None:
                time.sleep(max(0, float(p.get("delay", 1)) - (time.monotonic() - self.last)))
            self.last = time.monotonic()

    async def await_turn(self, policy=None):
        p = current() if policy is None else policy
        if not p or p.get("module") == "race-replay":
            return
        if self.async_lock is None:
            self.async_lock = asyncio.Lock()
        async with self.async_lock:
            if self.last is not None:
                await asyncio.sleep(max(0, float(p.get("delay", 1)) - (time.monotonic() - self.last)))
            self.last = time.monotonic()


def command(args, policy):
    """Inject verified native header/pacing options or a Python transport guard."""
    args = list(args)
    if not policy:
        return args
    module = policy.get("module")
    delay = max(1, float(policy.get("delay", 1)))
    extra = policy.get("headers", {})
    def replace(flag, value):
        if flag in args:
            args[args.index(flag) + 1] = str(value)
        else:
            args.extend([flag, str(value)])
    if module in PYTHON_HTTP and args and "python" in os.path.basename(args[0]):
        return [args[0], "-m", "app.policy_entry"] + args[1:]
    if module in ("katana", "httpx", "nuclei", "ffuf", "dalfox", "nikto", "kiterunner"):
        flag = {"dalfox": "--headers", "nikto": "-Add-header", "kiterunner": "--header"}.get(module, "-H")
        for name, value in extra.items():
            args.extend([flag, name + ": " + value])
    if module == "katana":
        replace("-rd", math.ceil(delay))
    elif module == "httpx":
        replace("-delay", str(delay) + "s")
    elif module == "nuclei":
        replace("-rlm", max(1, math.floor(60 / delay)))
        # Minute pacing is the effective native limiter; one worker/batch remains.
    elif module == "ffuf":
        replace("-p", delay)
    elif module == "dalfox":
        replace("--delay", math.ceil(delay * 1000))
    elif module == "sqlmap":
        args = [a for a in args if not a.startswith("--delay=")]
        args.append("--delay=" + str(delay))
        if extra:
            args.extend(["--headers", "\n".join(k + ": " + v for k, v in extra.items())])
    return args
