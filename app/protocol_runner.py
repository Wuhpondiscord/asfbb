"""Keyless scoped protocol profiles. Upstream engines run only through Transport."""
import base64
import contextlib
import hashlib
import html
import importlib
import io
import json
import os
import re
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit, urlunsplit

try:
    from .scope import public_host, DNSResolutionFailed
except ImportError:
    from scope import public_host, DNSResolutionFailed

LIMITS = {"graphw00f": (64, 90), "corsy": (12, 30), "takeover": (1, 25),
          "s3-review": (2, 20), "websocket": (2, 15), "vcs-artifacts": (5, 25)}
BROWSER_CORS = {"origin reflected", "post-domain wildcard", "pre-domain wildcard", "null origin allowed"}


class Stopped(Exception):
    pass


def origin(url):
    p = urlsplit(url)
    if (p.scheme not in ("http", "https") or not p.hostname or p.username or p.password
            or p.port not in (None, 80, 443, 8080) or "\\" in url or any(c in url for c in "\r\n\x00")):
        raise ValueError("Invalid origin")
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


class Transport:
    def __init__(self, spec, session, pause=time.sleep):
        self.target, self.module = spec["target"], spec["module"]
        self.scope = origin(self.target)
        if self.scope[1] != spec["host"]:
            raise ValueError("Host mismatch")
        self.limit, self.seconds = LIMITS[self.module]
        self.started, self.last = time.monotonic(), None
        self.requests, self.truncated = 0, False
        self.delay = max(1.0, min(30.0, float(spec.get("delay", 1.5))))
        self.session, self.pause, self.agent = session, pause, spec["agent"]
        session.trust_env = False

    def request(self, method, url=None, *, headers=None, params=None, payload=None, body=True):
        url = url or self.target
        if origin(url) != self.scope or method not in ("GET", "POST") or method == "POST" and self.module != "graphw00f":
            raise Stopped("scope_blocked")
        if self.requests >= self.limit:
            raise Stopped("request_budget")
        if self.last is not None:
            self.pause(max(0, self.delay - (time.monotonic() - self.last)))
        left = self.seconds - (time.monotonic() - self.started)
        if left <= 0:
            raise Stopped("deadline")
        allowed = {"User-Agent": self.agent}
        for key, value in (headers or {}).items():
            if key not in ("Origin", "Upgrade", "Connection", "Sec-WebSocket-Key", "Sec-WebSocket-Version"):
                raise Stopped("scope_blocked")
            allowed[key] = value
        public_host(self.scope[1], os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")
        self.requests += 1
        self.last = time.monotonic()
        if getattr(self.session, "cookies", None) is not None:
            self.session.cookies.clear()
        try:
            with self.session.request(method, url, headers=allowed, params=params, json=payload,
                                      timeout=min(8, left), allow_redirects=False, stream=True, verify=True) as response:
                if response.status_code == 429:
                    raise Stopped("rate_limited")
                if response.status_code in (301, 302, 303, 307, 308):
                    raise Stopped("redirect_not_followed")
                content = bytearray()
                if body:
                    for chunk in response.iter_content(8192):
                        if time.monotonic() - self.started >= self.seconds:
                            raise Stopped("deadline")
                        if len(content) + len(chunk) > 65536:
                            content.extend(chunk[:65536 - len(content)])
                            self.truncated = True
                            break
                        content.extend(chunk)
                return response.status_code, dict((k.lower(), v) for k, v in response.headers.items()), bytes(content)
        except Stopped:
            raise
        except Exception as exc:
            raise Stopped("request_failed") from exc


def graph_profile(net, report, emit, engine_cls=None):
    if engine_cls is None:
        sys.path.insert(0, "/opt/graphw00f")
        engine_cls = importlib.import_module("graphw00f.lib").GRAPHW00F
    cache, method = {}, ["POST"]
    excluded = [0]

    def query(url, operation="query", payload=""):
        if (operation != "query" or not isinstance(payload, str)
                or re.search(r"\b(mutation|subscription|fragment)\b", payload, re.I)):
            excluded[0] += 1
            return {}
        key = re.sub(r"\s+", "", payload)
        if key in cache:
            return cache[key]
        code, _, data = net.request(method[0], url, payload={"query": payload} if method[0] == "POST" else None,
                                    params={"query": payload} if method[0] == "GET" else None)
        try:
            result = json.loads(data)
        except (ValueError, UnicodeError):
            result = None
        if method[0] == "POST" and (code in (405, 415) or result is None):
            method[0] = "GET"
            code, _, data = net.request("GET", url, params={"query": payload})
            try:
                result = json.loads(data)
            except (ValueError, UnicodeError):
                result = None
        cache[key] = result if isinstance(result, dict) else {}
        return cache[key]

    baseline = query(net.target, payload="query { __typename }")
    data = baseline.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("__typename"), str):
        report.update(status="skipped", stop_reason="graphql_unconfirmed")
        return
    emit("graphql_present")
    introspection = query(net.target, payload="query { __schema { queryType { name } } }")
    if isinstance(introspection.get("data"), dict) and isinstance(introspection["data"].get("__schema"), dict):
        emit("graphql_introspection")
    class Engine(engine_cls):
        def graph_query(self, url, operation="query", payload=""):
            return query(url, operation, payload)
    engine = Engine(headers={}, cookies={}, timeout=8, proxies={}, follow_redirects=False)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        name = engine.execute(net.target)
    if isinstance(name, str) and re.fullmatch(r"[a-z0-9_-]{1,50}", name):
        emit("graphql_engine", engine=name)
    report["excluded_probe_types"] = excluded[0]


def browser_origin(value):
    if value == "null":
        return True
    try:
        p = urlsplit(value)
        port = p.port
        return (p.scheme in ("http", "https") and bool(p.hostname)
                and re.fullmatch(r"[a-zA-Z0-9.-]+", p.hostname) is not None
                and not p.username and not p.password and not p.path and not p.query and not p.fragment
                and (port is None or 1 <= port <= 65535))
    except (TypeError, ValueError):
        return False


def cors_profile(net, report, emit, native=None):
    if native is None:
        sys.path.insert(0, "/opt/corsy")
        native = importlib.import_module("core.tests")
    history = []
    def requester(url, scheme, header_dict, probe_origin):
        code, headers, _ = net.request("GET", url, headers={"Origin": probe_origin}, body=False)
        history.append((probe_origin, code, headers))
        return headers
    # Use the native test order/classifier, with all network/pacing in Transport.
    previous_requester, previous_time = native.requester, native.time
    native.requester = requester
    native.time = SimpleNamespace(sleep=lambda seconds: None)
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            result = native.active_tests(net.target, urlsplit(net.target).netloc, net.scope[0], {}, 0)
    finally:
        native.requester, native.time = previous_requester, previous_time
    if result and isinstance(result.get(net.target), dict):
        kind = result[net.target].get("class")
        known = BROWSER_CORS | {"wildcard value", "third party allowed", "unrecognized underscore",
                                "broken parser", "unescaped regex", "http origin allowed", "invalid value"}
        if kind not in known:
            return
        candidates = [(code, headers) for probe, code, headers in history
                      if browser_origin(probe) and probe != net.scope[0] + "://" + urlsplit(net.target).netloc
                      and headers.get("access-control-allow-origin") == probe]
        credentials = any(200 <= code < 300 and headers.get("access-control-allow-credentials", "").strip() == "true"
                          for code, headers in candidates)
        emit("cors_observation", category=kind, credential_candidate=kind in BROWSER_CORS and credentials)


def dns_state(host, resolver=None):
    import dns.resolver
    resolver = resolver or dns.resolver.Resolver()
    resolver.timeout, resolver.lifetime = 2, 3
    aliases, current, unknown = [], host, False
    nxdomain = False
    for _ in range(4):
        try:
            answer = resolver.resolve(current, "CNAME", raise_on_no_answer=False)
            targets = [str(item.target).lower().rstrip(".") for item in answer if hasattr(item, "target")]
        except dns.resolver.NXDOMAIN as exc:
            targets = []
            for response in exc.responses().values():
                for rrset in response.answer:
                    if rrset.rdtype == 5:
                        targets.extend(str(item.target).lower().rstrip(".") for item in rrset if hasattr(item, "target"))
            nxdomain = True
        except dns.resolver.NoAnswer:
            break
        except Exception:
            unknown = True
            break
        targets = [name for name in targets if re.fullmatch(r"[a-z0-9_.-]{1,253}", name)]
        if not targets:
            break
        for name in targets:
            if name != host and name not in aliases:
                aliases.append(name)
        current = targets[-1]
        if nxdomain:
            break
    if aliases and not nxdomain and not unknown:
        try:
            resolver.resolve(aliases[-1], "A", raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN:
            nxdomain = True
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            unknown = True
    return {"aliases": aliases[:4], "nxdomain": nxdomain, "unknown": unknown}


def takeover_profile(net, report, emit, resolve=dns_state, fingerprints=None):
    state = resolve(net.scope[1])
    report["dns_aliases"] = state["aliases"]
    if state["unknown"]:
        raise Stopped("dns_inconclusive")
    if fingerprints is None:
        fingerprints = json.loads(Path("/opt/takeover/fingerprints.json").read_text(encoding="utf-8"))
    rows = []
    for item in fingerprints:
        if not isinstance(item, dict) or item.get("vulnerable") is not True or item.get("cicd_pass") is not True:
            continue
        suffixes = [suffix.lower().lstrip("*.") for suffix in item.get("cname", []) if isinstance(suffix, str)]
        if any(alias == suffix or alias.endswith("." + suffix) for alias in state["aliases"] for suffix in suffixes):
            rows.append(item)
    report["provider_candidates"] = len(rows)
    if not rows:
        return
    if state["nxdomain"]:
        for item in rows:
            if item.get("nxdomain") is True:
                emit("takeover_candidate", provider=str(item["service"])[:100], evidence="cname_and_nxdomain")
        return
    rows = [item for item in rows if not item.get("nxdomain") and isinstance(item.get("fingerprint"), str)
            and item["fingerprint"] and item["fingerprint"] != "NXDOMAIN"
            and not item["fingerprint"].startswith("HTTP_STATUS=") and ".*" not in item["fingerprint"]]
    if not rows:
        return
    code, _, body = net.request("GET")
    text = html.unescape(body.decode("utf-8", "replace")).casefold()
    for item in rows:
        if item.get("http_status") is not None and item["http_status"] != code:
            continue
        fingerprint = item.get("fingerprint", "")
        if (not item.get("nxdomain") and isinstance(fingerprint, str) and fingerprint
                and fingerprint != "NXDOMAIN" and not fingerprint.startswith("HTTP_STATUS=")
                and ".*" not in fingerprint and html.unescape(fingerprint).casefold() in text):
            emit("takeover_candidate", provider=str(item["service"])[:100], evidence="cname_and_literal_fingerprint")


def bucket_target(url):
    p = urlsplit(url)
    host, path = p.hostname or "", p.path
    region = r"[a-z]{2}(?:-[a-z]+){1,2}-[0-9]+"
    service = r"s3(?:[.-]" + region + r")?\.amazonaws\.com"
    virtual = re.fullmatch(r"([a-z0-9.-]+)\." + service, host)
    if p.scheme not in ("http", "https") or p.port not in (None, 80, 443):
        return None
    if virtual:
        bucket = virtual.group(1)
        if path not in ("", "/"):
            return None
        root = "/"
    elif re.fullmatch(service, host):
        fields = path.strip("/").split("/")
        if len(fields) != 1 or not fields[0]:
            return None
        bucket, root = fields[0], "/" + fields[0] + "/"
    else:
        return None
    if (not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket or "") or ".." in bucket
            or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+", bucket) or p.query):
        return None
    return urlunsplit((p.scheme, p.netloc, root, "", "")), bucket


def xml_body(data):
    if b"<!doctype" in data.lower() or b"<!entity" in data.lower():
        return None
    try:
        return ET.fromstring(data)
    except (ET.ParseError, ValueError):
        return None


def local(tag):
    return tag.rsplit("}", 1)[-1]


def s3_profile(net, report, emit):
    target = bucket_target(net.target)
    if target is None:
        report.update(status="skipped", stop_reason="s3_root_required")
        return
    url, bucket = target
    code, _, data = net.request("GET", url, params={"list-type": "2", "max-keys": "0"})
    parsed = xml_body(data)
    if code == 200 and parsed is not None and local(parsed.tag) == "ListBucketResult":
        names = [node.text for node in parsed if local(node.tag) == "Name"]
        if names == [bucket]:
            emit("s3_anonymous_list")
    code, _, data = net.request("GET", url, params={"acl": ""})
    parsed = xml_body(data)
    if code == 200 and parsed is not None and local(parsed.tag) == "AccessControlPolicy":
        emit("s3_acl_readable")
        permissions = set()
        for grant in parsed.iter():
            if local(grant.tag) != "Grant":
                continue
            group = [node.text for node in grant.iter() if local(node.tag) == "URI"]
            if "http://acs.amazonaws.com/groups/global/AllUsers" in group:
                permissions.update(node.text for node in grant.iter() if local(node.tag) == "Permission")
        allowed = {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}
        for permission in sorted(permissions & allowed):
            emit("s3_public_acl", permission=permission)


def websocket_profile(net, report, emit):
    site_origin = net.scope[0] + "://" + urlsplit(net.target).netloc
    for attempt, request_origin in enumerate((site_origin, "https://asfb-probe.invalid")):
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        expected = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()).decode("ascii")
        code, headers, _ = net.request("GET", headers={"Origin": request_origin, "Upgrade": "websocket",
            "Connection": "Upgrade", "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"}, body=False)
        valid = (code == 101 and headers.get("sec-websocket-accept", "").strip() == expected
                 and headers.get("upgrade", "").lower() == "websocket"
                 and "upgrade" in [part.strip() for part in headers.get("connection", "").lower().split(",")])
        if attempt == 0:
            if not valid:
                report.update(status="skipped", stop_reason="websocket_unconfirmed")
                return
            emit("websocket_present")
        elif valid:
            emit("websocket_cross_origin")


def vcs_match(kind, data):
    text = data.decode("utf-8", "replace").strip()
    if kind == "git_head":
        return bool(re.fullmatch(r"ref: refs/(?:heads|tags)/[A-Za-z0-9_./-]{1,200}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", text))
    if kind == "git_config":
        return bool(re.search(r"(?m)^\[core\]\s*$", text) and re.search(r"(?m)^\s*repositoryformatversion\s*=\s*[0-9]+\s*$", text))
    if kind == "hg_requires":
        features = {"revlogv1", "store", "fncache", "dotencode", "generaldelta", "sparserevlog"}
        return len(features.intersection(text.splitlines())) >= 2
    parsed = xml_body(data)
    return (parsed is not None and local(parsed.tag) == "wc-entries"
            or text.startswith("10\n") and "\ndir\n" in text)


def vcs_profile(net, report, emit):
    p = urlsplit(net.target)
    if p.query or p.path and not p.path.endswith("/"):
        report.update(status="skipped", stop_reason="directory_url_required")
        return
    base = net.target.rstrip("/") + "/"
    from urllib.parse import urljoin
    _, _, baseline = net.request("GET", urljoin(base, ".asfb-missing-" + os.urandom(8).hex() + ".txt"))
    for path, kind in ((".git/HEAD", "git_head"), (".git/config", "git_config"),
                       (".hg/requires", "hg_requires"), (".svn/entries", "svn_entries")):
        code, _, data = net.request("GET", urljoin(base, path))
        if code == 200 and data and data != baseline and vcs_match(kind, data) and not vcs_match(kind, baseline):
            emit("vcs_metadata", artifact=kind)


def run(spec, session=None, pause=time.sleep, checkpoint=lambda report: None, **engines):
    if session is None:
        import requests
        session = requests.Session()
    net = Transport(spec, session, pause)
    report = {"profile": spec["module"], "status": "running", "observations": [], "requests": 0, "stop_reason": ""}
    def save():
        report["requests"] = net.requests
        checkpoint(report)
    def emit(kind, **values):
        report["observations"].append({"kind": kind, **values})
        save()
    save()
    try:
        callbacks = {"graphw00f": graph_profile, "corsy": cors_profile, "takeover": takeover_profile,
                     "s3-review": s3_profile, "websocket": websocket_profile, "vcs-artifacts": vcs_profile}
        callbacks[spec["module"]](net, report, emit, **engines)
        if report["status"] == "running":
            report["status"] = "completed"
        if net.truncated:
            report.update(status="partial", stop_reason="response_limit")
    except Stopped as exc:
        report.update(status="partial", stop_reason=str(exc))
    except DNSResolutionFailed:
        report.update(status="partial", stop_reason="dns_inconclusive")
    except Exception:
        report.update(status="failed", stop_reason="engine_error")
    finally:
        session.close()
        save()
    return report


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as source:
        spec = json.load(source)
    output = Path(sys.argv[2])
    def checkpoint(report):
        temporary = output.with_suffix(".tmp")
        temporary.write_text(json.dumps(report), encoding="utf-8")
        temporary.replace(output)
    run(spec, checkpoint=checkpoint)
