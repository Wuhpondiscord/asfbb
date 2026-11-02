"""Installed protocol engines and DNS API with mocked I/O; container has no network."""
import base64
import hashlib
import json
import socket
import sys
from types import SimpleNamespace
from unittest.mock import patch

import requests

sys.path.insert(0, "/app")
from app import protocol_runner as engine


class Session:
    def __init__(self, handler):
        self.handler, self.calls, self.cookies = handler, [], requests.cookies.RequestsCookieJar()
    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        assert kwargs["verify"] is True and kwargs["allow_redirects"] is False
        assert "Authorization" not in kwargs["headers"] and "Cookie" not in kwargs["headers"]
        code, headers, body = self.handler(method, url, kwargs)
        response = requests.Response()
        response.status_code, response.url = code, url
        response.headers.update(headers)
        response._content, response._content_consumed = body, True
        return response
    def close(self): pass


def run(module, target, handler, **options):
    session = Session(handler)
    cfg = {"module": module, "target": target, "host": engine.origin(target)[1], "agent": "Test", "delay": 1}
    with patch("app.protocol_runner.public_host"), patch.object(socket.socket, "connect", side_effect=AssertionError("Network forbidden")):
        report = engine.run(cfg, session, pause=lambda seconds: None, **options)
    assert report["status"] == "completed", (module, report)
    assert "fixture-private" not in json.dumps(report), report
    return report, session


def graph(method, url, kwargs):
    query = kwargs["json"]["query"] if method == "POST" else kwargs["params"]["query"]
    assert not any(word in query.lower() for word in ("mutation", "subscription", "fragment"))
    if "__schema" in query:
        result = {"data": {"__schema": {"queryType": {"name": "fixture-private-schema"}}}}
    else:
        result = {"data": {"__typename": "Query"}, "extensions": {"inigo": {}}}
    return 200, {}, json.dumps(result).encode()


report, session = run("graphw00f", "https://example.org/graphql", graph)
assert any(row.get("engine") == "inigo" for row in report["observations"]), report
assert len(session.calls) == 2

def cors(method, url, kwargs):
    assert method == "GET"
    return 200, {"Access-Control-Allow-Origin": kwargs["headers"]["Origin"],
                 "Access-Control-Allow-Credentials": "true"}, b""
report, _ = run("corsy", "https://example.org/", cors)
assert report["observations"][0]["category"] == "origin reflected", report
assert report["observations"][0]["credential_candidate"] is True, report
report, _ = run("corsy", "https://example.org/", lambda *args: (
    200, {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}, b""))
assert report["observations"][0]["category"] == "wildcard value", report
assert report["observations"][0]["credential_candidate"] is False, report

report, _ = run("corsy", "https://example.org/", lambda method, url, kwargs: (
    200, {"Access-Control-Allow-Origin": kwargs["headers"]["Origin"], "Access-Control-Allow-Credentials": "TRUE"}, b""))
assert report["observations"][0]["credential_candidate"] is False, report

import dns.message
import dns.name
import dns.rcode
import dns.resolver
import dns.rrset
class Resolver:
    def resolve(self, host, kind, **kwargs):
        qname = dns.name.from_text(host)
        response = dns.message.make_response(dns.message.make_query(qname, kind))
        response.set_rcode(dns.rcode.NXDOMAIN)
        response.answer.append(dns.rrset.from_text(host, 60, "IN", "CNAME", "missing.azurewebsites.net."))
        raise dns.resolver.NXDOMAIN(qnames=[qname], responses={qname: response})
state = engine.dns_state("example.org", Resolver())
assert state["aliases"] == ["missing.azurewebsites.net"] and state["nxdomain"], state
report, session = run("takeover", "https://example.org/", lambda *args: (_ for _ in ()).throw(AssertionError("No HTTP")),
                      resolve=lambda host: state)
assert report["observations"][0]["provider"] == "Microsoft Azure", report
assert not session.calls

class NoAnswerResolver:
    def resolve(self, host, kind, **kwargs):
        if host == "example.org":
            return [SimpleNamespace(target="existing.azurewebsites.net.")]
        return []
assert not engine.dns_state("example.org", NoAnswerResolver())["nxdomain"]


def s3(method, url, kwargs):
    assert method == "GET"
    if "acl" in kwargs["params"]:
        return 200, {}, b'<AccessControlPolicy><Owner><ID>fixture-private-owner</ID></Owner><AccessControlList><Grant><Grantee><URI>http://acs.amazonaws.com/groups/global/AllUsers</URI></Grantee><Permission>WRITE</Permission></Grant></AccessControlList></AccessControlPolicy>'
    assert kwargs["params"] == {"list-type": "2", "max-keys": "0"}
    return 200, {}, b'<ListBucketResult><Name>unit-bucket</Name><KeyCount>0</KeyCount></ListBucketResult>'
report, session = run("s3-review", "https://unit-bucket.s3.amazonaws.com/", s3)
assert any(row.get("permission") == "WRITE" for row in report["observations"]), report
assert len(session.calls) == 2

def websocket(method, url, kwargs):
    key = kwargs["headers"]["Sec-WebSocket-Key"]
    accept = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
    return 101, {"Upgrade": "websocket", "Connection": "Upgrade", "Sec-WebSocket-Accept": accept}, b""
report, session = run("websocket", "https://example.org/ws", websocket)
assert {row["kind"] for row in report["observations"]} == {"websocket_present", "websocket_cross_origin"}, report
assert len(session.calls) == 2

def vcs(method, url, kwargs):
    if url.endswith(".git/config"):
        return 200, {}, b'[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = fixture-private-value\n'
    return 404, {}, b"missing"
report, session = run("vcs-artifacts", "https://example.org/", vcs)
assert report["observations"] == [{"kind": "vcs_metadata", "artifact": "git_config"}], report
assert len(session.calls) == 5
print("Protocol installed-engine smoke passed: native graphw00f/Corsy, pinned takeover data, NXDOMAIN/NoAnswer, S3, WebSocket and VCS metadata; network disabled")
