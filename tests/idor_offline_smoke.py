"""Run on GitHub inside the built HF container, using the real upstream engine."""
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, "/app")
from app import idor_runner as runner

checker = runner.load_checker()
assert checker.__class__.__name__ == "IDORChecker"
base = json.dumps({"id": "baseline-private", "owner": "first", "email": "private@example.invalid"})
other = json.dumps({"id": "reference-private", "owner": "second", "email": "private@example.invalid"})
metrics, candidate = runner.compare(checker, base, other, 200)
assert candidate and metrics["structure_similarity"] == 1
assert not runner.compare(checker, base, base, 200)[1]
assert not runner.compare(checker, base, other, 403)[1]
runner.compare(checker, '[1,2]', '[1,3]', 200)  # Upstream methods otherwise assume JSON objects.


class Response:
    status_code = 200
    def __init__(self, text, status=200):
        self.content = text.encode()
        self.status_code = status
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def iter_content(self, size):
        yield self.content


class Session:
    trust_env = True
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
    def get(self, target, **kwargs):
        assert target == "https://example.org/api/item"
        assert kwargs["allow_redirects"] is False and kwargs["stream"] is True
        assert kwargs["timeout"] == (5, 8)
        self.calls.append(kwargs)
        return next(self.responses)


spec = {"target": "https://example.org", "host": "example.org", "agent": "CI-offline", "delay": 1,
        "inputs": {"idor_path": "/api/item", "idor_parameter": "id",
                   "idor_baseline": "baseline-private", "idor_values": ["reference-private"]}}
session = Session([Response(base), Response(other)])
with patch.object(runner, "public_host") as public_host:
    report = runner.run(spec, checker, session, pause=lambda _: None)
assert len(session.calls) == 2 and public_host.call_count == 2
assert session.trust_env is False
assert report["comparisons"][0]["candidate"]
assert all(value not in json.dumps(report) for value in ("baseline-private", "reference-private", "private@example.invalid"))
session = Session([Response("", 302)])
with patch.object(runner, "public_host"):
    report = runner.run(spec, checker, session, pause=lambda _: None)
assert report["status"] == "skipped" and len(session.calls) == 1
session = Session([Response(base), Response("x" * 65537)])
with patch.object(runner, "public_host"):
    report = runner.run(spec, checker, session, pause=lambda _: None)
assert report["status"] == "partial" and not report["comparisons"]
print("IDOR-Forge installed engine, GET guard, redaction and size-limit smoke passed")
