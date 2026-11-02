"""Small keyless garak REST profile; no local model, GPU or provider SDK required."""
import ipaddress
import json
import socket
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

import requests


def origin(value):
    p = urlsplit(str(value))
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise ValueError("Invalid target origin")
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


def guarded_send(original, target, delay):
    count, last = 0, None
    expected = origin(target)
    def send(session, request, **kwargs):
        nonlocal count, last
        if request.url != target or origin(request.url) != expected or request.method != "POST" or count >= 2:
            raise requests.RequestException("ASFB REST guard blocked request")
        addresses = socket.getaddrinfo(expected[1], None, proto=socket.IPPROTO_TCP)
        if not addresses or any(not ipaddress.ip_address(row[4][0]).is_global for row in addresses):
            raise requests.RequestException("ASFB REST DNS validation failed")
        if last is not None:
            time.sleep(max(0.0, max(1.0, delay) - (time.monotonic() - last)))
        last = time.monotonic()
        count += 1
        kwargs.update(allow_redirects=False, stream=True, timeout=5)
        session.trust_env = False
        response = original(session, request, **kwargs)
        try:
            chunks, size = [], 0
            for chunk in response.iter_content(16384):
                size += len(chunk)
                if size > 65536:
                    raise requests.RequestException("ASFB REST response limit reached")
                chunks.append(chunk)
            response._content = b"".join(chunks)
            response._content_consumed = True
        finally:
            response.close()
        return response
    return send


def profile(settings):
    from garak import _config
    from garak.generators.rest import RestGenerator
    from garak.attempt import Attempt, Conversation, Message, Turn
    from garak.probes.av_spam_scanning import REPEAT_PROMPTS, EICAR_SIGNATURE
    from garak.detectors.knownbadsignatures import EICAR
    _config.system.verbose = 0
    _config.system.parallel_requests = 1
    _config.system.max_workers = 1
    _config.run.seed = None
    _config.run.deprefix = False
    options = {"uri": settings["url"], "key_env_var": "", "api_key": "", "method": "post",
               "headers": {"Content-Type": "application/json"},
               "req_template_json_object": {settings["prompt_field"]: "$INPUT"},
               "response_json": True, "response_json_field": settings["response_field"],
               "request_timeout": 5, "ratelimit_codes": [], "skip_codes": [], "verify_ssl": True}
    generator = RestGenerator(config_root={"generators": {"rest": {"RestGenerator": options}}})
    generator.retry_5xx = False
    detector = EICAR(config_root={})
    tests = []
    for text in REPEAT_PROMPTS[:2]:
        conversation = Conversation(turns=[Turn(role="user", content=Message(text=text.replace("{signature}", EICAR_SIGNATURE), lang="en"))])
        outputs = generator.generate(conversation, 1)
        if not outputs or outputs[0] is None:
            raise ValueError("LLM response did not contain the configured text field")
        attempt = Attempt(prompt=conversation)
        attempt.outputs = outputs
        scores = list(detector.detect(attempt))
        tests.append({"probe": "av_spam_scanning.EICAR", "matched": any(v is not None and v > 0 for v in scores)})
    return {"status": "completed", "tests": tests}


def main():
    settings = json.loads(Path(sys.argv[1]).read_text())
    requests.Session.send = guarded_send(requests.Session.send, settings["url"], settings["delay"])
    try:
        result = profile(settings)
    except Exception as exc:
        result = {"status": "failed", "tests": [], "error_type": exc.__class__.__name__}
    Path(sys.argv[2]).write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main()
