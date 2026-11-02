"""Partial Nettacker profile: its HTTP engine and HTTP-status module conditions."""
import asyncio
import json
import sys
from pathlib import Path

import nettacker
import yaml
from nettacker.core.lib import http as engine
from wapiti_guard import validate_public
from urllib.parse import urlsplit


async def bounded_action(action, options):
    async with action(**options) as response:
        data = await response.content.read(524289)
        return {"reason": response.reason, "url": str(response.url),
                "status_code": str(response.status), "content": data[:524288].decode("utf-8", "replace"),
                "headers": {}, "responsetime": 0}


async def inspect(url, agent):
    await validate_public(urlsplit(url).hostname)
    module_path = Path(nettacker.__file__).parent / "modules" / "scan" / "http_status.yaml"
    document = yaml.safe_load(module_path.read_text())
    step = document["payloads"][0]["steps"][0]
    engine.perform_request_action = bounded_action
    response = await engine.send_request(
        {"url": url, "timeout": 5, "allow_redirects": False, "ssl": True,
         "headers": {"User-Agent": agent}}, "get")
    conditions = engine.response_conditions_matched(step, response)
    return {"status": "completed", "status_code": int(response["status_code"]),
            "condition_matched": bool(conditions), "profile": "http_status_scan"}


def main():
    url, output, agent = sys.argv[1:4]
    try:
        result = asyncio.run(asyncio.wait_for(inspect(url, agent), 10))
    except Exception as exc:
        result = {"status": "failed", "error_type": exc.__class__.__name__}
    Path(output).write_text(json.dumps(result), encoding="utf-8")


if __name__ == "__main__":
    main()
