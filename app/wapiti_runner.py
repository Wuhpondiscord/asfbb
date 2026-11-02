"""Run the pinned Wapiti CLI with the ASFB origin/method/budget guard."""
import json
import sys
from pathlib import Path

import httpx
from wapiti_guard import RequestGuard


def pop_option(name, default=None):
    if name not in sys.argv:
        return default
    index = sys.argv.index(name)
    value = sys.argv[index + 1]
    del sys.argv[index:index + 2]
    return value


def main():
    stats = pop_option("--asfb-stats")
    delay = float(pop_option("--asfb-delay", "1.5"))
    budget = int(pop_option("--asfb-budget", "12"))
    guard = None
    if "-u" in sys.argv:
        target = sys.argv[sys.argv.index("-u") + 1]
        guard = RequestGuard(target, delay, budget)
        httpx.AsyncClient.send = guard.wrap(httpx.AsyncClient.send)
    try:
        from wapitiCore.main.wapiti import wapiti_asyncio_wrapper
        wapiti_asyncio_wrapper()
    finally:
        if stats and guard:
            Path(stats).write_text(json.dumps(guard.report()), encoding="utf-8")


if __name__ == "__main__":
    main()
