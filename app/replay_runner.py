"""Bounded asynchronous replay, running only in the remote scanner subprocess."""
import asyncio
import copy
import json
import logging
import os
import re
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit

import httpx

from .scope import public_host
from .sampling import origin
from .replay_inputs import RaceReplay, NoSQLReplay

class Stopped(Exception):
    pass


def json_value(document, pointer):
    current = document
    for token in pointer.split("/")[1:] if pointer else []:
        token = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]{0,4}", token) is not None and int(token) < len(current):
            current = current[int(token)]
        else:
            raise KeyError
    return current


def fixture(request, field, value):
    result = request.model_dump()
    location = "query" if request.method == "GET" else "json_body"
    result[location][field] = value
    return result


async def default_check(host):
    await asyncio.to_thread(public_host, host, os.environ.get("ALLOW_PRIVATE_TARGETS") == "1")


class ReplayIO:
    def __init__(self, spec, report, save, factory=None, check=default_check, pause=asyncio.sleep):
        self.target, self.scope = spec["target"], origin(spec["target"])
        if self.scope[1] != spec["host"] or self.scope[2] not in (80, 443, 8080):
            raise ValueError("Invalid replay target")
        self.agent, self.report, self.save = spec["agent"], report, save
        self.delay = max(1.0, min(30.0, float(spec["delay"])))
        self.factory = factory or (lambda: httpx.AsyncClient(timeout=8, trust_env=False,
                                               follow_redirects=False, http2=False, verify=True))
        self.check, self.pause = check, pause
        self.limit, self.last = (8 if spec["module"] == "race-replay" else 6), None
        self.count_lock = asyncio.Lock()

    async def rest(self):
        if self.last is not None:
            await self.pause(max(0, self.delay - (time.monotonic() - self.last)))

    async def send(self, request, *, success=None, counter=None, barrier=None):
        target = urljoin(urlsplit(self.target)._replace(path="/", query="", fragment="").geturl(), request["path"])
        if origin(target) != self.scope or request["method"] not in ("GET", "POST"):
            raise Stopped("scope_blocked")
        if barrier is None:
            await self.rest()
        await self.check(self.scope[1])
        async with self.count_lock:
            if self.report["requests"] >= self.limit:
                raise Stopped("request_budget")
            self.report["requests"] += 1
        headers = {"User-Agent": self.agent, "Accept": "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-cache", "Pragma": "no-cache"}
        headers.update(request["headers"])
        async with self.factory() as client:
            if barrier is not None:
                await barrier.wait()
            started = time.monotonic()
            self.last = started
            try:
                async with client.stream(request["method"], target, headers=headers,
                        params=request["query"], json=request["json_body"], follow_redirects=False) as response:
                    status = response.status_code
                    if status == 429:
                        raise Stopped("rate_limited")
                    if 300 <= status < 400:
                        raise Stopped("redirect_not_followed")
                    if status >= 500:
                        raise Stopped("server_error")
                    if response.headers.get("content-encoding", "identity").lower() not in ("", "identity"):
                        raise Stopped("encoded_response")
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        if len(content) + len(chunk) > 65536:
                            raise Stopped("response_limit")
                        content.extend(chunk)
            except Stopped:
                raise
            except httpx.HTTPError as exc:
                raise Stopped("request_failed") from exc
        finished = time.monotonic()
        valid_json = True
        try:
            document = json.loads(content, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        except (ValueError, UnicodeError):
            valid_json, document = False, None
        outcome = {"status": status, "matched": None, "counter": None, "start": started, "finish": finished}
        if success is not None:
            if 400 <= status < 500:
                outcome["matched"] = False
            elif valid_json:
                try:
                    value = json_value(document, success.pointer)
                    outcome["matched"] = type(value) is type(success.equals) and value == success.equals
                except (KeyError, TypeError, IndexError):
                    pass
        if counter is not None and valid_json and 200 <= status < 300:
            try:
                value = json_value(document, counter)
                if type(value) is int and 0 <= value <= 1000000000:
                    outcome["counter"] = value
            except (KeyError, TypeError, IndexError):
                pass
        self.save()
        return outcome


async def counter_value(io, verification, value):
    outcome = await io.send(fixture(verification.request, verification.field, value), counter=verification.pointer)
    if outcome["counter"] is None:
        raise Stopped("counter_unavailable")
    return outcome["counter"]


async def race(io, cfg, report):
    if cfg.verification and await counter_value(io, cfg.verification, cfg.control_value) != 0:
        raise Stopped("control_not_fresh")
    control = []
    for _ in range(2):
        control.append(await io.send(fixture(cfg.request, cfg.field, cfg.control_value), success=cfg.success))
    report["control_statuses"] = [row["status"] for row in control]
    report["control_successes"] = sum(row["matched"] is True for row in control)
    io.save()
    if any(row["matched"] is None for row in control):
        raise Stopped("matcher_unavailable")
    if report["control_successes"] != 1:
        raise Stopped("control_not_single_effect")
    if cfg.verification and await counter_value(io, cfg.verification, cfg.control_value) != 1:
        raise Stopped("control_effect_unconfirmed")
    if cfg.verification and await counter_value(io, cfg.verification, cfg.parallel_value) != 0:
        raise Stopped("parallel_not_fresh")
    await io.rest()
    barrier = asyncio.Barrier(2)
    tasks = [asyncio.create_task(io.send(fixture(cfg.request, cfg.field, cfg.parallel_value),
                                       success=cfg.success, barrier=barrier)) for _ in range(2)]
    try:
        parallel = await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise
    report["parallel_statuses"] = [row["status"] for row in parallel]
    report["parallel_successes"] = sum(row["matched"] is True for row in parallel)
    overlap = max(row["start"] for row in parallel) < min(row["finish"] for row in parallel)
    report["client_overlap"] = overlap
    report["start_gap_ms"] = min(60000, round(abs(parallel[0]["start"] - parallel[1]["start"]) * 1000))
    io.save()
    if any(row["matched"] is None for row in parallel):
        raise Stopped("matcher_unavailable")
    if not overlap:
        raise Stopped("overlap_unconfirmed")
    if cfg.verification:
        after = await counter_value(io, cfg.verification, cfg.parallel_value)
        if after == 0 and report["parallel_successes"]:
            raise Stopped("parallel_effect_unconfirmed")
        report["state_overrun"] = after > 1
        if after > 1:
            report["observations"].append({"kind": "race_state_candidate"})
    elif report["parallel_successes"] == 2:
        report["observations"].append({"kind": "race_response_signal"})


async def nosql(io, cfg, report):
    baseline = cfg.request.query[cfg.field] if cfg.request.method == "GET" else cfg.request.json_body[cfg.field]
    nonce = "asfb_probe_" + secrets.token_urlsafe(18)
    variants = [("baseline", baseline), ("negative_scalar", nonce), ("inert_object", {"asfb_control": nonce}),
                ("eq_baseline", {"$eq": baseline}), ("eq_negative", {"$eq": nonce}), ("ne_negative", {"$ne": nonce})]
    outcomes = {}
    for name, value in variants:
        request = fixture(cfg.request, cfg.field, value)
        if cfg.request.method == "GET" and isinstance(value, dict):
            request["query"].pop(cfg.field)
            for operator, operand in value.items():
                request["query"][cfg.field + "[" + operator + "]"] = operand
        result = await io.send(request, success=cfg.success)
        outcomes[name] = result["matched"]
        report.setdefault("statuses", {})[name] = result["status"]
        report.setdefault("matches", {})[name] = result["matched"]
        io.save()
        if name == "baseline" and result["matched"] is not True:
            raise Stopped("baseline_unconfirmed")
    required = ("negative_scalar", "eq_baseline", "eq_negative", "ne_negative")
    if any(outcomes[name] is None for name in required):
        raise Stopped("matcher_unavailable")
    if (outcomes["negative_scalar"] is False and outcomes["inert_object"] is not True
            and outcomes["eq_baseline"] is True and outcomes["eq_negative"] is False
            and outcomes["ne_negative"] is True):
        report["observations"].append({"kind": "nosql_operator_candidate"})


async def run(spec, factory=None, check=default_check, pause=asyncio.sleep, checkpoint=lambda report: None):
    module = spec["module"]
    report = {"profile": module, "status": "running", "requests": 0, "observations": [], "stop_reason": ""}
    def save():
        checkpoint(copy.deepcopy(report))
    save()
    try:
        cfg = RaceReplay.model_validate(spec["config"]) if module == "race-replay" else NoSQLReplay.model_validate(spec["config"])
        if cfg.target_origin and origin(cfg.target_origin) != origin(spec["target"]):
            report.update(status="skipped", stop_reason="origin_mismatch")
            return report
        io = ReplayIO(spec, report, save, factory, check, pause)
        async with asyncio.timeout(max(1, spec["deadline"] - 5)):
            await (race(io, cfg, report) if module == "race-replay" else nosql(io, cfg, report))
        report["status"] = "completed"
    except Stopped as exc:
        report.update(status="partial", stop_reason=str(exc))
    except TimeoutError:
        report.update(status="partial", stop_reason="deadline")
    except Exception:
        report.update(status="partial" if report["requests"] else "failed", stop_reason="replay_error")
    finally:
        save()
    return report


if __name__ == "__main__":
    logging.disable(logging.CRITICAL)
    output = Path(sys.argv[2])
    def checkpoint(report):
        temporary = output.with_suffix(".tmp")
        temporary.write_text(json.dumps(report), encoding="utf-8")
        temporary.replace(output)
    try:
        spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        asyncio.run(run(spec, checkpoint=checkpoint))
    except Exception:
        checkpoint({"profile": "invalid", "status": "failed", "requests": 0, "observations": [], "stop_reason": "replay_error"})