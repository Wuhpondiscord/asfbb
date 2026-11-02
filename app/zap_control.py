"""Read-only ZAP passive queue monitoring with conservative completion semantics."""
import asyncio
import time
from urllib.parse import urlsplit


def _task_urls(response):
    if not isinstance(response, dict):
        return None
    tasks = response.get("currentTasks")
    if isinstance(tasks, dict):
        tasks = tasks.get("task") or tasks.get("tasks") or []
    if not isinstance(tasks, list):
        return None
    urls = []
    for item in tasks:
        if not isinstance(item, dict):
            return None
        # ZAP's ApiResponseSet can wrap each task under "currentTasks".
        value = item.get("currentTasks", item)
        if not isinstance(value, dict) or not isinstance(value.get("url"), str):
            return None
        urls.append(value["url"])
    return urls


async def wait_for_passive_queue(client, zap_call, host, *, limit, interval, stall_checks,
                                 timeout_seconds=None, on_progress=None):
    """Wait for the global queue to drain, bounded by both time and poll count.

    A stable record count with a current-host task is still active work. Only
    zero pending records proves drained; a hard deadline remains partial.
    """
    remaining, checks, stable = 0, 0, 0
    last = None
    host_tasks, global_tasks = 0, 0
    stalled, deadline_reached = False, False
    started = time.monotonic()

    async def query(action):
        if timeout_seconds is None:
            return await zap_call(client, "pscan", action, {})
        left = timeout_seconds - (time.monotonic() - started)
        if left <= 0:
            raise TimeoutError
        async with asyncio.timeout(left):
            return await zap_call(client, "pscan", action, {})

    def snapshot():
        return {"remaining": remaining, "checks": checks, "stalled": stalled,
                "host_tasks_running": host_tasks, "global_tasks_running": global_tasks,
                "elapsed_seconds": round(time.monotonic() - started, 2),
                "deadline_seconds": timeout_seconds, "deadline_reached": deadline_reached}

    for _ in range(max(1, limit)):
        try:
            data = await query("view/recordsToScan")
        except TimeoutError:
            if timeout_seconds is None:
                raise
            deadline_reached = True
            # A timeout before the first successful read cannot prove a clean queue.
            remaining = remaining if checks else -1
            break
        remaining = max(0, int(data.get("recordsToScan", 0)))
        checks += 1
        if remaining == 0:
            host_tasks = global_tasks = 0
            break
        stable = stable + 1 if remaining == last else 0
        last = remaining
        if stable >= max(1, stall_checks):
            try:
                tasks = _task_urls(await query("view/currentTasks"))
            except Exception:
                tasks = None
            if tasks is not None:
                global_tasks = len(tasks)
                host_tasks = 0
                for u in tasks:
                    try:
                        host_tasks += int(urlsplit(u).hostname == host)
                    except ValueError:
                        host_tasks += 1
                if host_tasks == 0:
                    stalled = True
                    break
        if on_progress is not None and (checks == 1 or checks % 10 == 0):
            on_progress(snapshot())
        left = (timeout_seconds - (time.monotonic() - started)
                if timeout_seconds is not None else interval)
        if left <= 0 and timeout_seconds is not None:
            deadline_reached = True
            break
        await asyncio.sleep(min(interval, max(0, left)))
    if remaining:
        deadline_reached = deadline_reached or (
            timeout_seconds is not None and time.monotonic() - started >= timeout_seconds)
        suffix = ("; no current-host task reported and backlog unchanged" if stalled else
                  "; passive wait budget reached; scan still processing or queued")
        reason = (f"ZAP global passive queue still has {remaining if checks else 'an unknown number of'} pending records "
                  f"after {checks} checks ({time.monotonic() - started:.1f}s){suffix}. "
                  "Partial alerts collected; passive coverage is incomplete.")
    else:
        reason = ""
    return {**snapshot(), "reason": reason}
