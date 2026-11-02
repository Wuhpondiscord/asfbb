"""Read-only ZAP passive queue monitoring with conservative completion semantics."""
import asyncio
from urllib.parse import urlsplit


def _task_urls(response):
    if not isinstance(response, dict):
        return None
    tasks = response.get("currentTasks")
    if isinstance(tasks, dict):
        tasks = tasks.get("task") or tasks.get("tasks") or []
    if not isinstance(tasks, list):
        return None
    return [t.get("url", "") for t in tasks if isinstance(t, dict)]


async def wait_for_passive_queue(client, zap_call, host, *, limit, interval, stall_checks):
    """Poll ZAP's global queue. Only zero pending records proves drained.

    currentTasks reports active rules/URLs, but cannot prove that unstarted
    queued records belong to another host. Never declare complete if pending.
    """
    remaining, checks, stable = 0, 0, 0
    last = None
    host_tasks, global_tasks = 0, 0
    stalled = False
    for _ in range(max(1, limit)):
        data = await zap_call(client, "pscan", "view/recordsToScan", {})
        remaining = max(0, int(data.get("recordsToScan", 0)))
        checks += 1
        if remaining == 0:
            break
        stable = stable + 1 if remaining == last else 0
        last = remaining
        if stable >= max(1, stall_checks):
            try:
                tasks = _task_urls(await zap_call(
                    client, "pscan", "view/currentTasks", {}))
            except Exception:
                tasks = None
            if tasks is not None:
                global_tasks = len(tasks)
                host_tasks = sum(
                    1 for u in tasks
                    if isinstance(u, str) and urlsplit(u).hostname == host)
                if host_tasks == 0:
                    stalled = True
                    break
        await asyncio.sleep(interval)
    if remaining:
        suffix = ("; no current-host task reported and backlog unchanged"
                  if stalled else "; scan still processing or queued")
        reason = (f"ZAP global passive queue still has {remaining} pending records "
                  f"after {checks} checks{suffix}. Some alerts may arrive later.")
    else:
        reason = ""
    return {
        "remaining": remaining, "checks": checks, "stalled": stalled,
        "host_tasks_running": host_tasks, "global_tasks_running": global_tasks,
        "reason": reason,
    }
