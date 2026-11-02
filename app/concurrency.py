"""Bounded job scheduling and shared-resource gates for the HF process."""
import asyncio
import time
import weakref
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from . import config

_loop_resources = weakref.WeakKeyDictionary()
MODULE_RESOURCES = {"zap-passive": "zap-daemon", "depscan": "dependency-cache",
                    "trivy": "dependency-cache"}


def resource_lock(name):
    loop = asyncio.get_running_loop()
    locks = _loop_resources.setdefault(loop, {})
    return locks.setdefault(name, asyncio.Lock())


@asynccontextmanager
async def module_slot(module, job, record, enabled=True):
    name = MODULE_RESOURCES.get(module)
    if name is None or not enabled:
        yield
        return
    lock = resource_lock(name)
    started = time.monotonic()
    waited = lock.locked()
    if waited:
        job["waiting_for"] = name
        job["stage"] = module
        record(job, "resource_wait", module=module, resource=name,
               reason="Waiting for shared " + name + " slot")
    try:
        await lock.acquire()
    finally:
        job.pop("waiting_for", None)
    try:
        if waited:
            record(job, "resource_acquired", module=module, resource=name,
                   elapsed_ms=round((time.monotonic() - started) * 1000))
        yield
    finally:
        lock.release()


def job_host(job, identifier):
    try:
        return (urlsplit(job.get("target", "")).hostname or
                str(job.get("asset_id") or identifier)).lower().rstrip(".")
    except ValueError:
        return identifier


def blocked_reason(job, spec, running):
    if len(running) >= config.PARALLEL_JOBS_MAX:
        return "Space concurrency limit"
    host = job_host(job, job["id"])
    if any(item["host"] == host for item in running.values()):
        return "Another endpoint on this hostname is running"
    owned = [item for item in running.values() if item["owner"] == job.get("owner")]
    limit = min([spec.options.parallel_jobs] + [item["limit"] for item in owned])
    if len(owned) >= limit:
        return "Session concurrency limit (" + str(limit) + ")"
    return ""


async def dispatch(work_queue, jobs, active_tasks, run_job, record):
    running = {}
    pending = None
    try:
        while True:
            for identifier, item in list(running.items()):
                if not item["task"].done():
                    continue
                try:
                    item["task"].result()
                except asyncio.CancelledError:
                    pass  # Individual job cancellation must not stop the dispatcher.
                except Exception as exc:
                    job = jobs.get(identifier)
                    if job:
                        job.update(status="failed", stage="failed", error=type(exc).__name__)
                        record(job, "failed", error_type=type(exc).__name__)
                finally:
                    running.pop(identifier, None)
                    active_tasks.pop(identifier, None)
                    work_queue.task_done()
            # Inspect the bounded queue so one busy hostname does not block
            # unrelated hosts. Requeue with balanced unfinished-task accounting.
            for _ in range(work_queue.qsize() + (pending is not None)):
                if pending is not None:
                    identifier, spec = pending
                    pending = None
                else:
                    identifier, spec = work_queue.get_nowait()
                job = jobs.get(identifier)
                if not job or job.get("cancelled") or job.get("status") != "queued":
                    work_queue.task_done()
                    continue
                reason = blocked_reason(job, spec, running)
                if reason:
                    if job.get("queue_reason") != reason:
                        job["queue_reason"] = reason
                        record(job, "queue_wait", reason=reason)
                    work_queue.put_nowait((identifier, spec))
                    work_queue.task_done()
                    continue
                job.pop("queue_reason", None)
                task = asyncio.create_task(run_job(identifier, spec))
                active_tasks[identifier] = task
                running[identifier] = {"task": task, "host": job_host(job, identifier),
                                       "owner": job.get("owner"),
                                       "limit": spec.options.parallel_jobs}
            if running:
                await asyncio.wait([item["task"] for item in running.values()],
                                   timeout=0.2, return_when=asyncio.FIRST_COMPLETED)
            else:
                # Keep the first item at the front when waking from idle.
                # Requeueing it here rotates the first submitted target behind
                # the rest of a batch before admission checks even run.
                pending = await work_queue.get()
    finally:
        tasks = [item["task"] for item in running.values()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for identifier in running:
            active_tasks.pop(identifier, None)
            work_queue.task_done()
