import asyncio
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from app import main
from app import concurrency as scheduling


class Harness:
    def __init__(self, limits, hosts=None, owners=None):
        hosts = hosts or ["host" + str(i) + ".example.org" for i in range(len(limits))]
        owners = owners or ["owner"] * len(limits)
        self.jobs, self.specs, self.tasks = {}, {}, {}
        self.queue, self.started = asyncio.Queue(), asyncio.Queue()
        self.release = {}
        self.peak = self.current = 0
        self.events = []
        for i, (limit, host, owner) in enumerate(zip(limits, hosts, owners)):
            key = str(i)
            self.jobs[key] = {"id": key, "owner": owner, "target": "https://" + host,
                              "status": "queued", "cancelled": False}
            self.specs[key] = main.ScanRequest(asset_id=key, modules=["httpx"],
                                             options=main.PipelineOptions(parallel_jobs=limit))
            self.release[key] = asyncio.Event()
            self.queue.put_nowait((key, self.specs[key]))

    async def run(self, key, spec):
        self.current += 1
        self.peak = max(self.peak, self.current)
        self.jobs[key]["status"] = "running"
        self.started.put_nowait(key)
        try:
            await self.release[key].wait()
            self.jobs[key]["status"] = "completed"
        except asyncio.CancelledError:
            self.jobs[key]["status"] = "cancelled"
            raise
        finally:
            self.current -= 1

    def record(self, job, event, **details):
        self.events.append((job["id"], event, details))

    def start(self):
        self.worker = asyncio.create_task(scheduling.dispatch(
            self.queue, self.jobs, self.tasks, self.run, self.record))

    async def next(self):
        return await asyncio.wait_for(self.started.get(), 2)

    async def stop(self):
        for event in self.release.values():
            event.set()
        await asyncio.wait_for(self.queue.join(), 2)
        self.worker.cancel()
        await asyncio.gather(self.worker, return_exceptions=True)
        assert not self.tasks


def test_default_sequential_and_server_bounds():
    assert main.PipelineOptions().parallel_jobs == 1
    for value in (0, -1, 4, 100):
        with pytest.raises(ValidationError):
            main.PipelineOptions(parallel_jobs=value)
    async def exercise():
        h = Harness([1, 1, 1])
        h.start()
        try:
            assert await h.next() == "0"
            assert h.jobs["1"]["status"] == "queued"
            assert "Session concurrency limit" in h.jobs["1"]["queue_reason"]
            h.release["0"].set()
            assert await h.next() == "1"
            h.release["1"].set()
            assert await h.next() == "2"
            assert h.peak == 1
        finally:
            await h.stop()
    asyncio.run(exercise())


@pytest.mark.parametrize("limit", [2, 3])
def test_opt_in_jobs_really_overlap_with_a_bounded_peak(limit):
    async def exercise():
        h = Harness([limit] * 5)
        h.start()
        try:
            first = {await h.next() for _ in range(limit)}
            assert first == {str(i) for i in range(limit)}
            assert h.current == limit
            assert h.jobs[str(limit)]["status"] == "queued"
            h.release["0"].set()
            assert await h.next() == str(limit)
            assert h.peak == limit
        finally:
            await h.stop()
    asyncio.run(exercise())


def test_same_host_is_serial_but_does_not_block_other_hosts():
    async def exercise():
        h = Harness([3, 3, 3], ["same.example.org", "same.example.org", "other.example.org"])
        h.start()
        try:
            assert {await h.next(), await h.next()} == {"0", "2"}
            assert "hostname" in h.jobs["1"]["queue_reason"]
            assert h.jobs["1"]["status"] == "queued"
            h.release["0"].set()
            assert await h.next() == "1"
            assert h.jobs["2"]["status"] == "running"
        finally:
            await h.stop()
    asyncio.run(exercise())


def test_global_cap_applies_across_sessions_and_mixed_limits_are_respected():
    async def exercise():
        h = Harness([3] * 5, owners=["a", "b", "c", "d", "e"])
        h.start()
        try:
            assert {await h.next() for _ in range(3)} == {"0", "1", "2"}
            assert h.jobs["3"]["queue_reason"] == "Space concurrency limit"
            assert h.peak == 3
        finally:
            await h.stop()
        h = Harness([1, 3, 3])
        h.start()
        try:
            assert await h.next() == "0"
            assert h.jobs["1"]["status"] == "queued"
            h.release["0"].set()
            assert {await h.next(), await h.next()} == {"1", "2"}
            assert h.peak == 2
        finally:
            await h.stop()
    asyncio.run(exercise())


def test_cancelling_one_running_job_frees_a_slot_without_stopping_others():
    async def exercise():
        h = Harness([2] * 3)
        h.start()
        try:
            assert {await h.next(), await h.next()} == {"0", "1"}
            h.tasks["0"].cancel()
            assert await h.next() == "2"
            assert h.jobs["0"]["status"] == "cancelled"
            assert h.jobs["1"]["status"] == "running"
            assert not h.tasks["1"].cancelled()
        finally:
            await h.stop()
    asyncio.run(exercise())


def test_dispatcher_shutdown_waits_for_all_running_jobs_to_stop():
    async def exercise():
        h = Harness([3] * 3)
        h.start()
        for _ in range(3):
            await h.next()
        h.worker.cancel()
        await asyncio.gather(h.worker, return_exceptions=True)
        await asyncio.wait_for(h.queue.join(), 2)
        assert h.current == 0 and not h.tasks
        assert all(job["status"] == "cancelled" for job in h.jobs.values())
    asyncio.run(exercise())


def test_cancelled_resource_waiter_does_not_release_another_jobs_lock():
    async def exercise():
        acquired, waiting = asyncio.Event(), asyncio.Event()
        job = {"id": "waiter"}
        events = []
        def record(job, event, **details):
            events.append(event)
            if event == "resource_wait":
                waiting.set()
        async def waiter():
            async with scheduling.module_slot("zap-passive", job, record):
                acquired.set()
        lock = scheduling.resource_lock("zap-daemon")
        await lock.acquire()
        task = asyncio.create_task(waiter())
        await asyncio.wait_for(waiting.wait(), 2)
        assert job["waiting_for"] == "zap-daemon"
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        assert lock.locked() and not acquired.is_set()
        assert "waiting_for" not in job
        lock.release()
        async with scheduling.module_slot("zap-passive", job, record):
            assert lock.locked()
        assert not lock.locked()
    asyncio.run(exercise())


def test_shared_dependency_cache_stages_are_serialized():
    async def exercise():
        release, entered, waiting = asyncio.Event(), asyncio.Event(), asyncio.Event()
        def record(job, event, **details):
            if event == "resource_wait":
                waiting.set()
        async def first():
            async with scheduling.module_slot("depscan", {}, record):
                entered.set()
                await release.wait()
        second_entered = asyncio.Event()
        async def second():
            async with scheduling.module_slot("trivy", {}, record):
                second_entered.set()
        a = asyncio.create_task(first())
        await asyncio.wait_for(entered.wait(), 2)
        b = asyncio.create_task(second())
        await asyncio.wait_for(waiting.wait(), 2)
        assert not second_entered.is_set()
        release.set()
        await asyncio.wait_for(asyncio.gather(a, b), 2)
        assert second_entered.is_set()
    asyncio.run(exercise())


def test_cancel_queue_requeue_accounting_does_not_leave_join_hanging():
    async def exercise():
        work = asyncio.Queue()
        jobs = {"a": {"id": "a", "owner": "a", "status": "queued", "cancelled": False},
                "b": {"id": "b", "owner": "b", "status": "queued", "cancelled": False}}
        work.put_nowait(("a", None))
        work.put_nowait(("b", None))
        with patch.object(main, "queue", work), patch.object(main, "jobs", jobs):
            main.cancel_owned_jobs("a")
        assert work.get_nowait()[0] == "b"
        work.task_done()
        await asyncio.wait_for(work.join(), 2)
    asyncio.run(exercise())


def test_parallel_zap_jobs_reset_fetch_and_collect_under_one_exclusive_gate():
    async def exercise():
        hosts = ["alpha.example.org", "beta.example.org"]
        specs, jobs, assets, work = {}, {}, {}, asyncio.Queue()
        for i, host in enumerate(hosts):
            key = str(i)
            assets[key] = {"id": key, "name": "https://" + host, "compatibility": "web"}
            specs[key] = main.ScanRequest(asset_id=key, modules=["zap-passive"],
                                          options=main.PipelineOptions(parallel_jobs=2))
            jobs[key] = {"id": key, "owner": "test", "asset_id": key, "target": "https://" + host,
                         "status": "queued", "cancelled": False, "alerts": [], "pipeline": {},
                         "reviews": [], "probes": [], "endpoints": [], "progress": 0,
                         "request_count": 0, "error": None}
            work.put_nowait((key, specs[key]))
        order, tasks = [], {}
        fetched, waiting, release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        def record(job, event, **details):
            if event == "resource_wait":
                waiting.set()
        class Response:
            status_code = 200
        class Client:
            async def __aenter__(self): return self
            async def __aexit__(self, *args): pass
            async def get(self, url, **kwargs):
                order.append("fetch:" + url)
                if url.endswith(hosts[0]):
                    fetched.set()
                    await release.wait()
                return Response()
        async def zap_call(client, component, action, params=None):
            if action == "action/newSession":
                order.append("reset")
            if action == "view/alerts":
                order.append("alerts:" + params["baseurl"])
                return {"alerts": []}
            return {}
        async def drained(*args, **kwargs):
            return {"remaining": 0, "checks": 1, "reason": "", "stalled": False,
                    "host_tasks_running": 0, "global_tasks_running": 0}
        async def no_sleep(*args): pass
        with patch.object(main, "jobs", jobs), patch.object(main, "assets", assets), \
             patch.object(main, "queue", work), patch.object(main, "active_scan_tasks", tasks), \
             patch.object(main, "public_host"), patch.object(main, "log_event", record), \
             patch.object(main, "zap_call", zap_call), patch.object(main.httpx, "AsyncClient", return_value=Client()), \
             patch("app.zap_control.wait_for_passive_queue", drained), patch.object(main.asyncio, "sleep", no_sleep):
            worker = asyncio.create_task(main.worker())
            try:
                await asyncio.wait_for(fetched.wait(), 2)
                await asyncio.wait_for(waiting.wait(), 2)
                assert order == ["reset", "fetch:https://" + hosts[0]]
                release.set()
                await asyncio.wait_for(work.join(), 2)
                assert order == ["reset", "fetch:https://" + hosts[0], "alerts:https://" + hosts[0] + "/",
                                 "reset", "fetch:https://" + hosts[1], "alerts:https://" + hosts[1] + "/"]
                assert all(job["status"] == "completed" for job in jobs.values())
            finally:
                worker.cancel()
                await asyncio.gather(worker, return_exceptions=True)
    asyncio.run(exercise())

def test_inapplicable_database_modules_do_not_wait_for_a_cache_slot():
    async def exercise():
        lock = scheduling.resource_lock("dependency-cache")
        await lock.acquire()
        try:
            async with scheduling.module_slot("trivy", {}, lambda *a, **kw: None, enabled=False):
                assert lock.locked()
        finally:
            lock.release()
    asyncio.run(exercise())
