import asyncio
from unittest.mock import patch

from app import main, pipeline


def test_cancel_all_only_affects_current_session_and_drains_owned_queue():
    original_jobs, original_queue = main.jobs, main.queue
    original_tasks = main.active_scan_tasks
    main.jobs = {
        "a": {"id": "a", "owner": "session-a", "status": "queued",
              "stage": "queued", "cancelled": False},
        "b": {"id": "b", "owner": "session-b", "status": "queued",
              "stage": "queued", "cancelled": False}
    }
    main.queue = asyncio.Queue()
    main.active_scan_tasks = {}
    main.queue.put_nowait(("a", None))
    main.queue.put_nowait(("b", None))
    try:
        result = main.cancel_owned_jobs("session-a")
        assert result == {"cancelled_queued": 1, "cancellation_requested_running": 0}
        assert main.jobs["a"]["status"] == "cancelled"
        assert main.jobs["b"]["status"] == "queued"
        assert main.queue.qsize() == 1
        assert main.queue.get_nowait()[0] == "b"
        main.queue.task_done()
    finally:
        main.jobs, main.queue = original_jobs, original_queue
        main.active_scan_tasks = original_tasks


def test_active_scan_cancellation_interrupts_running_stage():
    async def exercise():
        original_jobs, original_queue, original_assets = main.jobs, main.queue, main.assets
        original_tasks = main.active_scan_tasks
        main.jobs, main.assets, main.active_scan_tasks = {}, {}, {}
        main.queue = asyncio.Queue()
        started = asyncio.Event()
        async def never_finishes(*args):
            started.set()
            await asyncio.sleep(600)
        main.assets["unit-target"] = {
            "id": "unit-target", "owner": "session-a",
            "name": "https://example.org", "compatibility": "web"}
        main.jobs["unit-job"] = {
            "id": "unit-job", "owner": "session-a", "asset_id": "unit-target",
            "status": "queued", "stage": "queued", "cancelled": False,
            "alerts": [], "pipeline": {}, "reviews": [], "probes": [],
            "endpoints": [], "progress": 0, "request_count": 0, "error": None}
        spec = main.ScanRequest(asset_id="unit-target", modules=["katana", "httpx"])
        with patch.object(main, "public_host", return_value=None), \
             patch.object(main, "katana", never_finishes):
            worker_task = asyncio.create_task(main.worker())
            try:
                main.queue.put_nowait(("unit-job", spec))
                await asyncio.wait_for(started.wait(), 2)
                result = main.cancel_owned_jobs("session-a")
                assert result["cancellation_requested_running"] == 1
                await asyncio.wait_for(main.queue.join(), 2)
                assert main.jobs["unit-job"]["status"] == "cancelled"
                assert "httpx" not in main.jobs["unit-job"]["pipeline"]
            finally:
                worker_task.cancel()
                try:
                    await worker_task
                except asyncio.CancelledError:
                    pass
                main.jobs, main.queue, main.assets = original_jobs, original_queue, original_assets
                main.active_scan_tasks = original_tasks
    asyncio.run(exercise())


def test_subprocess_terminated_when_stage_task_cancelled():
    async def exercise():
        class FakeProcess:
            def __init__(self):
                self.killed = False
                self.event = asyncio.Event()
                self.returncode = None
            async def communicate(self):
                await self.event.wait()
                return b"", b""
            def kill(self):
                self.killed = True
                self.returncode = -9
                self.event.set()
        p = FakeProcess()
        async def spawn(*args, **kwargs):
            return p
        with patch.object(pipeline.asyncio, "create_subprocess_exec", spawn):
            task = asyncio.create_task(pipeline.execute(["sample"], 30))
            await asyncio.sleep(0)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        assert p.killed is True
    asyncio.run(exercise())


def test_dashboard_has_confirmed_cancel_all_control():
    from pathlib import Path
    src = Path("app/index.html").read_text()
    assert 'id="cancelAllJobs"' in src
    assert "async function cancelAllJobs()" in src
    assert "'/scans/cancel-all'" in src
