import asyncio
from unittest.mock import patch

import pytest

from app import config, pipeline


class BufferedProcess:
    """A single communicate reader that has consumed output before blocking."""
    def __init__(self, *, exit_during_kill=False):
        self.returncode = None
        self.started = asyncio.Event()
        self.stopped = asyncio.Event()
        self.reads = 0
        self.reader_cancelled = False
        self.killed = False
        self.exit_during_kill = exit_during_kill

    async def communicate(self):
        self.reads += 1
        self.started.set()
        try:
            await self.stopped.wait()
        except asyncio.CancelledError:
            self.reader_cancelled = True
            raise
        return b"https://example.org/already-read\n", b"provider warning\n"

    def kill(self):
        self.killed = True
        self.returncode = -9
        self.stopped.set()
        if self.exit_during_kill:
            raise ProcessLookupError()


@pytest.mark.parametrize("exit_during_kill", [False, True])
def test_timeout_preserves_original_reader_and_handles_exit_race(exit_during_kill):
    async def scenario():
        process = BufferedProcess(exit_during_kill=exit_during_kill)
        async def spawn(*args, **kwargs):
            return process
        with patch.object(pipeline.asyncio, "create_subprocess_exec", spawn):
            lines, status = await pipeline.execute(["mock-tool"], 0.01)
        assert status == "timeout"
        assert "https://example.org/already-read" in lines
        assert "[stderr] provider warning" in lines
        assert any("partial output retained" in line for line in lines)
        assert process.killed
        assert process.reads == 1
        assert not process.reader_cancelled
    asyncio.run(scenario())


def test_scan_cancellation_kills_process_without_restarting_pipe_reader():
    async def scenario():
        process = BufferedProcess()
        async def spawn(*args, **kwargs):
            return process
        with patch.object(pipeline.asyncio, "create_subprocess_exec", spawn):
            task = asyncio.create_task(pipeline.execute(["mock-tool"], 60))
            await process.started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert process.killed
        assert process.reads == 1
        assert not process.reader_cancelled
    asyncio.run(scenario())


def test_successful_process_honors_configured_output_limit():
    class CompletedProcess:
        returncode = 0
        async def communicate(self):
            return b"one\ntwo\nthree\n", b""
    async def spawn(*args, **kwargs):
        return CompletedProcess()
    with patch.object(pipeline.asyncio, "create_subprocess_exec", spawn), \
         patch.object(config, "PROCESS_OUTPUT_MAX_LINES", 2):
        lines, status = asyncio.run(pipeline.execute(["mock-tool"], 1))
    assert status == "completed"
    assert lines == ["one", "two"]
