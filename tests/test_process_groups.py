import asyncio
import os
import signal
from unittest.mock import patch

import pytest

from app import pipeline


@pytest.mark.skipif(os.name != "posix", reason="HF process-group cleanup is POSIX")
def test_shell_timeout_kills_entire_group():
    async def scenario():
        class Process:
            pid = 123456
            returncode = None
            def __init__(self): self.done = asyncio.Event()
            async def communicate(self):
                await self.done.wait()
                return b"partial", b""
            def kill(self): raise AssertionError("Only killing the shell leaves children alive")
        process = Process()
        async def spawn(*args, **kwargs):
            assert kwargs["start_new_session"] is True
            return process
        def kill_group(pid, sig):
            assert pid == process.pid and sig == signal.SIGKILL
            process.returncode = -9
            process.done.set()
        with patch.object(pipeline.asyncio, "create_subprocess_exec", spawn), \
             patch.object(pipeline.os, "killpg", kill_group):
            lines, status = await pipeline.execute(["mock-shell"], 0.01)
        assert status == "timeout"
        assert "partial" in lines
    asyncio.run(scenario())
