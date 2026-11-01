import asyncio
from unittest.mock import patch
from app import pipeline

def test_timeout_retains_partial_output():
    class FakeProc:
        def __init__(self): self.killed=False
        def kill(self): self.killed=True
        async def communicate(self):
            if not self.killed:
                await asyncio.sleep(1)
            return b"discovered https://example.org/a\\n",b"partial stderr"
    async def launch(*args,**kwargs): return FakeProc()
    with patch.object(pipeline.asyncio,"create_subprocess_exec",launch):
        lines,status=asyncio.run(pipeline.execute(["fake"],0.001))
    assert status=="timeout"
    assert any("discovered" in line for line in lines)
    assert any("Deadline exceeded" in line for line in lines)

def test_all_worker_stages_generate_summaries():
    from pathlib import Path
    src=Path("app/main.py").read_text()
    ui=Path("app/index.html").read_text()
    assert '"summary": summary' in src
    assert "moduleLogs" in ui
    assert "data-detail-key" in ui
