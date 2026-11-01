import asyncio
from unittest.mock import patch
from app import main
from test_worker_pipeline import run_job

def test_one_module_exception_does_not_discard_subsequent_stages():
    execute_job, job = run_job(["katana","httpx"])
    async def broken(*args):
        raise RuntimeError("test stage failure")
    async def safe(*args):
        return {"status":"completed","probes":[]}
    with patch.object(main,"public_host",return_value=None), \
         patch.object(main,"katana",broken), patch.object(main,"probe",safe):
        asyncio.run(execute_job())
    assert job["status"] == "partial"
    assert job["pipeline"]["katana"] == "failed"
    assert job["pipeline"]["httpx"] == "completed"
    assert job["stage_details"]["katana"]["reason"].startswith("Module exception")
    assert any(row["event"] == "stage_exception" for row in main.scan_events)
