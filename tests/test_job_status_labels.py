from pathlib import Path

def test_pending_job_ui_distinguishes_not_started_from_zero_findings():
    source = Path("app/index.html").read_text()
    assert "Not started · queue position " in source
    assert "queuePositions=new Map" in source
    assert "j.status==='queued'?'':'<button" in source

def test_review_ui_explains_skipped_and_clean_empty_output():
    source = Path("app/index.html").read_text()
    assert "Skipped: " in source
    assert "No matching results reported by the module." in source
    assert "No output captured" in source
