from pathlib import Path
def test_report_refresh_can_be_paused_while_copying():
    page=Path("app/index.html").read_text()
    for item in ("toggleAutoRefresh()","hasActiveTextSelection()","keepReportStable()",
                 "async function loadScans(force=false)","async function loadLogs(force=false)",
                 "loadScans(true)"):
        assert item in page
