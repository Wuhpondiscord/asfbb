from pathlib import Path

def test_file_exposure_panel_uses_tool_reported_candidates_only():
    text=Path("app/index.html").read_text()
    assert 'id="fileExposurePanel"' in text
    assert "potentialFileExposure ||= !!a.potential_file_exposure" in text
    assert "findings.filter(f=>f.potentialFileExposure)" in text
    assert "Tool-reported candidates, not confirmed vulnerabilities" in text
    assert "Copy URL" in text

def test_findings_detail_expansion_survives_render():
    text=Path("app/index.html").read_text()
    assert "existingFindOpen.has(f.url+'|'+f.name)" in text
    assert "data-find-key=" in text
