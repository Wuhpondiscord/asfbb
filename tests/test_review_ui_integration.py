from pathlib import Path

def test_review_results_show_tool_source_not_only_zap():
    src=Path("app/index.html").read_text()
    assert 'esc(f.sources.join(", "))' in src
    assert "Discovered parameters" in src

def test_dalfox_findings_are_counted_by_module():
    src=Path("app/main.py").read_text()
    assert 'len(result.get("alerts", [])) + len(result.get("findings", []))' in src
    assert '"targets_checked"' in Path("app/pipeline.py").read_text()
