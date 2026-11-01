from pathlib import Path


def test_scope_ui_allows_non_web_selection_and_copy():
    html=Path("app/index.html").read_text()
    assert "Web-compatible only</label>" in html
    assert "function copySelectedScope()" in html
    assert "visibleWebIds=rows.map(a=>a.id);" in html
    assert "const eligible=Array.from(selectedIds).filter(" in html
    assert "Other assets can be copied" not in html  # explanatory labels need not be repeated


def test_nuclei_settings_support_combinations_and_community_browser():
    html=Path("app/index.html").read_text()
    for marker in ['id="nucleiBuiltins"', 'id="nucleiCatalogResults"',
                   'id="nucleiCustom"', 'id="nucleiSelectedCommunity"',
                   'async function checkNucleiCommunity()', 'async function importNucleiFiles(files)']:
        assert marker in html
    assert 'community_paths' in html
    assert 'custom_templates' in html
    assert 'default_ids' in html
    assert "nuclei:nucleiOptions()" in html


def test_open_findings_and_active_text_interaction_are_preserved():
    html=Path("app/index.html").read_text()
    assert "existingFindOpen" in html
    assert "data-find-key" in html
    assert "interactionHoldUntil" in html
    assert "openDetailUnderPointer" in html
    assert "keepReportStable()" in html
