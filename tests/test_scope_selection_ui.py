from pathlib import Path

def test_manual_scope_rows_are_selectable_when_filter_off():
    source=Path("app/index.html").read_text()
    assert "visibleWebIds=rows.map(a=>a.id)" in source
    assert "(a.compatibility!=='web'?'disabled ':'')" not in source
    assert "scannable=Array.from(selectedIds)" in source
    assert "no compatible scan targets" in source
