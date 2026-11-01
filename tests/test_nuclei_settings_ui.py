from pathlib import Path

def test_nuclei_settings_combine_builtins_community_and_custom():
    text=Path("app/index.html").read_text()
    assert 'id="nucleiSettings"' in text
    assert 'id="nucleiCustom"' in text
    assert 'id="nucleiSearch"' in text
    assert "nuclei:nucleiOptions()" in text
    assert "nucleiCommunityPaths=new Set()" in text
    assert "searchNucleiTemplates(page=1)" in text
