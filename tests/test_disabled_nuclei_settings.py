from pathlib import Path
def test_inactive_nuclei_does_not_block_other_modules():
    page=Path("app/index.html").read_text()
    assert "if(el('modNuclei').checked&&!default_ids.length" in page
