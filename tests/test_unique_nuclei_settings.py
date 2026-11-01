from pathlib import Path
def test_nuclei_settings_ids_unique():
    text=Path("app/index.html").read_text()
    for id in ("nucleiSettings","nucleiBuiltins","nucleiSearch","nucleiCatalogStatus",
               "nucleiCatalogResults","nucleiSelectedCommunity","nucleiCustom"):
        assert text.count('id="'+id+'"') == 1
