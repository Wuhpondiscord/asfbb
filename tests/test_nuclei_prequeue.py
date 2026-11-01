from pathlib import Path

def test_nuclei_configuration_is_preflighted_before_queuing():
    source=Path("app/index.html").read_text()
    scan=source.split("async function scan(){",1)[1].split("async function inspectJwt()",1)[0]
    assert "scanOptions=pipelineOptions()" in scan
    assert "if(modules.includes('nuclei'))" in scan
    assert "await api('/nuclei/validate'" in scan
    assert scan.index("await api('/nuclei/validate'") < scan.index("api('/scans'")
    assert "options:scanOptions" in scan
    assert "Nuclei preflight failed before queuing" in scan


def test_preflight_blocks_overbudget_selection_without_enqueueing():
    source=Path("app/index.html").read_text()
    scan=source.split("async function scan(){",1)[1].split("async function inspectJwt()",1)[0]
    assert "if(!check.valid){" in scan
    assert "return message('Nuclei preflight blocked this scan:" in scan
