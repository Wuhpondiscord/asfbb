from pathlib import Path

def test_live_jobs_preserve_expanded_details():
    source = Path("app/index.html").read_text()
    assert "existingOpen" in source
    assert "data-detail-key" in source
    assert "currentScroll=window.scrollY" in source
    assert "window.scrollTo({top:currentScroll" in source

def test_nuclei_has_a_bundled_template():
    from app import config
    assert "/app/app/nuclei-templates/technology-headers.yaml" in config.NUCLEI_TEMPLATE_PATHS
    template = Path("app/nuclei-templates/technology-headers.yaml").read_text()
    assert "id: asfb-tech-response-headers" in template
    assert "severity: info" in template
