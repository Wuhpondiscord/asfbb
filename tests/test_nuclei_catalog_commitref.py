from pathlib import Path
from app import nuclei_catalog


def test_nuclei_catalog_uses_commit_reference_not_tree_sha():
    source = Path("app/nuclei_catalog.py").read_text()
    assert '/git/ref/heads/main' in source
    assert 'sha=commit_sha' in source


def test_nuclei_catalog_rejects_unsafe_protocols_and_posts():
    valid = """id: safe-http-check
info:
  name: Safe check
  severity: info
http:
  - method: GET
    path:
      - "{{BaseURL}}/robots.txt"
    matchers:
      - type: status
        status: [200]
"""
    assert nuclei_catalog.validate_template(valid)=="safe-http-check"
    bad = valid.replace("method: GET", "method: POST")
    import pytest
    with pytest.raises(ValueError):
        nuclei_catalog.validate_template(bad)
