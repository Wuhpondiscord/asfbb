"""Keep provider-health scenarios independent without changing production cooldowns."""
import pytest

from app import pipeline


@pytest.fixture(autouse=True)
def isolated_archive_provider_health(monkeypatch):
    monkeypatch.setattr(pipeline, "_gau_failures", 0)
    monkeypatch.setattr(pipeline, "_gau_disabled_until", 0.0)
    monkeypatch.setattr(pipeline, "_gau_provider_failures", {})
    monkeypatch.setattr(pipeline, "_gau_provider_disabled_until", {})
