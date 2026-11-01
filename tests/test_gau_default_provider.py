from app import config
def test_unavailable_wayback_is_opt_in_not_default():
    assert config.GAU_PROVIDER != "wayback"
    assert "wayback" not in config.GAU_FALLBACK_PROVIDERS
    assert config.GAU_ENABLE_WAYBACK is False
