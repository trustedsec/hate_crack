from hate_crack import config_schema


def test_brain_password_is_a_declared_secret():
    assert "BRAIN_PASSWORD" in config_schema.SECRET_ENV_KEYS


def test_brain_password_lives_in_env():
    assert config_schema.BY_ENV["BRAIN_PASSWORD"].home == "env"


def test_brain_tuning_keys_live_in_config_json():
    for legacy in (
        "brain_enabled",
        "brain_host",
        "brain_port",
        "brain_client_features",
        "brain_server_timer",
        "brain_modes_force",
        "brain_modes_exclude",
    ):
        assert config_schema.BY_LEGACY[legacy].home == "json"


def test_brain_defaults_match_the_design():
    assert config_schema.BY_LEGACY["brain_port"].default == 6863
    assert config_schema.BY_LEGACY["brain_client_features"].default == 3
    assert config_schema.BY_LEGACY["brain_enabled"].default is True
    assert config_schema.BY_LEGACY["brain_host"].default == ""
