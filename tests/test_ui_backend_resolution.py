import pytest

from hate_crack.ui import resolve_backend_name

TTY = {"is_tty": True, "term": "xterm"}


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({}, "plain"),
        ({"config_value": "rich", **TTY}, "rich"),
        ({"config_value": "bogus", **TTY}, "plain"),
        ({"config_value": "rich", "is_tty": True, "term": "dumb"}, "plain"),
        ({"config_value": "rich", "is_tty": True, "term": "DUMB"}, "plain"),
        ({"config_value": "rich", **TTY, "non_interactive": True}, "plain"),
        ({"config_value": "rich", "is_tty": True, "term": None}, "rich"),
        ({"config_value": "rich", "is_tty": False}, "plain"),
    ],
)
def test_resolve_backend_name(kwargs, expected):
    assert resolve_backend_name(**kwargs) == expected


def test_ui_backend_env_override_arrives_via_config_loader(monkeypatch):
    from hate_crack.config_loader import load_config

    monkeypatch.setenv("UI_BACKEND", "rich")
    assert load_config().config["ui_backend"] == "rich"


def test_resolve_backend_name_has_no_env_parameter():
    with pytest.raises(TypeError):
        resolve_backend_name(env_value="rich", **TTY)  # type: ignore[call-arg]
