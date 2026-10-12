import pytest

from hate_crack.ui import resolve_backend_name

TTY = {"is_tty": True, "term": "xterm"}


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        ({}, "plain"),
        ({"env_value": "rich", **TTY}, "rich"),
        ({"config_value": "rich", **TTY}, "rich"),
        ({"env_value": "plain", "config_value": "rich", **TTY}, "plain"),
        ({"env_value": "rich", "config_value": "plain", **TTY}, "rich"),
        ({"env_value": "", "config_value": "rich", **TTY}, "rich"),
        ({"env_value": "bogus", "config_value": "rich", **TTY}, "rich"),
        ({"env_value": "bogus", "config_value": "bogus", **TTY}, "plain"),
        ({"env_value": "bogus", **TTY}, "plain"),
        ({"env_value": "rich", "is_tty": False, "term": "xterm"}, "plain"),
        ({"config_value": "rich", "is_tty": False}, "plain"),
        ({"env_value": "rich", "is_tty": True, "term": "dumb"}, "plain"),
        ({"env_value": "rich", "is_tty": True, "term": "DUMB"}, "plain"),
        ({"env_value": "rich", **TTY, "non_interactive": True}, "plain"),
        ({"env_value": "rich", "is_tty": True, "term": None}, "rich"),
    ],
)
def test_resolve_backend_name(kwargs, expected):
    assert resolve_backend_name(**kwargs) == expected
