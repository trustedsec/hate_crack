"""The ui_backend config key must offer exactly the backends hate_crack.ui knows."""

from hate_crack import ui
from hate_crack.config_schema import CONFIG_SCHEMA


def _row(legacy_name: str):
    matches = [row for row in CONFIG_SCHEMA if row.legacy == legacy_name]
    assert len(matches) == 1, f"expected exactly one {legacy_name!r} row"
    return matches[0]


def test_ui_backend_choices_match_ui_backends():
    assert _row("ui_backend").choices == tuple(ui.BACKENDS)


def test_ui_backend_default_is_plain_and_json_homed():
    row = _row("ui_backend")
    assert row.default == "plain"
    assert row.home == "json"
