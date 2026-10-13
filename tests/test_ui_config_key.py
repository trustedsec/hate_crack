"""The ui_backend config key must offer exactly the backends hate_crack.ui knows."""

from hate_crack import ui
from hate_crack.config_schema import CONFIG_SCHEMA


def _row(legacy_name: str):
    matches = [row for row in CONFIG_SCHEMA if row.legacy == legacy_name]
    assert len(matches) == 1, f"expected exactly one {legacy_name!r} row"
    return matches[0]


def test_ui_backend_choices_match_ui_backends():
    assert _row("ui_backend").choices == tuple(ui.BACKENDS) + tuple(ui.RETIRED_BACKENDS)


def test_ui_backend_default_is_rich_and_json_homed():
    row = _row("ui_backend")
    assert row.default == "rich"
    assert row.home == "json"


def test_retired_textual_value_still_loads_and_runs_rich():
    """ui_backend=textual was valid on nightlies; an existing config must still
    start after its removal, on rich, rather than fail config validation."""
    from hate_crack.config_schema import validate_choices

    validate_choices(_row("ui_backend"), "textual", "<test>")  # must not raise
    kw = {"is_tty": True, "term": "xterm"}
    assert ui.resolve_backend_name(config_value="textual", **kw) == "rich"
    assert ui.resolve_backend_name(config_value="textual", is_tty=False) == "plain"
    assert "textual" not in ui.BACKENDS
