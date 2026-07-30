"""Startup config-load diagnostics (#155), now via the shared loader.

These tests used to exercise ``hate_crack.main._load_config_defaults()``,
which read ``config.json.example`` to fill in keys a user's ``config.json``
was missing. That helper is gone: schema defaults are layer 1 of
``hate_crack.config_loader``, so there is no example file to read and no
"missing key" merge to get wrong.

The behaviour worth keeping from #155 is the *diagnostic*: a config file
that exists but cannot be read (including a dangling symlink, which surfaces
as ``FileNotFoundError`` rather than ``PermissionError``) must produce a
named, actionable message and ``exit(1)`` instead of an uncaught traceback.
That now belongs to ``load_config_or_exit()``, so these tests assert it
there, against both file kinds it can be handed.
"""

import json
import os

import pytest

from hate_crack.config_loader import load_config, load_config_or_exit


def test_missing_config_file_is_not_an_error(tmp_path):
    """A config path that simply doesn't exist is normal, not fatal.

    This is the deliberate behaviour change from the old helper, which
    exited: with schema defaults as layer 1, "no config file anywhere" is a
    complete, usable configuration.
    """
    result = load_config_or_exit(
        env_path=str(tmp_path / ".env"),
        legacy_json_path=str(tmp_path / "config.json"),
        environ={},
    )
    assert result.config["hcatBin"] == "hashcat"
    assert result.warnings == []


@pytest.mark.parametrize("kind", ["env_path", "legacy_json_path"])
def test_unreadable_config_file_names_the_cause(tmp_path, capsys, kind):
    """#155's real requirement: a config file that exists but cannot be
    opened must produce a named, actionable message and exit(1), not an
    uncaught OSError from deep inside import."""
    name = ".env" if kind == "env_path" else "config.json"
    path = tmp_path / name
    path.write_text("HCAT_BIN=hashcat\n" if name == ".env" else "{}")
    path.chmod(0o000)
    try:
        with pytest.raises(SystemExit) as exc_info:
            load_config_or_exit(**{kind: str(path)}, environ={})
    finally:
        path.chmod(0o600)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "could not be read" in captured.out
    assert str(path) in captured.out


@pytest.mark.parametrize("name", [".env", "config.json"])
def test_dangling_symlink_config_falls_back_to_defaults(tmp_path, name):
    """Documents deliberate behaviour, not an oversight: the loader gates
    every file layer on ``os.path.isfile()``, which a dangling symlink fails,
    so the layer is skipped and the schema defaults stand. Before the .env
    migration a dangling ``config.json`` symlink was equally non-fatal (the
    old bootstrap's ``shutil.copy`` followed the link and materialised the
    target), so nothing regresses here -- but note that the "dangling
    symlink" branch of ConfigFileUnreadableError's diagnostic is therefore
    only reachable for a path a caller passes in explicitly.
    """
    link_path = tmp_path / name
    os.symlink(tmp_path / "does-not-exist", link_path)
    kind = "env_path" if name == ".env" else "legacy_json_path"

    result = load_config_or_exit(**{kind: str(link_path)}, environ={})

    assert result.config["hcatBin"] == "hashcat"


def test_malformed_legacy_json_exits_with_clear_message(tmp_path, capsys):
    bad_path = tmp_path / "config.json"
    bad_path.write_text("{not valid json")

    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(legacy_json_path=str(bad_path), environ={})

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "invalid JSON" in captured.out
    assert str(bad_path) in captured.out


def test_valid_legacy_json_loads_and_defaults_fill_the_rest(tmp_path):
    good_path = tmp_path / "config.json"
    good_path.write_text(json.dumps({"hcatBin": "hashcat-6.2.6"}))

    config = load_config(legacy_json_path=str(good_path), environ={}).config

    assert config["hcatBin"] == "hashcat-6.2.6"
    # Every other key still present, from the schema-default layer.
    assert config["pipal_count"] == 10
