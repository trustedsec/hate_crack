"""The --brain / --no-brain per-run override (Task 7).

Mirrors the pattern already pinned for --coverage: three resolver-level tests
covering the tri-state precedence (config default, explicit off overriding an
enabled config, explicit on overriding a disabled config), plus one
parser-level test that drives the real ``main()`` entry point so the nested
``_build_parser`` wiring itself is pinned, not just ``resolve_flag_overrides``.

``resolve_flag_overrides`` takes a required ``base_dir`` keyword (see
``main.py:372``); the task brief's sketch omits it, so these tests pass a
throwaway value the way ``tests/test_flag_overrides.py`` does.
"""

import sys
from types import SimpleNamespace

import pytest

import hate_crack.main as hc_main


def _args(**overrides):
    base = {"brain": None, "coverage": None, "rule_debug_mode": None, "debug": None}
    base.update(overrides)
    return SimpleNamespace(**base)


def test_absent_flag_falls_back_to_config():
    flags = hc_main.resolve_flag_overrides(
        _args(),
        {"brain_enabled": False},
        base_dir="/base/dir",
        current_potfile_path="",
        hcat_bin="hashcat",
    )
    assert flags.brain_enabled is False


def test_no_brain_overrides_an_enabled_config():
    flags = hc_main.resolve_flag_overrides(
        _args(brain=False),
        {"brain_enabled": True},
        base_dir="/base/dir",
        current_potfile_path="",
        hcat_bin="hashcat",
    )
    assert flags.brain_enabled is False


def test_brain_overrides_a_disabled_config():
    flags = hc_main.resolve_flag_overrides(
        _args(brain=True),
        {"brain_enabled": False},
        base_dir="/base/dir",
        current_potfile_path="",
        hcat_bin="hashcat",
    )
    assert flags.brain_enabled is True


# ---------------------------------------------------------------------------
# Parser-level: drive the real entry point so --brain/--no-brain themselves
# are pinned, not just the resolver. No hash file is given, which routes
# through the "no hash file provided" menu loop (same shape as
# test_debug_mode_through_the_real_parser in test_cli_flags.py) -- the global
# wiring runs before that branch, so a bare "Exit" selection is enough to
# observe the resolved value without building out a full attack run.
# ---------------------------------------------------------------------------


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + argv)
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    with pytest.raises(SystemExit) as exc:
        hc_main.main()
    return exc.value.code


@pytest.mark.parametrize(
    ("argv", "config_value", "expected"),
    [
        (["--brain"], False, True),
        (["--no-brain"], True, False),
        ([], True, True),
        ([], False, False),
    ],
)
def test_brain_flag_through_the_real_parser(monkeypatch, argv, config_value, expected):
    monkeypatch.setitem(hc_main.config_parser, "brain_enabled", config_value)
    assert _run_main(monkeypatch, argv) == 0
    assert hc_main._brain_enabled is expected
