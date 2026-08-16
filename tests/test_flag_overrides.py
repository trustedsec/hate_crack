"""Tests for the seven argparse flags promoted into schema-backed keys.

Each flag is now a per-run override of a config-file-settable default, resolved
by ``hate_crack.main.resolve_flag_overrides``. All seven of these keys are
``home="json"``, so their persisted default comes from ``config.json``; the
helper below routes a ``KEY=VALUE`` body to whichever file each key's home is,
so a test cannot accidentally assert that the wrong file works. For every flag
we cover the four states from the task brief:

1. flag passed affirmatively -> flag wins
2. flag passed negatively -> flag wins and the value is genuinely off/empty,
   even when the config file says on. **This is the state
   ``action="store_true"`` silently breaks**: with ``store_true``, absent and
   explicitly-false are both ``False``, so the flag could never turn a
   config-enabled setting off.
3. flag absent, the config file sets a value -> that value is used
4. flag absent, nothing set -> the documented default, unchanged

Plus the precedence edges (``os.environ`` > the home file, flag >
``os.environ``), the fatal diagnostic for an out-of-range
``HATE_CRACK_UPDATE_CHANNEL``, and parser-level checks that the negative
spellings actually exist.
"""

from __future__ import annotations

import json
import os
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import hate_crack.main as hc_main
from hate_crack import hashcat_paths
from hate_crack.config_loader import load_config, load_config_or_exit
from hate_crack.config_schema import BY_ENV, SECRET_ENV_KEYS, coerce

BASE_DIR = "/base/dir"


def _write_config(tmp_path, body: str) -> tuple[str | None, str | None]:
    """Write a ``KEY=VALUE`` body into each key's own home file.

    Returns ``(env_path, json_path)``, either of which is ``None`` when the
    body contained no key homed there. Routing by ``entry.home`` rather than
    dumping everything into `.env` is deliberate: under the split a key written
    to the wrong file is ignored, so a test that hard-coded `.env` would be
    asserting on the schema default and passing for the wrong reason.
    """
    env_lines: list[str] = []
    json_data: dict = {}
    for line in body.splitlines():
        if not line.strip():
            continue
        name, _, raw = line.partition("=")
        entry = BY_ENV[name]
        if entry.home == "env":
            env_lines.append(line)
        else:
            json_data[entry.legacy] = coerce(entry, raw, "<test>")
    env_path = json_path = None
    if env_lines:
        env_path = tmp_path / ".env"
        env_path.write_text("\n".join(env_lines) + "\n")
        env_path = str(env_path)
    if json_data:
        json_path = tmp_path / "config.json"
        json_path.write_text(json.dumps(json_data))
        json_path = str(json_path)
    return env_path, json_path


def _resolve(tmp_path, env_body="", environ=None, current_potfile_path=None, **flags):
    """Load config through the real loader, then layer the flags on top.

    ``flags`` uses the argparse ``dest`` names; anything omitted defaults to
    ``None``/absent, i.e. "flag not passed".
    """
    env_path, json_path = _write_config(tmp_path, env_body)
    config = load_config(
        env_path=env_path,
        legacy_json_path=json_path,
        environ=environ or {},
    ).config
    args = SimpleNamespace(
        debug=flags.get("debug"),
        nightly=flags.get("nightly"),
        rank=flags.get("rank"),
        restore_potfile=flags.get("restore_potfile"),
        no_optimized_kernel=flags.get("no_optimized_kernel", False),
        potfile_path=flags.get("potfile_path"),
        no_potfile_path=flags.get("no_potfile_path", False),
        rule_debug_mode=flags.get("rule_debug_mode"),
    )
    kwargs = {}
    if "hcat_bin" in flags:
        kwargs["hcat_bin"] = flags["hcat_bin"]
    return hc_main.resolve_flag_overrides(
        args,
        config,
        base_dir=BASE_DIR,
        current_potfile_path=current_potfile_path,
        **kwargs,
    )


def test_auto_potfile_path_resolves_against_the_configured_binary(tmp_path):
    """`--potfile-path auto` must ask the *configured* hashcat where its data
    lives, not whatever `hashcat` happens to be on $PATH.

    With `hcatBin` pointing at an install that cannot be probed, resolution
    falls back to whichever directory exists -- and on a box that still has a
    stale `~/.hashcat`, probing the wrong binary is how hate_crack ends up
    handing a hashcat 7 install the legacy path and recreating that directory
    all over again.
    """
    seen = []

    def _fake_version(hcat_bin="hashcat"):
        seen.append(hcat_bin)
        return 7

    with patch.object(hashcat_paths, "hashcat_major_version", _fake_version):
        _resolve(tmp_path, potfile_path="auto", hcat_bin="/opt/hashcat7/hashcat")

    assert seen == ["/opt/hashcat7/hashcat"], (
        f"resolution probed {seen!r} instead of the configured hcatBin"
    )


# ---------------------------------------------------------------------------
# --debug / --no-debug  <->  HATE_CRACK_DEBUG
# ---------------------------------------------------------------------------


def test_debug_flag_affirmative_wins(tmp_path):
    assert _resolve(tmp_path, "HATE_CRACK_DEBUG=0\n", debug=True).debug is True


def test_debug_flag_negative_beats_env_that_says_on(tmp_path):
    assert _resolve(tmp_path, "HATE_CRACK_DEBUG=1\n", debug=False).debug is False


def test_debug_from_env_when_flag_absent(tmp_path):
    assert _resolve(tmp_path, "HATE_CRACK_DEBUG=true\n").debug is True


def test_debug_default_is_off(tmp_path):
    assert _resolve(tmp_path).debug is False


# ---------------------------------------------------------------------------
# --restore-potfile / --no-restore-potfile  <->  RESTORE_POTFILE_ON_START
# ---------------------------------------------------------------------------


def test_restore_potfile_flag_affirmative_wins(tmp_path):
    got = _resolve(tmp_path, "RESTORE_POTFILE_ON_START=0\n", restore_potfile=True)
    assert got.restore_potfile is True


def test_restore_potfile_negative_beats_env_that_says_on(tmp_path):
    got = _resolve(tmp_path, "RESTORE_POTFILE_ON_START=1\n", restore_potfile=False)
    assert got.restore_potfile is False


def test_restore_potfile_from_env_when_flag_absent(tmp_path):
    got = _resolve(tmp_path, "RESTORE_POTFILE_ON_START=yes\n")
    assert got.restore_potfile is True


def test_restore_potfile_default_is_off(tmp_path):
    assert _resolve(tmp_path).restore_potfile is False


# ---------------------------------------------------------------------------
# --rule-debug-mode / --no-rule-debug-mode  <->  RULE_DEBUG_MODE_ENABLED
# ---------------------------------------------------------------------------


def test_rule_debug_mode_flag_negative_beats_config_that_says_on(tmp_path):
    got = _resolve(tmp_path, "RULE_DEBUG_MODE_ENABLED=1\n", rule_debug_mode=False)
    assert got.rule_debug_mode_enabled is False


def test_rule_debug_mode_flag_affirmative_beats_config_that_says_off(tmp_path):
    got = _resolve(tmp_path, "RULE_DEBUG_MODE_ENABLED=0\n", rule_debug_mode=True)
    assert got.rule_debug_mode_enabled is True


def test_rule_debug_mode_from_config_when_flag_absent(tmp_path):
    got = _resolve(tmp_path, "RULE_DEBUG_MODE_ENABLED=false\n")
    assert got.rule_debug_mode_enabled is False


def test_rule_debug_mode_default_is_on(tmp_path):
    # Unlike the other promoted booleans, this one defaults to True: rule
    # debug logging (mining winning rules for the Rosetta Attack) has always
    # been unconditional, so the flag is an opt-out, not an opt-in.
    assert _resolve(tmp_path).rule_debug_mode_enabled is True


# ---------------------------------------------------------------------------
# --rank  <->  WEAKPASS_MIN_RANK
# ---------------------------------------------------------------------------


def test_rank_flag_affirmative_wins(tmp_path):
    assert _resolve(tmp_path, "WEAKPASS_MIN_RANK=7\n", rank=3).weakpass_min_rank == 3


def test_rank_flag_zero_is_not_treated_as_absent(tmp_path):
    """``--rank 0`` means "show every wordlist" and must beat a `.env` value.

    0 is falsy, so a resolver written as ``flag or config`` would silently drop
    it -- this is --rank's version of the store_true bug.
    """
    assert _resolve(tmp_path, "WEAKPASS_MIN_RANK=7\n", rank=0).weakpass_min_rank == 0


def test_rank_flag_sentinel_beats_env(tmp_path):
    """``--rank -1`` is the "off" form: restore the built-in >4 rule."""
    assert _resolve(tmp_path, "WEAKPASS_MIN_RANK=7\n", rank=-1).weakpass_min_rank == -1


def test_rank_from_env_when_flag_absent(tmp_path):
    assert _resolve(tmp_path, "WEAKPASS_MIN_RANK=7\n").weakpass_min_rank == 7


def test_rank_default_is_the_builtin_sentinel(tmp_path):
    assert _resolve(tmp_path).weakpass_min_rank == -1


# ---------------------------------------------------------------------------
# --nightly / --no-nightly  <->  HATE_CRACK_UPDATE_CHANNEL
# ---------------------------------------------------------------------------


def test_nightly_flag_affirmative_wins(tmp_path):
    got = _resolve(tmp_path, "HATE_CRACK_UPDATE_CHANNEL=main\n", nightly=True)
    assert got.update_channel == "nightly-dev"


def test_no_nightly_beats_env_that_selects_nightly(tmp_path):
    got = _resolve(tmp_path, "HATE_CRACK_UPDATE_CHANNEL=nightly-dev\n", nightly=False)
    assert got.update_channel == "main"


def test_update_channel_from_env_when_flag_absent(tmp_path):
    got = _resolve(tmp_path, "HATE_CRACK_UPDATE_CHANNEL=nightly-dev\n")
    assert got.update_channel == "nightly-dev"


def test_update_channel_default_is_main(tmp_path):
    assert _resolve(tmp_path).update_channel == "main"


def test_invalid_update_channel_exits_naming_the_key(tmp_path, capsys):
    """Via os.environ, which is the one layer that hands the closed-set
    validator a raw string for this json-homed key."""
    with pytest.raises(SystemExit) as exc:
        load_config_or_exit(
            env_path=None,
            legacy_json_path=None,
            environ={"HATE_CRACK_UPDATE_CHANNEL": "stable"},
        )
    assert exc.value.code != 0
    out = capsys.readouterr().out
    assert "HATE_CRACK_UPDATE_CHANNEL" in out
    assert "main/nightly-dev" in out


def test_invalid_update_channel_in_config_json_also_exits(tmp_path, capsys):
    legacy = tmp_path / "config.json"
    legacy.write_text('{"update_channel": "stable"}')
    with pytest.raises(SystemExit):
        load_config_or_exit(env_path=None, legacy_json_path=str(legacy), environ={})
    assert "HATE_CRACK_UPDATE_CHANNEL" in capsys.readouterr().out


def test_choices_diagnostic_redacts_a_secret_bearing_key():
    """The closed-set diagnostic shares its rendering path with every other
    invalid-value message, so prove that path still redacts for a secret key.
    None of the six promoted keys is secret; the shared code is what matters.
    """
    from hate_crack.config_schema import ConfigKey, ConfigValueError, validate_choices

    secret_env = sorted(SECRET_ENV_KEYS)[0]
    entry = ConfigKey(secret_env, "fake_legacy", "str", "a", choices=("a", "b"))
    marker = "not-a-real-value-zzz"
    with pytest.raises(ConfigValueError) as exc:
        validate_choices(entry, marker, "<.env>")
    rendered = str(exc.value)
    assert secret_env in rendered
    assert marker not in rendered
    assert "<redacted>" in rendered


# ---------------------------------------------------------------------------
# --potfile-path / --no-potfile-path  <->  HCAT_POTFILE_PATH
# ---------------------------------------------------------------------------


def test_potfile_path_flag_affirmative_wins(tmp_path):
    got = _resolve(
        tmp_path,
        "HCAT_POTFILE_PATH=/from/env.potfile\n",
        potfile_path="/from/flag.potfile",
    )
    assert got.potfile_path == "/from/flag.potfile"


def test_no_potfile_path_empties_even_when_env_sets_one(tmp_path):
    got = _resolve(
        tmp_path,
        "HCAT_POTFILE_PATH=/from/env.potfile\n",
        no_potfile_path=True,
    )
    assert got.potfile_path == ""


def test_empty_potfile_path_flag_also_empties(tmp_path):
    got = _resolve(tmp_path, "HCAT_POTFILE_PATH=/from/env.potfile\n", potfile_path="  ")
    assert got.potfile_path == ""


def test_potfile_path_from_env_when_flag_absent(tmp_path):
    got = _resolve(tmp_path, "HCAT_POTFILE_PATH=/from/env.potfile\n")
    assert got.potfile_path == "/from/env.potfile"


def test_potfile_path_default_when_nothing_set(tmp_path):
    """The shipped default is the "auto" sentinel, and it must arrive at the
    caller already resolved to hashcat's own potfile -- an unresolved "auto"
    would be handed to hashcat as a cwd-relative filename."""
    assert BY_ENV["HCAT_POTFILE_PATH"].default == hashcat_paths.AUTO
    assert _resolve(tmp_path).potfile_path == hashcat_paths.default_potfile_path()


def test_relative_potfile_path_flag_is_joined_to_base_dir(tmp_path):
    got = _resolve(tmp_path, potfile_path="rel.potfile")
    assert got.potfile_path == os.path.join(BASE_DIR, "rel.potfile")


def test_potfile_path_flag_beats_no_potfile_path(tmp_path):
    """Pre-existing precedence: passing both leaves the explicit path in force."""
    got = _resolve(tmp_path, potfile_path="/x.potfile", no_potfile_path=True)
    assert got.potfile_path == "/x.potfile"


def test_absent_flags_keep_the_already_normalized_potfile_path(tmp_path):
    got = _resolve(
        tmp_path,
        "HCAT_POTFILE_PATH=/from/env.potfile\n",
        current_potfile_path="/already/normalized.potfile",
    )
    assert got.potfile_path == "/already/normalized.potfile"


# ---------------------------------------------------------------------------
# --no-optimized-kernel  <->  OPTIMIZED_KERNEL_ATTACKS
# ---------------------------------------------------------------------------


def test_no_optimized_kernel_flag_disables_for_the_run(tmp_path):
    assert _resolve(tmp_path, no_optimized_kernel=True).optimized_kernel_disabled


def test_optimized_kernel_enabled_by_default(tmp_path):
    assert not _resolve(tmp_path).optimized_kernel_disabled


def test_optimized_kernel_attacks_come_from_config_json(tmp_path):
    """The affirmative side of this key is the list itself, not a flag:
    config.json picks which attacks get -O, and the flag is only a blanket off
    switch."""
    json_path = tmp_path / "config.json"
    json_path.write_text(json.dumps({"optimizedKernelAttacks": ["hcatPrince"]}))
    config = load_config(
        env_path=None, legacy_json_path=str(json_path), environ={}
    ).config
    assert config["optimizedKernelAttacks"] == ["hcatPrince"]


def test_empty_optimized_kernel_attacks_in_config_json_is_an_empty_list(tmp_path):
    json_path = tmp_path / "config.json"
    json_path.write_text(json.dumps({"optimizedKernelAttacks": []}))
    config = load_config(
        env_path=None, legacy_json_path=str(json_path), environ={}
    ).config
    assert config["optimizedKernelAttacks"] == []


def test_empty_optimized_kernel_attacks_in_environ_is_an_empty_list(tmp_path):
    """The environ carve-out for list types: an explicitly-empty value means
    "no attack gets -O", not "unset"."""
    config = load_config(
        env_path=None,
        legacy_json_path=None,
        environ={"OPTIMIZED_KERNEL_ATTACKS": ""},
    ).config
    assert config["optimizedKernelAttacks"] == []


# ---------------------------------------------------------------------------
# Cross-layer precedence
# ---------------------------------------------------------------------------


def test_environ_outranks_the_home_file_for_a_promoted_key(tmp_path):
    got = _resolve(
        tmp_path,
        "WEAKPASS_MIN_RANK=7\nHATE_CRACK_DEBUG=0\n",
        environ={"WEAKPASS_MIN_RANK": "9", "HATE_CRACK_DEBUG": "1"},
    )
    assert got.weakpass_min_rank == 9
    assert got.debug is True


def test_flag_outranks_environ(tmp_path):
    got = _resolve(
        tmp_path,
        "WEAKPASS_MIN_RANK=7\nHATE_CRACK_DEBUG=0\n",
        environ={"WEAKPASS_MIN_RANK": "9", "HATE_CRACK_DEBUG": "1"},
        rank=2,
        debug=False,
    )
    assert got.weakpass_min_rank == 2
    assert got.debug is False


# ---------------------------------------------------------------------------
# Namespacing: a generic env var must not reach a hate_crack setting
# ---------------------------------------------------------------------------


def test_unrelated_bare_debug_env_var_does_not_enable_debug_mode(tmp_path):
    """A bare ``DEBUG=1`` exported for some *other* tool must not turn on
    hate_crack's debug mode.

    This is why the key is ``HATE_CRACK_DEBUG`` and not ``DEBUG``: the environ
    layer outranks both config files, debug mode writes files under
    ``hcatDebugLogPath``,
    and this tool handles cracked plaintexts. Somebody with ``export DEBUG=1``
    in their shell profile would get sensitive material written to disk they
    never asked for and would not think to look for. Do not "simplify" the key
    name back to ``DEBUG``.
    """
    got = _resolve(tmp_path, environ={"DEBUG": "1"})
    assert got.debug is False

    config = load_config(env_path=None, legacy_json_path=None, environ={"DEBUG": "1"})
    assert config.config["debug"] is False
    # ...and the bare name is not silently accepted as an alias either.
    assert "DEBUG" not in BY_ENV


def test_unrelated_bare_update_channel_env_var_is_ignored(tmp_path):
    """Same reasoning as above for ``UPDATE_CHANNEL``, which is generic enough
    to collide with an unrelated deployment tool. A collision here would also
    trip the closed-set validator and make hate_crack refuse to start."""
    got = _resolve(tmp_path, environ={"UPDATE_CHANNEL": "stable"})
    assert got.update_channel == "main"
    assert "UPDATE_CHANNEL" not in BY_ENV


def test_generic_key_names_are_namespaced_in_the_schema():
    """Guard the convention itself: no schema key may use one of these bare,
    collision-prone names. ``HATE_CRACK_`` matches the prefix already used by
    HATE_CRACK_SKIP_INIT / HATE_CRACK_ORIG_CWD / HATE_CRACK_RUN_E2E.
    """
    forbidden = {"DEBUG", "UPDATE_CHANNEL", "VERBOSE", "LOG_LEVEL", "TIMEOUT"}
    assert forbidden.isdisjoint(BY_ENV)
    assert BY_ENV["HATE_CRACK_DEBUG"].legacy == "debug"
    assert BY_ENV["HATE_CRACK_UPDATE_CHANNEL"].legacy == "update_channel"


# ---------------------------------------------------------------------------
# Parser-level: the negative spellings exist and reach the resolver
# ---------------------------------------------------------------------------


def _run_main(monkeypatch, argv):
    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + argv)
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "4")
    with pytest.raises(SystemExit) as exc:
        hc_main.main()
    return exc.value.code


@pytest.mark.parametrize(
    ("argv", "config_debug", "expected"),
    [
        (["--debug"], False, True),
        (["--no-debug"], True, False),
        ([], True, True),
        ([], False, False),
    ],
)
def test_debug_mode_through_the_real_parser(monkeypatch, argv, config_debug, expected):
    monkeypatch.setitem(hc_main.config_parser, "debug", config_debug)
    assert _run_main(monkeypatch, argv) == 0
    assert hc_main.debug_mode is expected


def test_no_restore_potfile_is_accepted_by_the_parser(monkeypatch):
    monkeypatch.setitem(hc_main.config_parser, "restore_potfile_on_start", True)
    # No hash file is given, so the restore path is never reached; this only
    # proves the negative spelling parses rather than erroring out.
    assert _run_main(monkeypatch, ["--no-restore-potfile"]) == 0


@pytest.mark.parametrize(
    ("argv", "config_value", "expected"),
    [
        (["--rule-debug-mode"], False, True),
        (["--no-rule-debug-mode"], True, False),
        ([], True, True),
        ([], False, False),
    ],
)
def test_rule_debug_mode_through_the_real_parser(
    monkeypatch, argv, config_value, expected
):
    monkeypatch.setitem(hc_main.config_parser, "rule_debug_mode_enabled", config_value)
    assert _run_main(monkeypatch, argv) == 0
    assert hc_main._rule_debug_mode_enabled is expected


def test_no_nightly_does_not_trigger_an_upgrade(monkeypatch):
    """HATE_CRACK_UPDATE_CHANNEL only picks the channel; starting an upgrade still needs
    an explicit --update/--nightly, so --no-nightly must be a no-op here."""
    calls = []
    monkeypatch.setattr(
        hc_main, "_run_upgrade", lambda branch="main": calls.append(branch)
    )
    monkeypatch.setitem(hc_main.config_parser, "update_channel", "nightly-dev")
    assert _run_main(monkeypatch, ["--no-nightly"]) == 0
    assert calls == []


def test_update_uses_the_configured_channel(monkeypatch):
    calls = []

    def fake_upgrade(branch="main"):
        calls.append(branch)
        raise SystemExit(0)

    monkeypatch.setattr(hc_main, "_run_upgrade", fake_upgrade)
    monkeypatch.setitem(hc_main.config_parser, "update_channel", "nightly-dev")
    _run_main(monkeypatch, ["--update"])
    assert calls == ["nightly-dev"]


def test_no_nightly_forces_main_channel_over_config(monkeypatch):
    calls = []

    def fake_upgrade(branch="main"):
        calls.append(branch)
        raise SystemExit(0)

    monkeypatch.setattr(hc_main, "_run_upgrade", fake_upgrade)
    monkeypatch.setitem(hc_main.config_parser, "update_channel", "nightly-dev")
    _run_main(monkeypatch, ["--update", "--no-nightly"])
    assert calls == ["main"]


@pytest.mark.parametrize("spelling", ["--no-optimized-kernel", "--no-optimize"])
def test_both_optimized_kernel_spellings_still_parse(monkeypatch, capsys, spelling):
    monkeypatch.setattr(hc_main, "disable_optimized_kernel", lambda: None)
    assert _run_main(monkeypatch, [spelling]) == 0
    assert "Optimized kernels (-O) disabled for this run" in capsys.readouterr().out


def test_rank_reaches_the_weakpass_menu(monkeypatch):
    seen = []
    monkeypatch.setattr(
        hc_main,
        "weakpass_wordlist_menu",
        lambda **kw: seen.append(kw.get("rank")),
    )
    assert _run_main(monkeypatch, ["--weakpass", "--rank", "0"]) == 0
    assert seen == [0]


def test_rank_from_config_reaches_the_weakpass_menu(monkeypatch):
    seen = []
    monkeypatch.setattr(
        hc_main,
        "weakpass_wordlist_menu",
        lambda **kw: seen.append(kw.get("rank")),
    )
    monkeypatch.setitem(hc_main.config_parser, "weakpass_min_rank", 5)
    assert _run_main(monkeypatch, ["--weakpass"]) == 0
    assert seen == [5]
