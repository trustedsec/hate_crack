"""Tests for hate_crack.config_loader."""

from __future__ import annotations

import json
import os
import stat

import pytest

from hate_crack import config_loader
from hate_crack.config_loader import (
    ConfigLoadResult,
    load_config,
    load_config_or_exit,
    resolve_config_paths,
)
from hate_crack.config_schema import BY_LEGACY, CONFIG_SCHEMA, ENV_KEYS, JSON_KEYS


def _write_env(path, lines: dict[str, str]) -> str:
    env_path = os.path.join(path, ".env")
    with open(env_path, "w") as fh:
        for key, value in lines.items():
            fh.write(f'{key}="{value}"\n')
    return env_path


def _write_json(path, data: dict) -> str:
    json_path = os.path.join(path, "config.json")
    with open(json_path, "w") as fh:
        json.dump(data, fh)
    return json_path


# ---------------------------------------------------------------------------
# 1. Defaults only
# ---------------------------------------------------------------------------


def test_defaults_only_matches_schema(tmp_path, monkeypatch):
    monkeypatch.delenv("HASHVIEW_API_KEY", raising=False)
    result = load_config(
        env_path=None,
        legacy_json_path=None,
        environ={},
    )
    assert isinstance(result, ConfigLoadResult)
    expected_keys = {entry.legacy for entry in CONFIG_SCHEMA}
    assert set(result.config.keys()) == expected_keys
    # 14 .env-homed integration keys + 38 config.json-homed settings.
    assert len(expected_keys) == 52
    for entry in CONFIG_SCHEMA:
        # path-typed defaults are expanded by load_config()'s uniform
        # post-merge normalization pass (see _normalize_path_values), so a
        # "~"-containing default like hcatPotfilePath's is expected to come
        # back expanded here, not verbatim.
        expected = (
            os.path.expanduser(entry.default) if entry.type == "path" else entry.default
        )
        assert result.config[entry.legacy] == expected


# ---------------------------------------------------------------------------
# 2. Layer overrides
# ---------------------------------------------------------------------------


def test_json_file_overrides_default_for_a_json_homed_key(tmp_path):
    json_path = _write_json(tmp_path, {"bandrelmaxruntime": 99})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["bandrelmaxruntime"] == 99


def test_env_file_overrides_default_for_an_env_homed_key(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "42"})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert result.config["pipal_count"] == 42


@pytest.mark.parametrize("entry", ENV_KEYS, ids=lambda entry: entry.env)
def test_every_integration_key_resolves_from_the_env_file(tmp_path, entry):
    """Requirement 1, first half: each of the twelve resolves from `.env`."""
    raw = {"int": "7", "bool": "1", "path": "/tmp/synthetic", "str": "synthetic"}[
        entry.type
    ]
    expected = {"int": 7, "bool": True, "path": "/tmp/synthetic", "str": "synthetic"}[
        entry.type
    ]
    env_path = _write_env(tmp_path, {entry.env: raw})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert result.config[entry.legacy] == expected
    assert result.warnings == []


@pytest.mark.parametrize("entry", JSON_KEYS, ids=lambda entry: entry.legacy)
def test_every_setting_resolves_from_config_json(tmp_path, entry):
    """Requirement 1, second half: each of the thirty-five resolves from
    ``config.json``. Uses a value of the right JSON type but distinguishable
    from the default, so "resolved" cannot be confused with "defaulted"."""
    if entry.choices:
        value = next(c for c in entry.choices if c != entry.default)
    elif entry.type == "bool":
        value = not entry.default
    elif entry.type == "int":
        value = entry.default + 1
    elif entry.type == "float":
        value = entry.default + 1.0
    elif entry.type in ("str", "path"):
        value = "/tmp/synthetic" if entry.type == "path" else "synthetic-value"
    else:  # csv_list / charset -- a JSON array either way
        value = ["x", "y"]
    json_path = _write_json(tmp_path, {entry.legacy: value})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config[entry.legacy] == value
    assert result.warnings == []


# ---------------------------------------------------------------------------
# 2b. One home per key: the wrong file is ignored, and says so
# ---------------------------------------------------------------------------


def test_setting_placed_in_the_env_file_is_ignored_and_warns(tmp_path):
    """The core invariant of the split: a `.env` value must never win for a
    home="json" key, however loudly it is written."""
    env_path = _write_env(tmp_path, {"HCAT_TUNING": "-w 4 --from-the-wrong-file"})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert result.config["hcatTuning"] == BY_LEGACY["hcatTuning"].default
    assert any(
        "HCAT_TUNING" in w and "config.json" in w and "hcatTuning" in w
        for w in result.warnings
    ), result.warnings


def test_env_file_cannot_beat_config_json_for_a_json_homed_key(tmp_path):
    """Same invariant, with the json-homed key actually set in its own home --
    the .env is not merely ignored in favour of the default, it loses to the
    file that owns the key."""
    json_path = _write_json(tmp_path, {"hcatTuning": "-w 3"})
    env_path = _write_env(tmp_path, {"HCAT_TUNING": "-w 4"})
    result = load_config(env_path=env_path, legacy_json_path=json_path, environ={})
    assert result.config["hcatTuning"] == "-w 3"


def test_integration_key_left_in_config_json_is_ignored_and_warns(tmp_path):
    """The mirror case, which is what a user has right after the migration:
    the key is still in config.json, and must not be read from there."""
    json_path = _write_json(tmp_path, {"hashmob_api_key": "placeholder-not-a-key"})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["hashmob_api_key"] == ""
    assert any(
        "hashmob_api_key" in w and "HASHMOB_API_KEY" in w and ".env" in w
        for w in result.warnings
    ), result.warnings


def test_config_json_cannot_beat_the_env_file_for_an_env_homed_key(tmp_path):
    json_path = _write_json(tmp_path, {"ollamaModel": "from-json"})
    env_path = _write_env(tmp_path, {"OLLAMA_MODEL": "from-dotenv"})
    result = load_config(env_path=env_path, legacy_json_path=json_path, environ={})
    assert result.config["ollamaModel"] == "from-dotenv"


def test_misplaced_key_warning_never_leaks_a_secret_value(tmp_path):
    json_path = _write_json(tmp_path, {"hashview_api_key": "synthetic-sentinel-value"})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.warnings
    assert not any("synthetic-sentinel-value" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# 2c. os.environ overrides either home
# ---------------------------------------------------------------------------


def test_environ_overrides_the_env_file(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "42"})
    result = load_config(
        env_path=env_path,
        legacy_json_path=None,
        environ={"PIPAL_COUNT": "7"},
    )
    assert result.config["pipal_count"] == 7


def test_environ_overrides_config_json(tmp_path):
    """os.environ may override *any* key, including a json-homed one: an
    environment variable is an ephemeral override, not a home."""
    json_path = _write_json(tmp_path, {"bandrelmaxruntime": 42})
    result = load_config(
        env_path=None,
        legacy_json_path=json_path,
        environ={"BANDRELMAXRUNTIME": "7"},
    )
    assert result.config["bandrelmaxruntime"] == 7
    assert result.warnings == []


def test_full_precedence_stack(tmp_path):
    json_path = _write_json(
        tmp_path,
        {"bandrelmaxruntime": 2, "hcatTuning": "-w 3", "pcfgRuleset": "FromJson"},
    )
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "10", "OLLAMA_TIMEOUT": "20"})
    result = load_config(
        env_path=env_path,
        legacy_json_path=json_path,
        environ={"PIPAL_COUNT": "100", "HCAT_TUNING": "-w 4"},
    )
    assert result.config["pipal_count"] == 100  # environ beats .env
    assert result.config["hcatTuning"] == "-w 4"  # environ beats config.json
    assert result.config["ollamaTimeout"] == 20  # .env, its own home
    assert result.config["bandrelmaxruntime"] == 2  # config.json, its own home
    assert result.config["pcfgRuleset"] == "FromJson"


# ---------------------------------------------------------------------------
# 3. os.environ outranks .env for HASHVIEW_API_KEY specifically
# ---------------------------------------------------------------------------


def test_environ_outranks_dotenv_for_hashview_api_key(tmp_path):
    """What HASHVIEW_TEST_LOCAL=1 depends on -- do not weaken this."""
    env_path = _write_env(tmp_path, {"HASHVIEW_API_KEY": "dotenv-placeholder-key"})
    result = load_config(
        env_path=env_path,
        legacy_json_path=None,
        environ={"HASHVIEW_API_KEY": "environ-placeholder-key"},
    )
    assert result.config["hashview_api_key"] == "environ-placeholder-key"


# ---------------------------------------------------------------------------
# 4. Empty string: environ falls through (except csv_list/charset), but a
#    value present in a *file* is explicit even when empty. This asymmetry is
#    deliberate, not an inconsistency to "fix": a value written to a config
#    file is a statement the user (or a migration) made on purpose, e.g.
#    PIPAL_PATH= meaning "there is no pipal here", whereas an
#    accidentally-empty exported shell variable is common enough that the
#    environ layer treating it as an override would be hostile. See
#    _apply_string_layer's docstring in config_loader.py.
# ---------------------------------------------------------------------------


def test_empty_string_in_dotenv_is_explicit_not_a_fallthrough(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_PATH": ""})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert result.config["pipalPath"] == ""


def test_bare_key_with_no_value_in_dotenv_falls_through_to_default(tmp_path):
    # dotenv_values() reports a bare `KEY` with no `=` as None, distinct from
    # an explicitly-empty `KEY=`; that still counts as unset.
    env_path = os.path.join(tmp_path, ".env")
    with open(env_path, "w") as fh:
        fh.write("PIPAL_PATH\n")
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    default = BY_LEGACY["pipalPath"].default
    assert result.config["pipalPath"] == default


def test_empty_string_in_environ_falls_through_to_default(tmp_path):
    result = load_config(
        env_path=None, legacy_json_path=None, environ={"PIPAL_PATH": ""}
    )
    default = BY_LEGACY["pipalPath"].default
    assert result.config["pipalPath"] == default


def test_empty_csv_list_in_environ_yields_empty_list(tmp_path):
    result = load_config(
        env_path=None, legacy_json_path=None, environ={"NOTIFY_ATTACK_ALLOWLIST": ""}
    )
    assert result.config["notify_attack_allowlist"] == []


def test_empty_json_potfile_path_stays_explicitly_empty(tmp_path):
    """The empty-is-explicit rule for the json home: an empty
    ``hcatPotfilePath`` is a deliberate "pass no --potfile-path to hashcat",
    not an absence to be filled in from the default."""
    json_path = _write_json(tmp_path, {"hcatPotfilePath": ""})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["hcatPotfilePath"] == ""


def test_charset_preserves_edge_spaces_via_environ(tmp_path):
    result = load_config(
        env_path=None,
        legacy_json_path=None,
        environ={"HCAT_MIDDLE_COMBINATOR_MASKS": " 24-_+,.& "},
    )
    value = result.config["hcatMiddleCombinatorMasks"]
    assert value[0] == " "
    assert value[-1] == " "


# ---------------------------------------------------------------------------
# 5. Types come back correct, for one key of every schema type
# ---------------------------------------------------------------------------


def test_types_are_correct_for_each_schema_type(tmp_path):
    """Exercised through the environ layer, because that is the one layer that
    sees raw strings for all seven types -- the `.env` layer only ever holds
    the four types the twelve integration keys use."""
    result = load_config(
        env_path=None,
        legacy_json_path=None,
        environ={
            "HCAT_BIN": "hashcat",  # str
            "HCAT_PATH": "/opt/hashcat",  # path
            "PIPAL_COUNT": "15",  # int
            "NOTIFY_POLL_INTERVAL_SECONDS": "2.5",  # float
            "NOTIFY_ENABLED": "1",  # bool -- must NOT stay the string "1"
            "HCAT_DICTIONARY_WORDLIST": "a.txt,b.txt",  # csv_list
            "HCAT_MIDDLE_COMBINATOR_MASKS": "ab",  # charset
        },
    )
    assert isinstance(result.config["hcatBin"], str)
    assert isinstance(result.config["hcatPath"], str)
    assert isinstance(result.config["pipal_count"], int)
    assert isinstance(result.config["notify_poll_interval_seconds"], float)
    notify_enabled = result.config["notify_enabled"]
    assert isinstance(notify_enabled, bool)
    assert notify_enabled is True
    assert notify_enabled != "1"
    assert isinstance(result.config["hcatDictionaryWordlist"], list)
    assert result.config["hcatDictionaryWordlist"] == ["a.txt", "b.txt"]
    assert isinstance(result.config["hcatMiddleCombinatorMasks"], list)
    assert result.config["hcatMiddleCombinatorMasks"] == ["a", "b"]


# ---------------------------------------------------------------------------
# 6. os.environ unmodified across load_config()
# ---------------------------------------------------------------------------


def test_load_config_does_not_mutate_process_environ(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "42"})
    before = dict(os.environ)
    load_config(env_path=env_path, legacy_json_path=None, environ=os.environ)
    after = dict(os.environ)
    assert before == after


# ---------------------------------------------------------------------------
# 7. Malformed bool/int -> SystemExit(1), message contains key name
# ---------------------------------------------------------------------------


def test_malformed_bool_exits_with_key_name(tmp_path, capsys):
    env_path = _write_env(tmp_path, {"OLLAMA_AUTO_RESEARCH": "maybe"})
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "OLLAMA_AUTO_RESEARCH" in captured.out


def test_malformed_int_exits_with_key_name(tmp_path, capsys):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "not-a-number"})
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "PIPAL_COUNT" in captured.out


def test_malformed_empty_value_is_shown_explicitly(tmp_path, capsys):
    """An empty value is the case that most needs printing, not hiding.

    ``PIPAL_COUNT=`` in a ``.env`` fails int coercion; suppressing the
    ``Value:`` line for a falsy raw value left the user with "not a valid int"
    and no hint that the value was empty.
    """
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": ""})
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "PIPAL_COUNT" in captured.out
    assert "Value: ''" in captured.out


# ---------------------------------------------------------------------------
# 8. Secret key with malformed value -> value redacted in output
# ---------------------------------------------------------------------------


def test_secret_key_malformed_value_is_redacted(tmp_path, capsys):
    # HASHVIEW_API_KEY is a str type so it can't fail coercion; use a bool
    # key is not secret. There is no bool/int secret key in the schema, so
    # exercise this via a legacy JSON type-mismatch path instead: a secret
    # key given the wrong JSON type in config.json still must not leak its
    # value if it were ever rendered. Simplest direct test: force a
    # ConfigValueError for a secret env key through .env with a type that can
    # fail -- HASHVIEW_API_KEY is "str" (cannot fail), so simulate the
    # rendering path directly via load_config_or_exit's redaction logic using
    # NOTIFY_PUSHOVER_TOKEN, coerced as "str" too. Instead, verify no schema
    # secret key can leak a placeholder token by checking a directly raised
    # ConfigValueError renders as redacted.
    from hate_crack.config_schema import ConfigValueError

    err = ConfigValueError(
        "HASHVIEW_API_KEY", "sk-placeholder-not-a-real-key", "<.env>", "test reason"
    )
    assert "sk-placeholder-not-a-real-key" not in str(err)
    assert "<redacted>" in str(err)


def test_secret_key_malformed_via_or_exit_output_redacted(
    tmp_path, capsys, monkeypatch
):
    from hate_crack import config_loader
    from hate_crack.config_schema import ConfigValueError

    def _boom(*args, **kwargs):
        raise ConfigValueError(
            "HASHVIEW_API_KEY",
            "sk-placeholder-not-a-real-key",
            "<.env>",
            "simulated failure",
        )

    monkeypatch.setattr(config_loader, "load_config", _boom)
    with pytest.raises(SystemExit):
        load_config_or_exit(env_path=None, legacy_json_path=None, environ={})
    captured = capsys.readouterr()
    assert "sk-placeholder-not-a-real-key" not in captured.out
    assert "<redacted>" in captured.out


# ---------------------------------------------------------------------------
# 9. Malformed legacy JSON -> SystemExit(1)
# ---------------------------------------------------------------------------


def test_malformed_legacy_json_exits(tmp_path, capsys):
    json_path = os.path.join(tmp_path, "config.json")
    with open(json_path, "w") as fh:
        fh.write("{not valid json")
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=None, legacy_json_path=json_path, environ={})
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    # Regression guard: the JSON-parse diagnostic must not reuse the
    # generic "malformed value" template, whose "remove the offending
    # line" advice is actively wrong for a file that fails to parse at
    # all. It must instead offer to delete the file and regenerate from
    # defaults, matching main.py's own JSONDecodeError handler.
    assert "offending line" not in captured.out
    assert "invalid JSON" in captured.out
    assert "Delete the file to regenerate from defaults" in captured.out
    assert json_path in captured.out


def test_malformed_legacy_json_message_names_file_not_generic_template(
    tmp_path, capsys
):
    json_path = os.path.join(tmp_path, "config.json")
    with open(json_path, "w") as fh:
        fh.write("{")
    with pytest.raises(SystemExit):
        load_config_or_exit(env_path=None, legacy_json_path=json_path, environ={})
    captured = capsys.readouterr()
    assert "invalid configuration value" not in captured.out


# ---------------------------------------------------------------------------
# 10. Unreadable .env -> SystemExit(1)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="permission bits are not enforced for root or on non-POSIX platforms",
)
def test_unreadable_dotenv_exits(tmp_path, capsys):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "1"})
    os.chmod(env_path, 0)
    try:
        if os.access(env_path, os.R_OK):
            pytest.skip("test process can still read a chmod 000 file")
        with pytest.raises(SystemExit) as exc_info:
            load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
        assert exc_info.value.code == 1
        captured = capsys.readouterr()
        # Regression guard: an unreadable file gets its own diagnostic
        # shape ("could not be read" / permissions), not the generic
        # malformed-value template.
        assert "invalid configuration value" not in captured.out
        assert "could not be read" in captured.out
        assert env_path in captured.out
    finally:
        os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# 11. Legacy JSON wrong type -> default kept, warning recorded
# ---------------------------------------------------------------------------


def test_json_wrong_type_keeps_default_and_warns(tmp_path):
    json_path = _write_json(tmp_path, {"bandrelmaxruntime": "not-an-int"})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["bandrelmaxruntime"] == BY_LEGACY["bandrelmaxruntime"].default
    assert any("bandrelmaxruntime" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# 12. Unrecognized .env key -> warning recorded, load still succeeds
# ---------------------------------------------------------------------------


def test_unrecognized_dotenv_key_warns_but_succeeds(tmp_path):
    env_path = _write_env(tmp_path, {"SOME_UNKNOWN_KEY": "value"})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert any("SOME_UNKNOWN_KEY" in w for w in result.warnings)


def test_unrecognized_config_json_key_is_tolerated_silently(tmp_path):
    """config.json has always tolerated extra keys (people keep notes and
    retired settings in there); that is unchanged, and is distinct from the
    misplaced-key warning, which fires only for a key the schema knows."""
    json_path = _write_json(tmp_path, {"some_retired_key": "value"})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.warnings == []


# ---------------------------------------------------------------------------
# 13. Legacy JSON missing keys added later -> schema defaults
# ---------------------------------------------------------------------------


def test_json_missing_new_keys_gets_defaults(tmp_path):
    json_path = _write_json(tmp_path, {"bandrelmaxruntime": 5})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["bandrelmaxruntime"] == 5
    assert (
        result.config["notify_poll_interval_seconds"]
        == BY_LEGACY["notify_poll_interval_seconds"].default
    )
    assert result.config["hcatBin"] == BY_LEGACY["hcatBin"].default


# ---------------------------------------------------------------------------
# resolve_config_paths
# ---------------------------------------------------------------------------


def test_resolve_config_paths_returns_tuple():
    env_path, legacy_json_path, warnings = resolve_config_paths()
    assert env_path is None or isinstance(env_path, str)
    assert legacy_json_path is None or isinstance(legacy_json_path, str)
    assert warnings == []


def _require_symlinks(tmp_path):
    """Skip rather than fail where symlink creation is not permitted."""
    probe = tmp_path / "_symlink-probe"
    try:
        os.symlink(tmp_path / "nothing", probe)
    except (OSError, NotImplementedError, AttributeError) as exc:
        pytest.skip(f"symlinks not supported here: {exc}")
    os.unlink(probe)


def _discover_in(monkeypatch, tmp_path):
    """Run real discovery over ``tmp_path`` only.

    conftest's ``_isolate_config_file_discovery`` empties the search order for
    every test, so a test that wants discovery to actually look at something
    has to re-patch it -- which is the point of doing it here rather than
    passing explicit paths: the bug in #227 was in discovery, not in load.
    """
    monkeypatch.setattr(config_loader, "candidate_roots", lambda: [str(tmp_path)])
    return config_loader.resolve_config_paths()


@pytest.mark.parametrize("name", [".env", "config.json"])
def test_discovery_treats_a_dangling_symlink_as_fatal(monkeypatch, tmp_path, name):
    """#227: ``os.path.isfile()`` reports a link with a missing target as
    absent, so discovery skipped it and startup ran on schema defaults -- wrong
    wordlists, wrong potfile path, no diagnostic. Discovery now raises so the
    existing dangling-symlink message fires."""
    _require_symlinks(tmp_path)
    link_path = tmp_path / name
    os.symlink(tmp_path / "does-not-exist", link_path)

    with pytest.raises(config_loader.ConfigFileUnreadableError) as exc_info:
        _discover_in(monkeypatch, tmp_path)

    assert exc_info.value.path == str(link_path)


@pytest.mark.parametrize("name", [".env", "config.json"])
def test_discovery_follows_a_valid_symlink(monkeypatch, tmp_path, name):
    """Regression guard: one config file symlinked into several checkouts is a
    supported setup and must keep resolving."""
    _require_symlinks(tmp_path)
    shared = tmp_path / "shared"
    shared.mkdir()
    target = shared / name
    target.write_text("OLLAMA_MODEL=synthetic-model\n" if name == ".env" else "{}")
    link_path = tmp_path / name
    os.symlink(target, link_path)

    env_path, json_path, _warnings = _discover_in(monkeypatch, tmp_path)

    found = env_path if name == ".env" else json_path
    assert found == str(link_path)


@pytest.mark.parametrize("name", [".env", "config.json"])
def test_discovery_does_not_warn_when_two_roots_share_one_symlinked_file(
    monkeypatch, tmp_path, name
):
    """#246 review: the shadow-warning check must not fire a false positive
    for the supported "one config symlinked into several checkouts" setup
    (see :func:`_config_file_is_usable`'s docstring and
    ``test_discovery_follows_a_valid_symlink`` above). Two candidate roots
    that both symlink to the *same* shared real file are not shadowing one
    another -- both paths resolve to the identical file, so nothing is
    actually being ignored.
    """
    _require_symlinks(tmp_path)
    shared = tmp_path / "shared"
    shared.mkdir()
    target = shared / name
    target.write_text("OLLAMA_MODEL=synthetic-model\n" if name == ".env" else "{}")

    higher = tmp_path / "higher"
    lower = tmp_path / "lower"
    higher.mkdir()
    lower.mkdir()
    higher_link = higher / name
    lower_link = lower / name
    os.symlink(target, higher_link)
    os.symlink(target, lower_link)

    monkeypatch.setattr(
        config_loader, "candidate_roots", lambda: [str(higher), str(lower)]
    )
    env_path, json_path, warnings = config_loader.resolve_config_paths()

    winner = env_path if name == ".env" else json_path
    assert winner == str(higher_link)
    assert warnings == []


def test_discovery_does_not_warn_when_one_root_is_a_symlink_to_another(
    monkeypatch, tmp_path
):
    """Same false-positive risk, other direction: a candidate *root* is
    itself a symlink to a different candidate root, so their config.json is
    the same file by construction, not two separate copies."""
    _require_symlinks(tmp_path)
    real_root = tmp_path / "real_root"
    real_root.mkdir()
    (real_root / "config.json").write_text("{}")
    linked_root = tmp_path / "linked_root"
    os.symlink(real_root, linked_root)

    monkeypatch.setattr(
        config_loader, "candidate_roots", lambda: [str(linked_root), str(real_root)]
    )
    _env_path, json_path, warnings = config_loader.resolve_config_paths()

    assert json_path == str(linked_root / "config.json")
    assert warnings == []


def test_discovery_ignores_a_directory_named_like_a_config_file(monkeypatch, tmp_path):
    """Why ``os.path.isfile()`` stays the positive test instead of collapsing
    the gate into ``os.path.exists()``: a *directory* called ``.env`` is not a
    config file, and must be neither read nor treated as a broken link."""
    (tmp_path / ".env").mkdir()
    (tmp_path / "config.json").mkdir()

    assert _discover_in(monkeypatch, tmp_path) == (None, None, [])


def test_discovery_reports_a_genuinely_absent_file_as_none(monkeypatch, tmp_path):
    assert _discover_in(monkeypatch, tmp_path) == (None, None, [])


@pytest.mark.parametrize("name", [".env", "config.json"])
def test_discovery_warns_when_a_lower_priority_file_is_shadowed(
    monkeypatch, tmp_path, name
):
    """#246: a stray file at a higher-priority candidate root (e.g. a repo
    checkout) can silently shadow a real one at a lower-priority root
    (``~/.hate_crack``) forever, with no indication anything was ignored.

    The winning path must not change -- higher-priority still wins, exactly as
    before -- but discovery must now say so, naming both paths.
    """
    higher = tmp_path / "higher"
    lower = tmp_path / "lower"
    higher.mkdir()
    lower.mkdir()
    higher_file = higher / name
    lower_file = lower / name
    body = "OLLAMA_MODEL=synthetic-model\n" if name == ".env" else "{}"
    higher_file.write_text(body)
    lower_file.write_text(body)

    monkeypatch.setattr(
        config_loader, "candidate_roots", lambda: [str(higher), str(lower)]
    )
    env_path, json_path, warnings = config_loader.resolve_config_paths()

    winner = env_path if name == ".env" else json_path
    assert winner == str(higher_file)
    assert len(warnings) == 1
    assert str(higher_file) in warnings[0]
    assert str(lower_file) in warnings[0]


def test_discovery_does_not_warn_when_only_one_root_has_the_file(monkeypatch, tmp_path):
    """A clean single-location setup -- the overwhelmingly common case --
    must produce no shadowing warning at all."""
    higher = tmp_path / "higher"
    lower = tmp_path / "lower"
    higher.mkdir()
    lower.mkdir()
    (higher / "config.json").write_text("{}")

    monkeypatch.setattr(
        config_loader, "candidate_roots", lambda: [str(higher), str(lower)]
    )
    _env_path, _json_path, warnings = config_loader.resolve_config_paths()

    assert warnings == []


def test_discovery_warns_once_per_shadowed_root_with_three_roots(monkeypatch, tmp_path):
    """``candidate_roots()`` returns three real directories (repo root,
    package directory, ``~/.hate_crack``), not two. With a distinct
    config.json at every one of them, discovery must warn once per shadowed
    (lower-priority) root -- two warnings, not one and not three -- while the
    highest-priority root still wins.
    """
    first = tmp_path / "first"
    second = tmp_path / "second"
    third = tmp_path / "third"
    for root in (first, second, third):
        root.mkdir()
        (root / "config.json").write_text("{}")

    monkeypatch.setattr(
        config_loader,
        "candidate_roots",
        lambda: [str(first), str(second), str(third)],
    )
    _env_path, json_path, warnings = config_loader.resolve_config_paths()

    assert json_path == str(first / "config.json")
    assert len(warnings) == 2
    assert all(str(first / "config.json") in w for w in warnings)
    assert any(str(second / "config.json") in w for w in warnings)
    assert any(str(third / "config.json") in w for w in warnings)
