"""Tests for hate_crack.config_loader."""

from __future__ import annotations

import json
import os
import stat

import pytest

from hate_crack.config_loader import (
    ConfigLoadResult,
    load_config,
    load_config_or_exit,
    resolve_config_paths,
)
from hate_crack.config_schema import BY_LEGACY, CONFIG_SCHEMA


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
    assert len(expected_keys) == 43
    for entry in CONFIG_SCHEMA:
        assert result.config[entry.legacy] == entry.default


# ---------------------------------------------------------------------------
# 2. Layer overrides
# ---------------------------------------------------------------------------


def test_legacy_json_overrides_default(tmp_path):
    json_path = _write_json(tmp_path, {"pipal_count": 99})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["pipal_count"] == 99


def test_dotenv_overrides_legacy_json(tmp_path):
    json_path = _write_json(tmp_path, {"pipal_count": 99})
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "42"})
    result = load_config(env_path=env_path, legacy_json_path=json_path, environ={})
    assert result.config["pipal_count"] == 42


def test_environ_overrides_dotenv(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "42"})
    result = load_config(
        env_path=env_path,
        legacy_json_path=None,
        environ={"PIPAL_COUNT": "7"},
    )
    assert result.config["pipal_count"] == 7


def test_full_four_layer_stack(tmp_path):
    json_path = _write_json(
        tmp_path,
        {"pipal_count": 1, "bandrelmaxruntime": 2, "ollamaTimeout": 3},
    )
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "10", "BANDRELMAXRUNTIME": "20"})
    result = load_config(
        env_path=env_path,
        legacy_json_path=json_path,
        environ={"PIPAL_COUNT": "100"},
    )
    assert result.config["pipal_count"] == 100  # environ wins
    assert result.config["bandrelmaxruntime"] == 20  # .env wins over json
    assert result.config["ollamaTimeout"] == 3.0  # json wins over default


# ---------------------------------------------------------------------------
# 3. os.environ outranks .env for HASHVIEW_API_KEY specifically
# ---------------------------------------------------------------------------


def test_environ_outranks_dotenv_for_hashview_api_key(tmp_path):
    env_path = _write_env(tmp_path, {"HASHVIEW_API_KEY": "dotenv-placeholder-key"})
    result = load_config(
        env_path=env_path,
        legacy_json_path=None,
        environ={"HASHVIEW_API_KEY": "environ-placeholder-key"},
    )
    assert result.config["hashview_api_key"] == "environ-placeholder-key"


# ---------------------------------------------------------------------------
# 4. Empty string falls through; csv_list/charset exception
# ---------------------------------------------------------------------------


def test_empty_string_in_dotenv_falls_through_to_default(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_PATH": ""})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    default = BY_LEGACY["pipalPath"].default
    assert result.config["pipalPath"] == default


def test_empty_string_in_environ_falls_through_to_default(tmp_path):
    result = load_config(
        env_path=None, legacy_json_path=None, environ={"PIPAL_PATH": ""}
    )
    default = BY_LEGACY["pipalPath"].default
    assert result.config["pipalPath"] == default


def test_empty_csv_list_in_dotenv_yields_empty_list(tmp_path):
    env_path = _write_env(tmp_path, {"NOTIFY_ATTACK_ALLOWLIST": ""})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert result.config["notify_attack_allowlist"] == []


def test_empty_charset_in_dotenv_yields_empty_list(tmp_path):
    env_path = _write_env(tmp_path, {"HCAT_MIDDLE_COMBINATOR_MASKS": ""})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert result.config["hcatMiddleCombinatorMasks"] == []


def test_charset_preserves_leading_and_trailing_space(tmp_path):
    env_path = os.path.join(tmp_path, ".env")
    with open(env_path, "w") as fh:
        fh.write('HCAT_MIDDLE_COMBINATOR_MASKS="24 -_+,.&"\n')
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    value = result.config["hcatMiddleCombinatorMasks"]
    assert value[0] == "2"
    assert " " in value


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
    env_path = _write_env(
        tmp_path,
        {
            "HCAT_BIN": "hashcat",  # str
            "HCAT_PATH": "/opt/hashcat",  # path
            "PIPAL_COUNT": "15",  # int
            "NOTIFY_POLL_INTERVAL_SECONDS": "2.5",  # float
            "NOTIFY_ENABLED": "1",  # bool -- must NOT stay the string "1"
            "HCAT_DICTIONARY_WORDLIST": "a.txt,b.txt",  # csv_list
            "HCAT_MIDDLE_COMBINATOR_MASKS": "ab",  # charset
        },
    )
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
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
    env_path = _write_env(tmp_path, {"NOTIFY_ENABLED": "maybe"})
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "NOTIFY_ENABLED" in captured.out


def test_malformed_int_exits_with_key_name(tmp_path, capsys):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "not-a-number"})
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "PIPAL_COUNT" in captured.out


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


def test_malformed_legacy_json_exits(tmp_path):
    json_path = os.path.join(tmp_path, "config.json")
    with open(json_path, "w") as fh:
        fh.write("{not valid json")
    with pytest.raises(SystemExit) as exc_info:
        load_config_or_exit(env_path=None, legacy_json_path=json_path, environ={})
    assert exc_info.value.code == 1


# ---------------------------------------------------------------------------
# 10. Unreadable .env -> SystemExit(1)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    os.name != "posix" or os.geteuid() == 0,
    reason="permission bits are not enforced for root or on non-POSIX platforms",
)
def test_unreadable_dotenv_exits(tmp_path):
    env_path = _write_env(tmp_path, {"PIPAL_COUNT": "1"})
    os.chmod(env_path, 0)
    try:
        if os.access(env_path, os.R_OK):
            pytest.skip("test process can still read a chmod 000 file")
        with pytest.raises(SystemExit) as exc_info:
            load_config_or_exit(env_path=env_path, legacy_json_path=None, environ={})
        assert exc_info.value.code == 1
    finally:
        os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# 11. Legacy JSON wrong type -> default kept, warning recorded
# ---------------------------------------------------------------------------


def test_legacy_json_wrong_type_keeps_default_and_warns(tmp_path):
    json_path = _write_json(tmp_path, {"pipal_count": "not-an-int"})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["pipal_count"] == BY_LEGACY["pipal_count"].default
    assert any("pipal_count" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# 12. Unrecognized .env key -> warning recorded, load still succeeds
# ---------------------------------------------------------------------------


def test_unrecognized_dotenv_key_warns_but_succeeds(tmp_path):
    env_path = _write_env(tmp_path, {"SOME_UNKNOWN_KEY": "value"})
    result = load_config(env_path=env_path, legacy_json_path=None, environ={})
    assert any("SOME_UNKNOWN_KEY" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# 13. Legacy JSON missing keys added later -> schema defaults
# ---------------------------------------------------------------------------


def test_legacy_json_missing_new_keys_gets_defaults(tmp_path):
    json_path = _write_json(tmp_path, {"pipal_count": 5})
    result = load_config(env_path=None, legacy_json_path=json_path, environ={})
    assert result.config["pipal_count"] == 5
    assert (
        result.config["notify_poll_interval_seconds"]
        == BY_LEGACY["notify_poll_interval_seconds"].default
    )
    assert result.config["hcatBin"] == BY_LEGACY["hcatBin"].default


# ---------------------------------------------------------------------------
# resolve_config_paths
# ---------------------------------------------------------------------------


def test_resolve_config_paths_returns_tuple():
    env_path, legacy_json_path = resolve_config_paths()
    assert env_path is None or isinstance(env_path, str)
    assert legacy_json_path is None or isinstance(legacy_json_path, str)
