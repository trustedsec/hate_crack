"""Tests for hate_crack.config_schema: the schema table and coercers.

These tests use synthetic key names for coercion-only checks so they do not
break when a real default value changes; the drift-guard test is the one
place we compare against the real config.json.example.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hate_crack.config_schema import (
    BY_ENV,
    BY_LEGACY,
    CONFIG_SCHEMA,
    SECRET_ENV_KEYS,
    ConfigKey,
    ConfigValueError,
    coerce,
)

EXAMPLE_PATH = (
    Path(__file__).resolve().parents[1] / "hate_crack" / "config.json.example"
)


def _load_example() -> dict:
    return json.loads(EXAMPLE_PATH.read_text())


# ---------------------------------------------------------------------------
# 1. Drift guard
# ---------------------------------------------------------------------------


def test_legacy_keys_match_config_json_example():
    example = _load_example()
    example_keys = set(example.keys())
    schema_keys = set(BY_LEGACY.keys())

    only_in_example = example_keys - schema_keys
    only_in_schema = schema_keys - example_keys

    assert not only_in_example and not only_in_schema, (
        f"config.json.example has keys missing from CONFIG_SCHEMA: "
        f"{sorted(only_in_example)}; CONFIG_SCHEMA has keys missing from "
        f"config.json.example: {sorted(only_in_schema)}"
    )


def test_defaults_match_config_json_example():
    example = _load_example()
    mismatches = []
    for entry in CONFIG_SCHEMA:
        example_value = example[entry.legacy]
        if entry.default != example_value:
            mismatches.append(
                f"{entry.legacy!r}: schema default={entry.default!r} != "
                f"config.json.example value={example_value!r}"
            )
    assert not mismatches, "Default drift from config.json.example:\n" + "\n".join(
        mismatches
    )


# ---------------------------------------------------------------------------
# 2. Uniqueness
# ---------------------------------------------------------------------------


def test_env_names_are_unique():
    envs = [entry.env for entry in CONFIG_SCHEMA]
    assert len(envs) == len(set(envs))
    assert len(BY_ENV) == len(CONFIG_SCHEMA)


def test_legacy_names_are_unique():
    legacies = [entry.legacy for entry in CONFIG_SCHEMA]
    assert len(legacies) == len(set(legacies))
    assert len(BY_LEGACY) == len(CONFIG_SCHEMA)


# ---------------------------------------------------------------------------
# 3. Pinned names
# ---------------------------------------------------------------------------


def test_pinned_hashview_url():
    entry = BY_LEGACY["hashview_url"]
    assert entry.env == "HASHVIEW_URL"
    assert BY_ENV["HASHVIEW_URL"] is entry


def test_pinned_hashview_api_key():
    entry = BY_LEGACY["hashview_api_key"]
    assert entry.env == "HASHVIEW_API_KEY"
    assert BY_ENV["HASHVIEW_API_KEY"] is entry


def test_pinned_hashmob_api_key():
    entry = BY_LEGACY["hashmob_api_key"]
    assert entry.env == "HASHMOB_API_KEY"
    assert BY_ENV["HASHMOB_API_KEY"] is entry


# ---------------------------------------------------------------------------
# 4/5. bool coercion
# ---------------------------------------------------------------------------

_BOOL_ENTRY = ConfigKey("SYNTH_BOOL", "synth_bool", "bool", False)

_TRUE_TOKENS = ["1", "true", "yes", "on"]
_FALSE_TOKENS = ["0", "false", "no", "off"]


@pytest.mark.parametrize("token", _TRUE_TOKENS)
def test_bool_accepts_true_tokens_both_cases(token):
    assert coerce(_BOOL_ENTRY, token) is True
    assert coerce(_BOOL_ENTRY, token.upper()) is True


@pytest.mark.parametrize("token", _FALSE_TOKENS)
def test_bool_accepts_false_tokens_both_cases(token):
    assert coerce(_BOOL_ENTRY, token) is False
    assert coerce(_BOOL_ENTRY, token.upper()) is False


def test_bool_tolerates_surrounding_whitespace():
    assert coerce(_BOOL_ENTRY, "  true  ") is True
    assert coerce(_BOOL_ENTRY, "  0 ") is False


@pytest.mark.parametrize("bad", ["ture", "", "2", "none"])
def test_bool_rejects_invalid_tokens(bad):
    with pytest.raises(ConfigValueError):
        coerce(_BOOL_ENTRY, bad)


def test_bool_never_uses_python_truthiness():
    # bool("false") is True in plain Python -- must not leak through.
    with pytest.raises(ConfigValueError):
        coerce(_BOOL_ENTRY, "false-ish")


# ---------------------------------------------------------------------------
# 6. int / float coercion
# ---------------------------------------------------------------------------

_INT_ENTRY = ConfigKey("SYNTH_INT", "synth_int", "int", 0)
_FLOAT_ENTRY = ConfigKey("SYNTH_FLOAT", "synth_float", "float", 0.0)


def test_int_parses_valid_values():
    assert coerce(_INT_ENTRY, "42") == 42
    assert coerce(_INT_ENTRY, "-7") == -7


@pytest.mark.parametrize("bad", ["not-a-number", "3.5", "", "12abc"])
def test_int_rejects_malformed_values(bad):
    with pytest.raises(ConfigValueError):
        coerce(_INT_ENTRY, bad)


def test_float_parses_valid_values():
    assert coerce(_FLOAT_ENTRY, "3.14") == 3.14
    assert coerce(_FLOAT_ENTRY, "-2") == -2.0


@pytest.mark.parametrize("bad", ["not-a-number", "", "1.2.3"])
def test_float_rejects_malformed_values(bad):
    with pytest.raises(ConfigValueError):
        coerce(_FLOAT_ENTRY, bad)


# ---------------------------------------------------------------------------
# 7. csv_list coercion
# ---------------------------------------------------------------------------

_CSV_ENTRY = ConfigKey("SYNTH_CSV", "synth_csv", "csv_list", [])


def test_csv_list_normal():
    assert coerce(_CSV_ENTRY, "a,b,c") == ["a", "b", "c"]


def test_csv_list_single_element():
    assert coerce(_CSV_ENTRY, "a") == ["a"]


def test_csv_list_empty_string():
    assert coerce(_CSV_ENTRY, "") == []


def test_csv_list_whitespace_only():
    assert coerce(_CSV_ENTRY, "   ") == []


def test_csv_list_trailing_comma():
    assert coerce(_CSV_ENTRY, "a,b,") == ["a", "b"]


def test_csv_list_interior_spaces():
    assert coerce(_CSV_ENTRY, " a , b , c ") == ["a", "b", "c"]


def test_csv_list_never_produces_list_of_empty_string():
    assert coerce(_CSV_ENTRY, "") != [""]
    assert coerce(_CSV_ENTRY, "   ") != [""]


# ---------------------------------------------------------------------------
# 8. path coercion
# ---------------------------------------------------------------------------

_PATH_ENTRY = ConfigKey("SYNTH_PATH", "synth_path", "path", "")


def test_path_expands_tilde():
    import os

    result = coerce(_PATH_ENTRY, "~/synthetic_dir")
    assert result == os.path.expanduser("~/synthetic_dir")
    assert not result.startswith("~")


def test_path_empty_string_stays_empty():
    assert coerce(_PATH_ENTRY, "") == ""


# ---------------------------------------------------------------------------
# 9. Secret redaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("secret_env", sorted(SECRET_ENV_KEYS))
def test_secret_value_never_appears_in_error_message(secret_env):
    entry = ConfigKey(secret_env, secret_env.lower(), "int", 0)
    offending_value = "definitely-not-an-int-synthetic-sentinel"
    with pytest.raises(ConfigValueError) as exc_info:
        coerce(entry, offending_value)
    assert offending_value not in str(exc_info.value)
    assert "<redacted>" in str(exc_info.value)


def test_secret_env_keys_contains_expected_members():
    assert SECRET_ENV_KEYS == frozenset(
        {
            "HASHVIEW_API_KEY",
            "HASHMOB_API_KEY",
            "NOTIFY_PUSHOVER_TOKEN",
            "NOTIFY_PUSHOVER_USER",
        }
    )


def test_non_secret_error_message_includes_raw_value():
    with pytest.raises(ConfigValueError) as exc_info:
        coerce(_INT_ENTRY, "not-an-int")
    assert "not-an-int" in str(exc_info.value)
