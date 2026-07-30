"""Tests for hate_crack.config_schema: the schema table and coercers.

These tests use synthetic key names for coercion-only checks so they do not
break when a real default value changes; the drift-guard test is the one
place we compare against the real config.json.example.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from hate_crack.config_schema import (
    BY_ENV,
    BY_LEGACY,
    CONFIG_SCHEMA,
    QUOTE_REQUIRED_TYPES,
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


def test_type_counts_match_config_json_example_value_types():
    """Guard the type-derivation rule itself: schema `type` must be driven by
    the Python type of each key's value in config.json.example (bool->bool,
    int->int, float->float, list->csv_list or charset, str->str/path), not
    by whatever cast happens to appear at a main.py read site. Counting
    types is what catches a systematic derivation error that individual key
    checks would miss.

    ``list`` splits into ``csv_list`` (5) and ``charset`` (2):
    hcatMiddleCombinatorMasks and hcatThoroughCombinatorMasks are lists of
    single characters (including a literal "," and " ") that csv_list's
    join/split/strip rules cannot represent losslessly, so they get the
    dedicated ``charset`` type instead.
    """
    example = _load_example()
    json_type_counts: dict[str, int] = {}
    for value in example.values():
        # bool must be checked before int: bool is an int subclass in Python.
        if isinstance(value, bool):
            json_type_counts["bool"] = json_type_counts.get("bool", 0) + 1
        elif isinstance(value, int):
            json_type_counts["int"] = json_type_counts.get("int", 0) + 1
        elif isinstance(value, float):
            json_type_counts["float"] = json_type_counts.get("float", 0) + 1
        elif isinstance(value, list):
            json_type_counts["list"] = json_type_counts.get("list", 0) + 1
        elif isinstance(value, str):
            json_type_counts["str_or_path"] = json_type_counts.get("str_or_path", 0) + 1

    schema_type_counts: dict[str, int] = {}
    for entry in CONFIG_SCHEMA:
        schema_type_counts[entry.type] = schema_type_counts.get(entry.type, 0) + 1

    # bool, int, float map straight across.
    assert schema_type_counts.get("bool", 0) == json_type_counts.get("bool", 0) == 5
    assert schema_type_counts.get("int", 0) == json_type_counts.get("int", 0) == 9
    assert schema_type_counts.get("float", 0) == json_type_counts.get("float", 0) == 1
    # list splits into csv_list/charset; the two must sum to the JSON list count.
    list_derived = schema_type_counts.get("csv_list", 0) + schema_type_counts.get(
        "charset", 0
    )
    assert list_derived == json_type_counts.get("list", 0) == 7
    assert schema_type_counts.get("csv_list", 0) == 5
    assert schema_type_counts.get("charset", 0) == 2
    # str splits into str/path; the two must sum to the JSON str count.
    str_and_path = schema_type_counts.get("str", 0) + schema_type_counts.get("path", 0)
    assert str_and_path == json_type_counts.get("str_or_path", 0) == 21
    assert schema_type_counts.get("path", 0) == 3
    assert schema_type_counts.get("str", 0) == 18


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


@pytest.mark.parametrize(
    "entry",
    [entry for entry in CONFIG_SCHEMA if entry.type == "csv_list"],
    ids=lambda entry: entry.legacy,
)
def test_csv_list_defaults_round_trip_through_join_and_coerce(entry):
    """Every csv_list default must survive Task 3's emitter (join on ',')
    followed by this module's parser unchanged. optimizedKernelAttacks is
    the largest such list (22 elements) and the one Task 3 will emit.

    hcatMiddleCombinatorMasks and hcatThoroughCombinatorMasks are NOT in
    this parametrization: they are ``charset``, not ``csv_list``, precisely
    because their single-character defaults (including a literal "," and
    " ") cannot round-trip through comma-join. See
    test_charset_defaults_round_trip_through_join_and_coerce below.
    """
    emitted = ",".join(entry.default)
    assert coerce(entry, emitted) == entry.default


# ---------------------------------------------------------------------------
# 8. path coercion
# ---------------------------------------------------------------------------

_PATH_ENTRY = ConfigKey("SYNTH_PATH", "synth_path", "path", "")


def test_path_expands_tilde():
    result = coerce(_PATH_ENTRY, "~/synthetic_dir")
    assert result == os.path.expanduser("~/synthetic_dir")
    assert not result.startswith("~")


def test_path_empty_string_stays_empty():
    assert coerce(_PATH_ENTRY, "") == ""


# ---------------------------------------------------------------------------
# 10. charset coercion
# ---------------------------------------------------------------------------

_CHARSET_ENTRY = ConfigKey("SYNTH_CHARSET", "synth_charset", "charset", [])


def test_charset_splits_into_one_element_per_character():
    assert coerce(_CHARSET_ENTRY, "24 -_+,.&") == [
        "2",
        "4",
        " ",
        "-",
        "_",
        "+",
        ",",
        ".",
        "&",
    ]


def test_charset_does_not_strip_whitespace():
    # A leading/trailing space is a real element for this type.
    assert coerce(_CHARSET_ENTRY, " a ") == [" ", "a", " "]


def test_charset_empty_string_yields_empty_list():
    assert coerce(_CHARSET_ENTRY, "") == []


@pytest.mark.parametrize(
    "entry",
    [entry for entry in CONFIG_SCHEMA if entry.type == "charset"],
    ids=lambda entry: entry.legacy,
)
def test_charset_defaults_round_trip_through_join_and_coerce(entry):
    """charset must be lossless for exactly the two keys csv_list could not
    represent: hcatMiddleCombinatorMasks and hcatThoroughCombinatorMasks,
    whose defaults contain a literal "," and " " element."""
    emitted = "".join(entry.default)
    assert coerce(entry, emitted) == entry.default


def test_charset_is_in_quote_required_types():
    # python-dotenv strips unquoted values, so Task 3 must quote charset
    # values in the .env file or a leading/trailing space element is lost.
    assert "charset" in QUOTE_REQUIRED_TYPES


def test_quote_required_types_does_not_include_ordinary_types():
    assert QUOTE_REQUIRED_TYPES.isdisjoint({"str", "int", "float", "bool", "path"})


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
