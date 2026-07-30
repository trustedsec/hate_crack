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
    ENV_KEYS,
    JSON_KEYS,
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


# The twelve third-party integration keys: the exact home="env" set. Pinned
# literally so a key cannot quietly change home -- moving one is a
# user-visible change of which file it must be written in, and it should not
# be possible to make it by editing one word of the schema.
EXPECTED_ENV_HOMED = frozenset(
    {
        "HASHVIEW_URL",
        "HASHVIEW_API_KEY",
        "HASHMOB_API_KEY",
        "NOTIFY_PUSHOVER_TOKEN",
        "NOTIFY_PUSHOVER_USER",
        "OLLAMA_HOST",
        "OLLAMA_MODEL",
        "OLLAMA_NO_CLOUD",
        "OLLAMA_NUM_CTX",
        "OLLAMA_TIMEOUT",
        "OLLAMA_MAX_SAMPLE_LINES",
        "OLLAMA_AUTO_RESEARCH",
        "PIPAL_PATH",
        "PIPAL_COUNT",
    }
)


# ---------------------------------------------------------------------------
# 1. Drift guard -- config.json.example IS the home="json" subset
# ---------------------------------------------------------------------------


def test_config_json_example_is_exactly_the_json_homed_schema_subset():
    """Plain bidirectional equality, no allowlist.

    ``config.json`` is a first-class, permanent config file, so its example
    must document every ``home="json"`` key and nothing else. A key only in
    the example is a setting that silently stops working; a key only in the
    schema is a setting nobody can discover.
    """
    example_keys = set(_load_example().keys())
    json_homed = {entry.legacy for entry in JSON_KEYS}

    assert example_keys == json_homed, (
        f"only in config.json.example: {sorted(example_keys - json_homed)}; "
        f"only in CONFIG_SCHEMA (home='json'): {sorted(json_homed - example_keys)}"
    )


def test_env_homed_keys_are_absent_from_config_json_example():
    """The other half of one-home-per-key: an integration key must not be
    documented in config.json.example, where the loader would ignore it."""
    example_keys = set(_load_example().keys())
    env_homed = {entry.legacy for entry in ENV_KEYS}
    assert example_keys.isdisjoint(env_homed)


def test_env_homed_key_set_is_pinned():
    assert {entry.env for entry in ENV_KEYS} == EXPECTED_ENV_HOMED


def test_key_counts_are_fourteen_and_thirty_five():
    assert len(ENV_KEYS) == 14
    assert len(JSON_KEYS) == 35
    assert len(CONFIG_SCHEMA) == 49


def test_every_key_has_exactly_one_home():
    assert {entry.home for entry in CONFIG_SCHEMA} == {"env", "json"}
    assert len(ENV_KEYS) + len(JSON_KEYS) == len(CONFIG_SCHEMA)


def test_secret_keys_are_a_strict_subset_of_the_env_homed_keys():
    """ "is a secret" and "lives in .env" are different questions -- every
    secret is .env-homed, but most .env-homed keys (URLs, model names, a
    timeout) are not secrets, and the redaction logic needs the narrower set.
    """
    assert SECRET_ENV_KEYS < EXPECTED_ENV_HOMED


def test_type_counts_match_config_json_example_value_types():
    """Guard the type-derivation rule itself: schema `type` must be driven by
    the Python type of each key's value in config.json.example (bool->bool,
    int->int, float->float, list->csv_list or charset, str->str/path), not
    by whatever cast happens to appear at a main.py read site. Counting
    types is what catches a systematic derivation error that individual key
    checks would miss.

    Scoped to the ``home="json"`` keys, since those are exactly the ones
    config.json.example documents.

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
    for entry in JSON_KEYS:
        schema_type_counts[entry.type] = schema_type_counts.get(entry.type, 0) + 1

    # bool, int, float map straight across.
    assert schema_type_counts.get("bool", 0) == json_type_counts.get("bool", 0) == 6
    assert schema_type_counts.get("int", 0) == json_type_counts.get("int", 0) == 6
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
    assert str_and_path == json_type_counts.get("str_or_path", 0) == 15
    assert schema_type_counts.get("path", 0) == 3
    assert schema_type_counts.get("str", 0) == 12


def test_defaults_match_config_json_example():
    example = _load_example()
    mismatches = []
    for entry in JSON_KEYS:
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


def test_no_env_homed_key_is_list_typed():
    """Why QUOTE_REQUIRED_TYPES and the charset/csv_list emitters are gone.

    Unconditional quoting existed for ``charset``, whose leading/trailing
    space elements python-dotenv would otherwise strip. No integration key is
    list-typed, so nothing is ever emitted to `.env` that needs it -- and the
    day one is, this test fails before the silently-lossy write can ship.
    """
    assert all(entry.type not in ("charset", "csv_list") for entry in ENV_KEYS)


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
