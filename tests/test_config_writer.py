"""Tests for hate_crack.config_writer: the `.env` serializer and the
one-shot config.json -> .env migration.

No real-looking passwords, API keys, or tokens appear anywhere below --
synthetic placeholders only (e.g. "synthetic-token-not-a-real-secret").
"""

from __future__ import annotations

import json
import os
import stat

import pytest
from dotenv import dotenv_values

from hate_crack.config_loader import load_config
from hate_crack.config_schema import BY_ENV, CONFIG_SCHEMA, coerce
from hate_crack.config_writer import (
    BY_ENV_NAME,
    EnvFileExistsError,
    emit_value,
    render_env,
    write_env,
    write_env_from_legacy,
)

DEFAULTS: dict[str, object] = {entry.legacy: entry.default for entry in CONFIG_SCHEMA}


def _expected_after_roundtrip(entry, value):
    """coerce(entry, emit_value(entry, value)) -- what a round-trip yields.

    Only differs from ``value`` for ``path``, where coercion expands ``~``;
    that's a property of the type, not a bug in the writer.
    """
    return coerce(entry, emit_value(entry, value))


# ---------------------------------------------------------------------------
# Deliverable A/B: emit_value + quoting, proven through the real dotenv parser
# ---------------------------------------------------------------------------


def test_all_defaults_roundtrip_through_dotenv_values(tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), DEFAULTS)

    parsed = dotenv_values(str(env_path))
    for entry in CONFIG_SCHEMA:
        raw = parsed[entry.env]
        assert raw is not None
        got = coerce(entry, raw)
        assert got == _expected_after_roundtrip(entry, entry.default), entry.env


def test_thorough_combinator_masks_explicit_roundtrip(tmp_path):
    entry = BY_ENV_NAME["HCAT_THOROUGH_COMBINATOR_MASKS"]
    assert entry.default == list(entry.default)
    assert len(entry.default) == 43
    for ch in ('"', "\\", "'", " ", ","):
        assert ch in entry.default

    env_path = tmp_path / ".env"
    write_env(str(env_path), DEFAULTS)
    parsed = dotenv_values(str(env_path))
    raw = parsed["HCAT_THOROUGH_COMBINATOR_MASKS"]
    assert raw is not None
    got = coerce(entry, raw)
    assert got == entry.default


def test_bool_emits_canonical_1_or_0(tmp_path):
    entry = BY_ENV_NAME["OLLAMA_AUTO_RESEARCH"]
    assert entry.type == "bool"
    config = dict(DEFAULTS)
    config[entry.legacy] = True
    text = render_env(config)
    assert "\nOLLAMA_AUTO_RESEARCH=1\n" in text

    config[entry.legacy] = False
    text = render_env(config)
    assert "\nOLLAMA_AUTO_RESEARCH=0\n" in text


@pytest.mark.parametrize(
    "env_name,value",
    [
        ("HCAT_MIDDLE_COMBINATOR_MASKS", [" ", "a", " "]),
        ("HCAT_DICTIONARY_WORDLIST", ["only-one.txt"]),
        ("NOTIFY_ATTACK_ALLOWLIST", []),
        ("HCAT_BIN", "has#a-comment-char"),
        ("HCAT_BIN", "has=an-equals"),
        ("HCAT_POTFILE_PATH", "~/.hashcat/custom.potfile"),
    ],
)
def test_nondefault_values_roundtrip(tmp_path, env_name, value):
    entry = BY_ENV_NAME[env_name]
    config = dict(DEFAULTS)
    config[entry.legacy] = value
    env_path = tmp_path / ".env"
    write_env(str(env_path), config)

    parsed = dotenv_values(str(env_path))
    raw = parsed[env_name]
    assert raw is not None
    got = coerce(entry, raw)
    assert got == _expected_after_roundtrip(entry, value)


def test_string_with_newline_is_supported_and_roundtrips(tmp_path):
    """Decision: a str/csv-element value containing a newline is supported.

    emit_value() passes the raw string through; render_line() quotes it
    (because the raw newline is one of the forced-quote characters) and
    backslash-escapes it as ``\\n`` inside the quotes, matching how
    python-dotenv itself round-trips an escaped newline in a quoted value.
    """
    entry = BY_ENV_NAME["HCAT_BIN"]
    value = "line-one\nline-two"
    config = dict(DEFAULTS)
    config[entry.legacy] = value
    env_path = tmp_path / ".env"
    write_env(str(env_path), config)

    parsed = dotenv_values(str(env_path))
    raw = parsed["HCAT_BIN"]
    assert raw is not None
    assert coerce(entry, raw) == value


# ---------------------------------------------------------------------------
# Deliverable C: write_env mechanics
# ---------------------------------------------------------------------------


def test_write_env_mode_is_0600(tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), DEFAULTS)
    mode = stat.S_IMODE(os.stat(env_path).st_mode)
    assert mode == 0o600


def test_write_env_refuses_overwrite_without_flag(tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), DEFAULTS)
    with pytest.raises(EnvFileExistsError):
        write_env(str(env_path), DEFAULTS)

    # succeeds with overwrite=True
    write_env(str(env_path), DEFAULTS, overwrite=True)


def test_write_env_idempotent(tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), DEFAULTS)
    first = env_path.read_bytes()
    write_env(str(env_path), DEFAULTS, overwrite=True)
    second = env_path.read_bytes()
    assert first == second


def test_write_env_atomic_on_failure_leaves_no_partial_file(tmp_path, monkeypatch):
    env_path = tmp_path / ".env"

    def _boom(entry, value):
        raise RuntimeError("simulated failure mid-render")

    monkeypatch.setattr("hate_crack.config_writer.emit_value", _boom)
    with pytest.raises(RuntimeError):
        write_env(str(env_path), DEFAULTS)

    assert not env_path.exists()
    leftovers = [p for p in tmp_path.iterdir() if p.name.startswith(".env-")]
    assert leftovers == []


# ---------------------------------------------------------------------------
# Deliverable D: write_env_from_legacy
# ---------------------------------------------------------------------------


def _legacy_defaults_json() -> dict:
    return {entry.legacy: entry.default for entry in CONFIG_SCHEMA}


def test_migration_carries_overrides_and_defaults_missing_keys(tmp_path):
    legacy = _legacy_defaults_json()
    legacy["hcatBin"] = "hashcat-custom"
    del legacy["pipal_count"]  # missing -> schema default
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    parsed = dotenv_values(str(env_path))
    assert coerce(BY_ENV["HCAT_BIN"], parsed["HCAT_BIN"]) == "hashcat-custom"
    assert coerce(BY_ENV["PIPAL_COUNT"], parsed["PIPAL_COUNT"]) == 10
    assert notes == []


def test_migration_drops_unrecognized_key_with_note(tmp_path):
    legacy = _legacy_defaults_json()
    legacy["some_retired_key"] = "synthetic-value"
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    parsed = dotenv_values(str(env_path))
    assert all(not name.upper().endswith("SOME_RETIRED_KEY") for name in parsed)
    assert any("some_retired_key" in note for note in notes)
    assert not any("synthetic-value" in note for note in notes)


def test_migration_type_mismatch_writes_default_with_note(tmp_path):
    legacy = _legacy_defaults_json()
    legacy["pipal_count"] = "not-an-int"  # schema type is int
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    parsed = dotenv_values(str(env_path))
    assert coerce(BY_ENV["PIPAL_COUNT"], parsed["PIPAL_COUNT"]) == 10
    assert any("pipal_count" in note for note in notes)
    assert not any("not-an-int" in note for note in notes)


def test_migration_does_not_touch_legacy_file(tmp_path):
    legacy = _legacy_defaults_json()
    legacy_path = tmp_path / "config.json"
    original_bytes = json.dumps(legacy).encode()
    legacy_path.write_bytes(original_bytes)

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    assert legacy_path.read_bytes() == original_bytes


def test_migration_notes_never_contain_secret_values(tmp_path):
    legacy = _legacy_defaults_json()
    legacy["hashview_api_key"] = ["not", "a", "string"]  # type mismatch
    legacy["notify_pushover_token"] = 12345  # type mismatch
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    joined = "\n".join(notes)
    assert "12345" not in joined
    assert "not', 'a', 'string" not in joined
    assert repr(["not", "a", "string"]) not in joined


# ---------------------------------------------------------------------------
# Deliverable E.10: end-to-end equivalence with load_config
# ---------------------------------------------------------------------------


def test_migration_then_load_matches_loading_legacy_directly(tmp_path):
    legacy = _legacy_defaults_json()
    legacy["hcatBin"] = "hashcat-custom"
    legacy["pipal_count"] = 42
    legacy["bandrelmaxruntime"] = 600
    legacy["ollamaTimeout"] = 900
    legacy["ollamaAutoResearch"] = False
    legacy["notify_poll_interval_seconds"] = 2.5
    legacy["hcatDictionaryWordlist"] = ["custom.txt", "extra.txt"]
    legacy["hcatMiddleCombinatorMasks"] = [" ", ",", "\\", '"', "'"]
    legacy["notify_attack_allowlist"] = []
    # Deliberately not using "~" here: config_loader's legacy-json layer
    # passes path values through raw (main.py expands them downstream at
    # consumption sites), while its .env layer expands via coerce()
    # immediately. That pre-existing (Task 2) asymmetry means a "~" value
    # legitimately differs between the two load paths this test compares --
    # see the config_writer report for the flagged concern.
    legacy["hcatPotfilePath"] = "/tmp/other.potfile"
    legacy["hcatDebugLogPath"] = "/tmp/other_debug"
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    via_migration = load_config(env_path=str(env_path), legacy_json_path=None).config
    via_legacy_directly = load_config(
        env_path=None, legacy_json_path=str(legacy_path)
    ).config

    assert via_migration == via_legacy_directly
