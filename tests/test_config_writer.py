"""Tests for hate_crack.config_writer: the `.env` serializer and the
one-shot lift of the integration keys out of an old config.json.

The writer owns the ``home="env"`` keys, so every assertion below is scoped to
``ENV_KEYS``. Its one reach into ``config.json`` is the migration's prune of
the keys it just copied out.

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
from hate_crack.config_schema import BY_ENV, CONFIG_SCHEMA, ENV_KEYS, JSON_KEYS, coerce
from hate_crack.config_writer import (
    BY_ENV_NAME,
    EnvFileExistsError,
    emit_value,
    render_env,
    write_env,
    write_env_from_legacy,
)

DEFAULTS: dict[str, object] = {entry.legacy: entry.default for entry in ENV_KEYS}


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
    for entry in ENV_KEYS:
        raw = parsed[entry.env]
        assert raw is not None
        got = coerce(entry, raw)
        assert got == _expected_after_roundtrip(entry, entry.default), entry.env


def test_env_file_holds_exactly_the_integration_keys(tmp_path):
    """The writer no longer emits all 49 keys. A json-homed key appearing here
    would be a key the loader then ignores with a warning -- i.e. a file we
    generated and then complained about."""
    env_path = tmp_path / ".env"
    write_env(str(env_path), DEFAULTS)

    parsed = dotenv_values(str(env_path))
    assert set(parsed) == {entry.env for entry in ENV_KEYS}
    assert len(parsed) == 14


def test_json_homed_values_in_the_input_are_not_rendered(tmp_path):
    """render_env() is handed a full config_parser-shaped dict at startup, so
    it must silently skip the 35 settings rather than emit them."""
    config = dict(DEFAULTS)
    config.update({entry.legacy: entry.default for entry in JSON_KEYS})
    config["hcatTuning"] = "-w 4"
    text = render_env(config)
    assert "HCAT_TUNING" not in text
    assert "-w 4" not in text


@pytest.mark.parametrize("entry", ENV_KEYS, ids=lambda e: e.env)
def test_no_integration_key_needs_a_list_emitter(entry):
    """Why emit_value()'s csv_list/charset branches were deleted."""
    assert entry.type in ("str", "path", "int", "bool", "float")


def test_emit_value_refuses_a_list_type_loudly():
    """The deletion is a hard failure, not a silent fallback: adding a
    list-typed key to `.env` must break here rather than emit a form that
    cannot round-trip a "," or a leading space."""
    charset_entry = next(e for e in CONFIG_SCHEMA if e.type == "charset")
    with pytest.raises(AssertionError):
        emit_value(charset_entry, charset_entry.default)
    csv_entry = next(e for e in CONFIG_SCHEMA if e.type == "csv_list")
    with pytest.raises(AssertionError):
        emit_value(csv_entry, csv_entry.default)


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
        ("OLLAMA_MODEL", "has#a-comment-char"),
        ("OLLAMA_MODEL", "has=an-equals"),
        ("OLLAMA_MODEL", "  leading-and-trailing-spaces  "),
        ("OLLAMA_MODEL", ""),
        ("PIPAL_PATH", "~/tools/pipal"),
        ("PIPAL_COUNT", 0),
        ("HASHVIEW_URL", "http://example.invalid:8443"),
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


@pytest.mark.parametrize(
    "value",
    [
        " leading-space",
        "trailing-space ",
        "  both-ends  ",
        "interior  double-space",
    ],
    ids=["leading", "trailing", "both", "interior"],
)
def test_plain_str_whitespace_survives_the_round_trip(tmp_path, value):
    """#227 item 3: ``_needs_quoting`` is type-agnostic, and the ``charset``
    keys prove that for values that always contain a space -- but no test
    covered an ordinary ``str`` whose whitespace is only incidental. Written to
    a real file and read back with ``dotenv_values()``, because asserting
    against the emitter alone would not prove the quoting is right.
    """
    entry = BY_ENV_NAME["OLLAMA_MODEL"]
    assert entry.type == "str"
    config = dict(DEFAULTS)
    config[entry.legacy] = value
    env_path = tmp_path / ".env"
    write_env(str(env_path), config)

    parsed = dotenv_values(str(env_path))
    raw = parsed["OLLAMA_MODEL"]
    assert raw is not None
    assert coerce(entry, raw) == value
    # And through the loader, which is what actually consumes the file.
    assert load_config(env_path=str(env_path), environ={}).config[entry.legacy] == value


def test_string_with_newline_is_supported_and_roundtrips(tmp_path):
    """Decision: a str/csv-element value containing a newline is supported.

    emit_value() passes the raw string through; render_line() quotes it
    (because the raw newline is one of the forced-quote characters) and
    backslash-escapes it as ``\\n`` inside the quotes, matching how
    python-dotenv itself round-trips an escaped newline in a quoted value.
    """
    entry = BY_ENV_NAME["OLLAMA_MODEL"]
    value = "line-one\nline-two"
    config = dict(DEFAULTS)
    config[entry.legacy] = value
    env_path = tmp_path / ".env"
    write_env(str(env_path), config)

    parsed = dotenv_values(str(env_path))
    raw = parsed["OLLAMA_MODEL"]
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
# write_env_from_legacy: lift the twelve out, leave config.json alone
# ---------------------------------------------------------------------------


def _legacy_config_json(**overrides) -> dict:
    """A pre-split config.json: all 47 keys, integration ones included."""
    data = {entry.legacy: entry.default for entry in CONFIG_SCHEMA}
    data.update(overrides)
    return data


def test_migration_carries_exactly_the_twelve_integration_keys(tmp_path):
    legacy = _legacy_config_json(
        ollamaModel="synthetic-model",
        pipal_count=3,
        hcatBin="hashcat-custom",  # json-homed: must NOT be carried over
    )
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    parsed = dotenv_values(str(env_path))
    assert set(parsed) == {entry.env for entry in ENV_KEYS}
    assert coerce(BY_ENV["OLLAMA_MODEL"], parsed["OLLAMA_MODEL"]) == "synthetic-model"
    assert coerce(BY_ENV["PIPAL_COUNT"], parsed["PIPAL_COUNT"]) == 3
    assert "HCAT_BIN" not in parsed


def test_migration_defaults_integration_keys_the_json_lacks(tmp_path):
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hcatBin": "hashcat-custom"}))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    parsed = dotenv_values(str(env_path))
    assert coerce(BY_ENV["PIPAL_COUNT"], parsed["PIPAL_COUNT"]) == 10
    # Nothing was migrated, so there is nothing to tell the user to delete.
    assert notes == []


def test_migration_notes_name_the_keys_and_no_values(tmp_path):
    legacy = _legacy_config_json(
        hashview_api_key="synthetic-sentinel-key",
        hashmob_api_key="another-synthetic-sentinel",
        ollamaModel="synthetic-model",
    )
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    joined = "\n".join(notes)
    for key in ("hashview_api_key", "hashmob_api_key", "ollamaModel"):
        assert key in joined
    assert "synthetic-sentinel-key" not in joined
    assert "another-synthetic-sentinel" not in joined
    assert "synthetic-model" not in joined
    # And the user is told, once and explicitly, what happened to config.json.
    assert "Removed them from" in joined
    assert str(legacy_path) in joined


def test_migration_ignores_unrecognized_and_json_homed_keys_silently(tmp_path):
    """Neither is this function's business any more: config.json keeps its own
    keys, and has always tolerated extra ones."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(
        json.dumps({"some_retired_key": "x", "hcatBin": "hashcat-custom"})
    )

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    assert notes == []


def test_migration_type_mismatch_writes_default_with_note(tmp_path):
    legacy = _legacy_config_json(pipal_count="not-an-int")
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    parsed = dotenv_values(str(env_path))
    assert coerce(BY_ENV["PIPAL_COUNT"], parsed["PIPAL_COUNT"]) == 10
    assert any("pipal_count" in note for note in notes)
    assert not any("not-an-int" in note for note in notes)


def test_migration_deletes_the_copied_keys_from_config_json(tmp_path):
    """A copied key left in config.json is one the loader ignores and warns
    about forever, so the migration finishes the job."""
    legacy = _legacy_config_json(hashmob_api_key="synthetic-sentinel")
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy, indent=2))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    remaining = json.loads(legacy_path.read_text())
    assert not ({entry.legacy for entry in ENV_KEYS} & set(remaining))


def test_migration_keeps_json_homed_and_unrecognized_keys(tmp_path):
    """Pruning is scoped to the keys that moved. The other 35 settings are the
    whole reason config.json still exists, and an unrecognized key is usually a
    note or a retired setting the user chose to keep."""
    legacy = _legacy_config_json(
        hashmob_api_key="synthetic-sentinel",
        hcatBin="hashcat-custom",
        some_retired_key="keep me",
    )
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy, indent=2))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    remaining = json.loads(legacy_path.read_text())
    assert remaining["hcatBin"] == "hashcat-custom"
    assert remaining["some_retired_key"] == "keep me"
    for entry in JSON_KEYS:
        assert entry.legacy in remaining


def test_migration_backs_config_json_up_before_pruning(tmp_path):
    legacy = _legacy_config_json(hashmob_api_key="synthetic-sentinel")
    legacy_path = tmp_path / "config.json"
    original_bytes = json.dumps(legacy, indent=2).encode()
    legacy_path.write_bytes(original_bytes)

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    backup = tmp_path / "config.json.pre-split.bak"
    assert backup.read_bytes() == original_bytes
    assert str(backup) in "\n".join(notes)


def test_migration_preserves_the_order_of_surviving_keys(tmp_path):
    """config.json is hand-edited, so the migration's diff has to be readable:
    only removed lines, never a wholesale reshuffle."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(
        json.dumps(
            {
                "hcatBin": "hashcat",
                "hashmob_api_key": "synthetic-sentinel",
                "hcatTuning": "-w 4",
                "ollamaModel": "synthetic-model",
                "hcatPath": "/opt/hashcat",
            },
            indent=2,
        )
    )

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    remaining = json.loads(legacy_path.read_text())
    assert list(remaining) == ["hcatBin", "hcatTuning", "hcatPath"]


def test_migration_keeps_a_type_mismatched_key_in_config_json(tmp_path):
    """The .env got the schema default, not the user's value, so deleting the
    key would destroy the only record of what they meant to set."""
    legacy = _legacy_config_json(pipal_count="not-an-int")
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy, indent=2))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    remaining = json.loads(legacy_path.read_text())
    assert remaining["pipal_count"] == "not-an-int"


def test_migration_preserves_config_json_permissions(tmp_path):
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_legacy_config_json(), indent=2))
    os.chmod(legacy_path, 0o600)

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    assert stat.S_IMODE(os.stat(legacy_path).st_mode) == 0o600


def test_migration_with_nothing_to_move_leaves_config_json_alone(tmp_path):
    """No prune, no backup, no notes -- a post-split config.json is untouched."""
    legacy_path = tmp_path / "config.json"
    original_bytes = json.dumps({"hcatBin": "hashcat"}, indent=2).encode()
    legacy_path.write_bytes(original_bytes)

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    assert notes == []
    assert legacy_path.read_bytes() == original_bytes
    assert not (tmp_path / "config.json.pre-split.bak").exists()


def test_migration_writes_the_env_at_0600(tmp_path):
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_legacy_config_json()))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    assert stat.S_IMODE(os.stat(env_path).st_mode) == 0o600


def test_migration_notes_never_contain_secret_values(tmp_path):
    legacy = _legacy_config_json(
        hashview_api_key=["not", "a", "string"],  # type mismatch
        notify_pushover_token=12345,  # type mismatch
    )
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    notes = write_env_from_legacy(str(legacy_path), str(env_path))

    joined = "\n".join(notes)
    assert "12345" not in joined
    assert repr(["not", "a", "string"]) not in joined


# ---------------------------------------------------------------------------
# End-to-end: after a migration, both files together reproduce the old config
# ---------------------------------------------------------------------------


def test_migrated_pair_reproduces_the_pre_split_configuration(tmp_path):
    """The user-visible promise of the migration: nothing they had configured
    changes value, even though half the keys now come from a different file.

    The pre-split ``config.json`` is loaded as the json home *and* the new
    `.env` as the env home; the merged result must equal what the whole file
    used to produce. The integration keys still sitting in ``config.json`` are
    ignored (with warnings) and therefore contribute nothing -- which is
    exactly why the `.env` has to carry them faithfully.
    """
    legacy = _legacy_config_json(
        # json-homed overrides
        hcatBin="hashcat-custom",
        bandrelmaxruntime=600,
        notify_poll_interval_seconds=2.5,
        hcatDictionaryWordlist=["custom.txt", "extra.txt"],
        hcatMiddleCombinatorMasks=[" ", ",", "\\", '"', "'"],
        notify_attack_allowlist=[],
        hcatDebugLogPath="~/custom/debug",
        hcatPotfilePath="",
        # env-homed overrides, including a "~" path and an empty value
        ollamaTimeout=900,
        ollamaAutoResearch=False,
        pipalPath="~/tools/pipal",
        hashview_api_key="",
        ollamaModel="synthetic-model",
    )
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(legacy))

    env_path = tmp_path / ".env"
    write_env_from_legacy(str(legacy_path), str(env_path))

    after = load_config(
        env_path=str(env_path), legacy_json_path=str(legacy_path), environ={}
    ).config

    expected = {}
    for entry in CONFIG_SCHEMA:
        value = legacy[entry.legacy]
        expected[entry.legacy] = (
            os.path.expanduser(value) if entry.type == "path" and value else value
        )
    assert after == expected
    # Spot-checks on the values a naive round-trip loses.
    assert after["hcatPotfilePath"] == ""
    assert after["pipalPath"] == os.path.expanduser("~/tools/pipal")
    assert after["hcatDebugLogPath"] == os.path.expanduser("~/custom/debug")
    assert after["ollamaAutoResearch"] is False
