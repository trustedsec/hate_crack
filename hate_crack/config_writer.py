"""``.env`` serializer and one-shot ``config.json`` -> ``.env`` migration.

This module is the write-side counterpart to :mod:`hate_crack.config_loader`.
It contains no wiring into startup -- nothing calls it yet. Task 4 will call
:func:`write_env_from_legacy` when a ``.env`` is absent but a legacy
``config.json`` is present; Task 6 will reuse :func:`emit_value` /
:func:`render_env` to generate the tracked ``.env.example``.

This module intentionally does NOT import ``hate_crack.main`` for the same
reason ``config_loader.py`` doesn't: ``main.py`` will import this module, and
an import back would be a cycle.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

from hate_crack.config_schema import (
    BY_LEGACY,
    CONFIG_SCHEMA,
    QUOTE_REQUIRED_TYPES,
    ConfigKey,
)

# ---------------------------------------------------------------------------
# Grouping -- mirrors hate_crack/config.json.example so a diff between the
# old file and the generated .env is easy to follow. Each group is
# (comment, [env names in this group]).
# ---------------------------------------------------------------------------

_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "hashcat paths, binary, and tuning options",
        (
            "HCAT_PATH",
            "HCAT_BIN",
            "HCAT_TUNING",
            "HCAT_POTFILE_PATH",
            "HCAT_DEBUG_LOG_PATH",
            "HCAT_WORDLISTS",
            "HCAT_OPTIMIZED_WORDLISTS",
            "RULES_DIRECTORY",
        ),
    ),
    (
        "wordlists used by specific attack modes",
        (
            "HCAT_DICTIONARY_WORDLIST",
            "HCAT_COMBINATION_WORDLIST",
            "HCAT_HYBRIDLIST",
        ),
    ),
    (
        "combinator mask charsets (type: charset -- one element per "
        "character, order and duplicates preserved)",
        (
            "HCAT_MIDDLE_COMBINATOR_MASKS",
            "HCAT_MIDDLE_BASE_LIST",
            "HCAT_THOROUGH_COMBINATOR_MASKS",
            "HCAT_THOROUGH_BASE_LIST",
            "HCAT_GOOD_MEASURE_BASE_LIST",
            "HCAT_PRINCE_BASE_LIST",
        ),
    ),
    (
        "pipal",
        ("PIPAL_PATH", "PIPAL_COUNT"),
    ),
    (
        "bandrel",
        ("BANDRELMAXRUNTIME", "BANDREL_COMMON_BASEDWORDS"),
    ),
    (
        "Hashview / Hashmob API integration (secrets)",
        ("HASHVIEW_URL", "HASHVIEW_API_KEY", "HASHMOB_API_KEY"),
    ),
    (
        "Ollama-backed AI research",
        (
            "OLLAMA_MODEL",
            "OLLAMA_NUM_CTX",
            "OLLAMA_TIMEOUT",
            "OLLAMA_MAX_SAMPLE_LINES",
            "OLLAMA_AUTO_RESEARCH",
        ),
    ),
    (
        "OMEN / PCFG candidate limits",
        (
            "OMEN_MAX_CANDIDATES",
            "PCFG_RULESET",
            "PCFG_MAX_CANDIDATES",
            "PCFG_PRINCE_LING_MAX_CANDIDATES",
        ),
    ),
    (
        "self-update check",
        ("CHECK_FOR_UPDATES",),
    ),
    (
        "attack modes that get -O appended to their tuning (type: csv_list)",
        ("OPTIMIZED_KERNEL_ATTACKS",),
    ),
    (
        "crack notifications (Pushover token/user are secrets)",
        (
            "NOTIFY_ENABLED",
            "NOTIFY_PUSHOVER_TOKEN",
            "NOTIFY_PUSHOVER_USER",
            "NOTIFY_PER_CRACK_ENABLED",
            "NOTIFY_ATTACK_ALLOWLIST",
            "NOTIFY_SUPPRESS_IN_ORCHESTRATORS",
            "NOTIFY_MAX_CRACKS_PER_BURST",
            "NOTIFY_POLL_INTERVAL_SECONDS",
        ),
    ),
    (
        "persisted defaults for per-run CLI flags (each flag still overrides "
        "the value below for one run)",
        (
            "HATE_CRACK_DEBUG",
            "WEAKPASS_MIN_RANK",
            "HATE_CRACK_UPDATE_CHANNEL",
            "RESTORE_POTFILE_ON_START",
        ),
    ),
)

_grouped_names = {name for _comment, names in _GROUPS for name in names}
_schema_names = {entry.env for entry in CONFIG_SCHEMA}
if _grouped_names != _schema_names:
    missing = _schema_names - _grouped_names
    extra = _grouped_names - _schema_names
    raise AssertionError(
        f"_GROUPS out of sync with CONFIG_SCHEMA: missing={sorted(missing)!r} "
        f"extra={sorted(extra)!r}"
    )

BY_ENV_NAME: dict[str, ConfigKey] = {entry.env: entry for entry in CONFIG_SCHEMA}


class EnvFileExistsError(Exception):
    """Raised by :func:`write_env` when the destination exists and
    ``overwrite`` was not requested."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"{path} already exists (pass overwrite=True to replace it)")


# ---------------------------------------------------------------------------
# Deliverable A/B -- value serialization + quoting
# ---------------------------------------------------------------------------

# Characters that force quoting for types not already in QUOTE_REQUIRED_TYPES:
# anything that would change python-dotenv's parse of an unquoted value.
_FORCE_QUOTE_CHARS = set("#\n\r\"'\\")


def _needs_quoting(entry: ConfigKey, rendered: str) -> bool:
    if entry.type in QUOTE_REQUIRED_TYPES:
        return True
    if rendered == "":
        return False
    if rendered != rendered.strip():
        return True
    return any(ch in _FORCE_QUOTE_CHARS for ch in rendered) or "=" in rendered


def _quote(rendered: str) -> str:
    """Double-quote ``rendered`` for a `.env` line, escaping as needed.

    Escapes backslash and double-quote (the two characters that are special
    inside a double-quoted value to python-dotenv), plus newlines as ``\\n``
    since a literal embedded newline would otherwise break the line-based
    file format.
    """
    escaped = rendered.replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\n", "\\n").replace("\r", "\\r")
    return f'"{escaped}"'


def emit_value(entry: ConfigKey, value: Any) -> str:
    """Serialize an already-typed Python ``value`` to its `.env` RHS text.

    Inverse of :func:`hate_crack.config_schema.coerce`: for every schema
    entry, ``coerce(entry, emit_value(entry, v)) == v``. Does not include
    quoting -- see :func:`render_line` for the quoted, ``KEY=VALUE`` line.
    """
    if entry.type == "bool":
        return "1" if value else "0"
    if entry.type in ("int", "float"):
        return str(value)
    if entry.type in ("str", "path"):
        return str(value)
    if entry.type == "csv_list":
        return ",".join(value)
    if entry.type == "charset":
        return "".join(value)
    raise AssertionError(f"unhandled config type: {entry.type!r}")  # pragma: no cover


def render_line(entry: ConfigKey, value: Any) -> str:
    """Render one complete ``KEY=VALUE`` (quoted if needed) `.env` line."""
    rendered = emit_value(entry, value)
    if _needs_quoting(entry, rendered):
        rendered = _quote(rendered)
    return f"{entry.env}={rendered}"


# ---------------------------------------------------------------------------
# Deliverable C -- write_env
# ---------------------------------------------------------------------------


def render_env(config: Mapping[str, Any]) -> str:
    """Render a complete, grouped, commented `.env` document as text.

    ``config`` is keyed by legacy JSON key names (the same shape
    :func:`hate_crack.config_loader.load_config` returns); missing keys fall
    back to the schema default.
    """
    lines: list[str] = [
        "# hate_crack configuration.",
        "# Generated by hate_crack/config_writer.py -- see config_schema.py",
        "# for the authoritative list of keys and types.",
        "#",
        "# Do not commit this file: it can hold API keys and tokens.",
        "",
    ]
    for comment, names in _GROUPS:
        lines.append(f"# {comment}")
        for env_name in names:
            entry = BY_ENV_NAME[env_name]
            value = config.get(entry.legacy, entry.default)
            lines.append(render_line(entry, value))
        lines.append("")
    # Single trailing newline, no dangling blank-line buildup.
    return "\n".join(lines).rstrip("\n") + "\n"


def write_env(path: str, config: Mapping[str, Any], *, overwrite: bool = False) -> None:
    """Write a complete `.env` file for ``config`` to ``path``.

    Mode ``0600``, atomic (temp file + ``os.replace`` in the same directory),
    and idempotent (byte-identical output for byte-identical input). Refuses
    to clobber an existing file unless ``overwrite=True``.
    """
    if os.path.exists(path) and not overwrite:
        raise EnvFileExistsError(path)

    text = render_env(config)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)

    # Create the temp file with O_CREAT | O_EXCL | O_WRONLY and mode=0o600 up
    # front -- there is no window where it is world-readable, unlike
    # create-then-chmod.
    tmp_path = os.path.join(directory, f".env-{os.urandom(8).hex()}.tmp")
    fd = os.open(tmp_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode=0o600)
    try:
        with os.fdopen(fd, "w") as tmp:
            tmp.write(text)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


# ---------------------------------------------------------------------------
# Deliverable D -- one-shot migration from a legacy config.json
# ---------------------------------------------------------------------------


def write_env_from_legacy(
    legacy_json_path: str, env_path: str, *, overwrite: bool = False
) -> list[str]:
    """Migrate a legacy ``config.json`` at ``legacy_json_path`` to a new
    `.env` at ``env_path``. Returns a list of human-readable notes about
    anything dropped or defaulted; never modifies or deletes the legacy file.

    - Keys absent from ``config.json`` get the schema default (matching
      today's merge in ``main.py``).
    - A ``config.json`` key not present in the schema is dropped and reported
      as a note (never silently, since this is the last time the old file is
      consulted).
    - A value whose type doesn't match the schema is dropped, the schema
      default is written instead, and a note is recorded. No best-effort
      conversion is attempted.
    - Notes never include the offending value, and never include the value of
      a key in ``SECRET_ENV_KEYS`` -- only the key name.
    """
    with open(legacy_json_path) as fh:
        legacy_data = json.load(fh)

    config: dict[str, Any] = {entry.legacy: entry.default for entry in CONFIG_SCHEMA}
    notes: list[str] = []

    if isinstance(legacy_data, dict):
        for key, value in legacy_data.items():
            entry = BY_LEGACY.get(key)
            if entry is None:
                notes.append(
                    f"{legacy_json_path}: key {key!r} is not a recognized "
                    "configuration key and was not carried over."
                )
                continue
            expected_type = type(entry.default)
            if isinstance(value, bool) != isinstance(entry.default, bool):
                type_ok = False
            else:
                type_ok = isinstance(value, expected_type)
            if not type_ok:
                notes.append(
                    f"{legacy_json_path}: key {key!r} has an unexpected type; "
                    "wrote the schema default instead."
                )
                continue
            config[entry.legacy] = value
    else:
        notes.append(
            f"{legacy_json_path}: top-level JSON is not an object; using defaults."
        )

    write_env(env_path, config, overwrite=overwrite)
    return notes
