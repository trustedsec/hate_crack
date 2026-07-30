"""`.env` serializer and the one-shot ``config.json`` -> `.env` migration.

This module is the write-side counterpart to :mod:`hate_crack.config_loader`.
It owns the `.env` file outright -- the ``home="env"`` third-party integration
keys -- and touches ``config.json`` in exactly one place: the migration prunes
the keys it copied out of it (see :func:`write_env_from_legacy`). Otherwise
``config.json`` is written by ``main.py`` (first-run bootstrap, by copying
``config.json.example``) and by :mod:`hate_crack.notify.settings` (the
notification toggles).

This module intentionally does NOT import ``hate_crack.main`` for the same
reason ``config_loader.py`` doesn't: ``main.py`` imports this module, and an
import back would be a cycle.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Mapping, Sequence
from typing import Any

from hate_crack.config_schema import (
    BY_LEGACY,
    ENV_KEYS,
    ConfigKey,
)

# ---------------------------------------------------------------------------
# Grouping -- one group per integration, so a hand-edited .env reads as a
# short list of services rather than an undifferentiated block. Each group is
# (comment, [env names in this group]).
# ---------------------------------------------------------------------------

_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Hashview (API key is a secret)",
        ("HASHVIEW_URL", "HASHVIEW_API_KEY"),
    ),
    (
        "Hashmob (API key is a secret)",
        ("HASHMOB_API_KEY",),
    ),
    (
        "Pushover credentials for crack notifications (both are secrets). The\n"
        "# notification on/off toggles live in config.json, not here.",
        ("NOTIFY_PUSHOVER_TOKEN", "NOTIFY_PUSHOVER_USER"),
    ),
    (
        "Ollama-backed AI research",
        (
            "OLLAMA_HOST",
            "OLLAMA_MODEL",
            "OLLAMA_NO_CLOUD",
            "OLLAMA_NUM_CTX",
            "OLLAMA_TIMEOUT",
            "OLLAMA_MAX_SAMPLE_LINES",
            "OLLAMA_AUTO_RESEARCH",
        ),
    ),
    (
        "pipal (an external tool hate_crack does not ship)",
        ("PIPAL_PATH", "PIPAL_COUNT"),
    ),
)

_grouped_names = {name for _comment, names in _GROUPS for name in names}
_schema_names = {entry.env for entry in ENV_KEYS}
if _grouped_names != _schema_names:
    missing = _schema_names - _grouped_names
    extra = _grouped_names - _schema_names
    raise AssertionError(
        f'_GROUPS out of sync with the home="env" schema keys: '
        f"missing={sorted(missing)!r} extra={sorted(extra)!r}"
    )

BY_ENV_NAME: dict[str, ConfigKey] = {entry.env: entry for entry in ENV_KEYS}

# The one command that regenerates the tracked `.env.example`. Named here so the
# file's own header, the drift-guard test's failure message and the docs cannot
# disagree about it.
REGENERATE_COMMAND = "uv run python -m hate_crack.config_writer"


class EnvFileExistsError(Exception):
    """Raised by :func:`write_env` when the destination exists and
    ``overwrite`` was not requested."""

    def __init__(self, path: str) -> None:
        self.path = path
        super().__init__(f"{path} already exists (pass overwrite=True to replace it)")


# ---------------------------------------------------------------------------
# Deliverable A/B -- value serialization + quoting
# ---------------------------------------------------------------------------

# Characters that force quoting: anything that would change python-dotenv's
# parse of an unquoted value.
_FORCE_QUOTE_CHARS = set("#\n\r\"'\\")


def _needs_quoting(rendered: str) -> bool:
    """Does ``rendered`` have to be double-quoted to survive a `.env` read?

    Takes no schema entry: the only type that needed unconditional quoting was
    ``charset`` (python-dotenv strips unquoted values, which would eat a
    leading/trailing space element), and no ``home="env"`` key is a charset.
    Quoting is now purely a property of the rendered text.
    """
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

    Inverse of :func:`hate_crack.config_schema.coerce` for the four types the
    ``home="env"`` keys actually use: for every such entry,
    ``coerce(entry, emit_value(entry, v)) == v``. Does not include quoting --
    see :func:`render_line` for the quoted, ``KEY=VALUE`` line.

    ``csv_list`` and ``charset`` are rejected rather than serialized: no
    integration key is list-typed, so those emitters had no reachable caller.
    Their *coercers* remain in ``config_schema`` because ``os.environ`` can
    still override a list-typed ``config.json`` setting; only the write side
    is gone. Adding a list-typed key to `.env` therefore fails loudly here
    instead of silently emitting a form that cannot round-trip a ``,`` or a
    leading space.
    """
    if entry.type == "bool":
        return "1" if value else "0"
    if entry.type in ("int", "float"):
        return str(value)
    if entry.type in ("str", "path"):
        return str(value)
    raise AssertionError(
        f"emit_value() cannot serialize type {entry.type!r} (key {entry.env}): "
        "the .env writer only supports str/path/int/float/bool"
    )


def render_line(entry: ConfigKey, value: Any) -> str:
    """Render one complete ``KEY=VALUE`` (quoted if needed) `.env` line."""
    rendered = emit_value(entry, value)
    if _needs_quoting(rendered):
        rendered = _quote(rendered)
    return f"{entry.env}={rendered}"


# ---------------------------------------------------------------------------
# Deliverable C -- write_env
# ---------------------------------------------------------------------------


_ENV_HEADER: tuple[str, ...] = (
    "# hate_crack third-party integration settings.",
    "# Generated by hate_crack/config_writer.py -- see config_schema.py",
    "# for the authoritative list of keys and types.",
    "#",
    "# Every other hate_crack setting lives in config.json. A key from",
    "# config.json placed here is ignored, with a warning, and vice versa.",
    "#",
    "# Do not commit this file: it can hold API keys and tokens.",
    "",
)

# Header for the tracked `.env.example` template. It says something different
# from the generated `.env`'s header on purpose: this file is committed, so it
# must tell the reader to copy it rather than edit it in place, and it must
# explain why the four credential keys are empty (a placeholder that looked
# like a real key would be both a bad example and a secret-scanner false
# positive waiting to happen).
_EXAMPLE_HEADER: tuple[str, ...] = (
    "# hate_crack third-party integration settings -- EXAMPLE TEMPLATE.",
    "#",
    "# This file is tracked in git. Do not put real credentials in it.",
    "# Copy it and edit the copy:",
    "#",
    "#     cp .env.example .env && chmod 600 .env",
    "#",
    "# hate_crack also creates a 0600 .env for you on first run, migrating any",
    "# integration settings it finds in an existing config.json.",
    "#",
    "# Regenerate this template after changing config_schema.py with:",
    f"#     {REGENERATE_COMMAND}",
    "#",
    "# Every other hate_crack setting lives in config.json. A key from",
    "# config.json placed here is ignored, with a warning, and vice versa.",
    "# Any key may also be overridden by a real environment variable.",
    "#",
    "# The four credential keys below ship empty on purpose. Fill them in your",
    "# own .env, never here:",
    "#   HASHVIEW_API_KEY      your Hashview account's API key",
    "#   HASHMOB_API_KEY       your Hashmob account's API key",
    "#   NOTIFY_PUSHOVER_TOKEN your Pushover application token",
    "#   NOTIFY_PUSHOVER_USER  your Pushover user key",
    "",
)


def render_env(
    config: Mapping[str, Any], *, header: tuple[str, ...] | None = None
) -> str:
    """Render a complete, grouped, commented `.env` document as text.

    Covers the ``home="env"`` integration keys and nothing else; every
    other setting belongs in ``config.json``. ``config`` is keyed by legacy
    JSON key names (the same shape
    :func:`hate_crack.config_loader.load_config` returns) and may contain
    json-homed keys, which are simply not rendered; missing keys fall back to
    the schema default.

    ``header`` replaces the default comment banner; see
    :func:`render_env_example`.
    """
    lines: list[str] = list(_ENV_HEADER if header is None else header)
    for comment, names in _GROUPS:
        lines.append(f"# {comment}")
        for env_name in names:
            entry = BY_ENV_NAME[env_name]
            value = config.get(entry.legacy, entry.default)
            lines.append(render_line(entry, value))
        lines.append("")
    # Single trailing newline, no dangling blank-line buildup.
    return "\n".join(lines).rstrip("\n") + "\n"


def render_env_example() -> str:
    """Render the tracked `.env.example` template from the schema.

    Every value is the schema default, which is why the four
    :data:`hate_crack.config_schema.SECRET_ENV_KEYS` come out as bare ``KEY=``:
    their defaults are empty strings. Nothing here may ever be given a
    realistic-looking credential -- the file is committed to a public repo.
    """
    return render_env({}, header=_EXAMPLE_HEADER)


def env_example_path() -> str:
    """Absolute path of the tracked `.env.example` at the repo root."""
    package_path = os.path.dirname(os.path.realpath(__file__))
    return os.path.join(os.path.dirname(package_path), ".env.example")


def write_env(path: str, config: Mapping[str, Any], *, overwrite: bool = False) -> None:
    """Write a complete `.env` file (the integration keys) to ``path``.

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
# One-shot migration: lift the integration keys out of an old config.json
# ---------------------------------------------------------------------------


def write_env_from_legacy(
    legacy_json_path: str, env_path: str, *, overwrite: bool = False
) -> list[str]:
    """Create ``env_path`` from the integration keys in ``legacy_json_path``.

    Reads a ``config.json`` written before the split, extracts whichever of
    the ``home="env"`` keys it contains, and writes a ``0600`` `.env` holding
    them (keys it does not contain get the schema default). Returns a list of
    human-readable notes to print once.

    Once the `.env` is safely in place, the keys that moved are **deleted from**
    ``config.json``, because a key left there is one the loader ignores and
    warns about on every subsequent load -- a permanent nag for a migration the
    user cannot finish except by hand-editing JSON. The original file is copied
    to ``<config.json>.pre-split.bak`` first, and the rewrite only touches the
    keys named in the notes: every ``home="json"`` setting is preserved
    verbatim, as is any unrecognized key the user was keeping as a note.

    Deletion is deliberately scoped to keys that were actually copied. A key
    whose value had the wrong type is left in place, since the `.env` got the
    schema default rather than the user's value and dropping it would destroy
    the only record of what they had meant to set.

    Notes name keys only, never values -- several of these keys are secrets.
    """
    with open(legacy_json_path) as fh:
        legacy_data = json.load(fh)

    config: dict[str, Any] = {entry.legacy: entry.default for entry in ENV_KEYS}
    notes: list[str] = []
    migrated: list[str] = []

    if isinstance(legacy_data, dict):
        for key, value in legacy_data.items():
            entry = BY_LEGACY.get(key)
            if entry is None or entry.home != "env":
                # Unrecognized keys and json-homed settings both belong to
                # config.json's business, not this migration's.
                continue
            expected_type = type(entry.default)
            if isinstance(value, bool) != isinstance(entry.default, bool):
                type_ok = False
            else:
                type_ok = isinstance(value, expected_type)
            if not type_ok:
                notes.append(
                    f"{legacy_json_path}: key {key!r} has an unexpected type; "
                    "wrote the schema default into the .env instead."
                )
                continue
            config[entry.legacy] = value
            migrated.append(key)
    else:
        notes.append(
            f"{legacy_json_path}: top-level JSON is not an object; using defaults."
        )

    write_env(env_path, config, overwrite=overwrite)

    if migrated:
        notes.append(
            "Copied these third-party integration settings into "
            f"{env_path}: {', '.join(sorted(migrated))}."
        )
        try:
            backup_path = _prune_migrated_keys(legacy_json_path, migrated)
        except OSError as exc:
            notes.append(
                f"Could not rewrite {legacy_json_path} to drop the copied keys "
                f"({exc}); they are now read from {env_path} only, so delete "
                "them by hand to stop the warnings."
            )
        else:
            notes.append(
                f"Removed them from {legacy_json_path}, where they would now be "
                f"ignored. The original is saved as {backup_path}."
            )
    return notes


def _prune_migrated_keys(legacy_json_path: str, migrated: Sequence[str]) -> str:
    """Delete ``migrated`` from ``legacy_json_path``; return the backup path.

    Back up first, then rewrite atomically, so a failure part-way through
    leaves either the original file or a complete new one -- never a truncated
    ``config.json``, which would cost the user all thirty-five of their other
    settings. Key order is preserved for the keys that survive: this is a file
    people read and hand-edit, and reordering it would make the migration's
    diff unreviewable.

    The original file's permissions are carried over to the replacement.
    ``config.json`` holds no secrets after this runs, but it may well have been
    tightened to ``0600`` while it did, and silently widening that is not this
    function's call to make.
    """
    with open(legacy_json_path) as fh:
        data = json.load(fh)

    backup_path = f"{legacy_json_path}.pre-split.bak"
    shutil.copy2(legacy_json_path, backup_path)

    drop = set(migrated)
    kept = {key: value for key, value in data.items() if key not in drop}

    directory = os.path.dirname(os.path.abspath(legacy_json_path)) or "."
    tmp_path = os.path.join(directory, f".config-{os.urandom(8).hex()}.tmp")
    try:
        with open(tmp_path, "w") as tmp:
            json.dump(kept, tmp, indent=2)
            tmp.write("\n")
        shutil.copymode(legacy_json_path, tmp_path)
        os.replace(tmp_path, legacy_json_path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    return backup_path


def _regenerate_env_example() -> str:
    """Write the tracked `.env.example` and return its path.

    Plain ``open()``/``write()`` rather than :func:`write_env`: this file is
    tracked, world-readable by design and holds no secrets, so the ``0600``
    atomic-replace machinery would only make it awkward to `git diff`.
    """
    path = env_example_path()
    with open(path, "w") as fh:
        fh.write(render_env_example())
    return path


if __name__ == "__main__":  # pragma: no cover
    print(f"Wrote {_regenerate_env_example()}")
