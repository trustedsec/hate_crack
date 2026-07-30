"""Layered configuration loader for hate_crack.

Loads configuration from four layers, lowest to highest precedence:

1. Schema defaults from :mod:`hate_crack.config_schema`.
2. A legacy ``config.json`` file, if present.
3. A ``.env`` file (read via ``python-dotenv``'s ``dotenv_values``), if present.
4. The real process environment.

This module intentionally does NOT import ``hate_crack.main`` -- ``main.py``
imports this module, and an import back would be a cycle. It performs no
hashcat-specific logic; it only produces the same ``dict`` shape that
``main.py``'s ``config_parser`` has today, keyed by legacy JSON key names.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Mapping
from typing import Any, NamedTuple

from dotenv import dotenv_values

from hate_crack.config_schema import (
    BY_ENV,
    BY_LEGACY,
    CONFIG_SCHEMA,
    SECRET_ENV_KEYS,
    ConfigValueError,
    coerce,
)

logger = logging.getLogger("hate_crack")

# csv_list and charset: an explicitly-present empty string means "empty list",
# not "unset". Every other type treats "" as unset and falls through to the
# next-lower layer.
_EMPTY_STRING_MEANS_EMPTY_LIST: frozenset[str] = frozenset({"csv_list", "charset"})


class ConfigLoadResult(NamedTuple):
    """Result of :func:`load_config`: the merged config plus any warnings."""

    config: dict[str, Any]
    warnings: list[str]


def _candidate_roots() -> list[str]:
    """Directory search order for ``.env`` and ``config.json``.

    Mirrors ``hate_crack.main._candidate_roots()``: the repo root, the
    installed package directory, and ``~/.hate_crack``.
    """
    package_path = os.path.dirname(os.path.realpath(__file__))
    repo_root = os.path.dirname(package_path)
    home = os.path.expanduser("~")
    return [
        repo_root,
        package_path,
        os.path.join(home, ".hate_crack"),
    ]


def resolve_config_paths() -> tuple[str | None, str | None]:
    """Locate ``.env`` and legacy ``config.json`` using the shared search order.

    Returns ``(env_path, legacy_json_path)``. Either element is ``None`` if
    no matching file was found in any candidate directory.
    """
    env_path: str | None = None
    legacy_json_path: str | None = None
    for candidate in _candidate_roots():
        if env_path is None:
            candidate_env = os.path.join(candidate, ".env")
            if os.path.isfile(candidate_env):
                env_path = candidate_env
        if legacy_json_path is None:
            candidate_json = os.path.join(candidate, "config.json")
            if os.path.isfile(candidate_json):
                legacy_json_path = candidate_json
    return env_path, legacy_json_path


class ConfigFileJSONError(Exception):
    """A legacy ``config.json`` file exists but fails to parse as JSON.

    Kept distinct from :class:`ConfigValueError` (a single malformed value)
    because the fix is different: a truncated/invalid JSON document cannot be
    repaired by removing "the offending value" -- the file itself needs to be
    hand-fixed or deleted and regenerated from defaults.
    """

    def __init__(self, path: str, lineno: int, colno: int, msg: str) -> None:
        self.path = path
        self.lineno = lineno
        self.colno = colno
        self.msg = msg
        super().__init__(f"{path}: line {lineno}, column {colno}: {msg}")


class ConfigFileUnreadableError(Exception):
    """A ``.env`` or ``config.json`` file exists but could not be opened.

    Distinct from :class:`ConfigValueError` for the same reason as
    :class:`ConfigFileJSONError`: "fix this value" is the wrong advice when
    the problem is that the file could not be read at all (permissions, a
    dangling symlink, etc.).
    """

    def __init__(self, path: str, os_error: OSError) -> None:
        self.path = path
        self.os_error = os_error
        super().__init__(f"{path}: {os_error.strerror or os_error}")


def _read_legacy_json(legacy_json_path: str) -> dict[str, Any]:
    try:
        with open(legacy_json_path) as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigFileJSONError(
            legacy_json_path, exc.lineno, exc.colno, exc.msg
        ) from exc
    except OSError as exc:
        raise ConfigFileUnreadableError(legacy_json_path, exc) from exc


def _read_dotenv(env_path: str) -> dict[str, str | None]:
    try:
        # Guard against dotenv_values() masking a permission error by
        # returning an empty mapping instead of raising -- open the file
        # ourselves first so an OSError surfaces.
        with open(env_path):
            pass
    except OSError as exc:
        raise ConfigFileUnreadableError(env_path, exc) from exc
    return dotenv_values(env_path)


def _apply_legacy_layer(
    result: dict[str, Any],
    legacy_data: Mapping[str, Any],
    legacy_json_path: str,
    warnings: list[str],
) -> None:
    for key, value in legacy_data.items():
        entry = BY_LEGACY.get(key)
        if entry is None:
            # Unknown legacy keys are not covered by the brief's warning
            # requirements (only .env unrecognized keys / legacy type
            # mismatches are); ignore silently, matching today's tolerance
            # of extra keys in config.json.
            continue
        expected_type = type(entry.default)
        # bool is a subclass of int; treat them as distinct schema types so
        # an int value passed for a bool key doesn't cover a real mismatch.
        if isinstance(value, bool) != isinstance(entry.default, bool):
            type_ok = False
        else:
            type_ok = isinstance(value, expected_type)
        if not type_ok:
            warnings.append(
                f"Legacy config.json key {key!r} in {legacy_json_path} has "
                f"the wrong type; keeping schema default."
            )
            continue
        result[entry.legacy] = value


def _apply_string_layer(
    result: dict[str, Any],
    data: Mapping[str, str | None],
    source: str,
    warnings: list[str],
    *,
    is_dotenv: bool,
) -> None:
    for key, raw in data.items():
        entry = BY_ENV.get(key)
        if entry is None:
            if is_dotenv:
                warnings.append(f"Unrecognized key {key!r} in {source} is ignored.")
            continue
        if raw is None:
            continue
        if raw == "" and entry.type not in _EMPTY_STRING_MEANS_EMPTY_LIST:
            continue
        result[entry.legacy] = coerce(entry, raw, source)


def load_config(
    *,
    env_path: str | None = None,
    legacy_json_path: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ConfigLoadResult:
    """Load configuration through the four-layer precedence stack.

    Returns a :class:`ConfigLoadResult` whose ``config`` dict is keyed by
    legacy JSON key names (e.g. ``hcatPath``) with values coerced to their
    final Python types, and whose ``warnings`` list holds human-readable,
    non-fatal problems encountered while loading.

    Raises :class:`hate_crack.config_schema.ConfigValueError` on a single
    malformed value, :class:`ConfigFileJSONError` on a legacy ``config.json``
    that fails to parse as JSON, or :class:`ConfigFileUnreadableError` on a
    ``.env``/``config.json`` that exists but could not be opened. Callers
    that want the process to exit on any of these should use
    :func:`load_config_or_exit` instead of catching them themselves.
    """
    if environ is None:
        environ = os.environ

    warnings: list[str] = []

    # Layer 1: schema defaults.
    result: dict[str, Any] = {entry.legacy: entry.default for entry in CONFIG_SCHEMA}

    # Layer 2: legacy config.json.
    if legacy_json_path and os.path.isfile(legacy_json_path):
        legacy_data = _read_legacy_json(legacy_json_path)
        _apply_legacy_layer(result, legacy_data, legacy_json_path, warnings)

    # Layer 3: .env file.
    if env_path and os.path.isfile(env_path):
        dotenv_data = _read_dotenv(env_path)
        _apply_string_layer(result, dotenv_data, env_path, warnings, is_dotenv=True)

    # Layer 4: real process environment.
    _apply_string_layer(result, environ, "<environment>", warnings, is_dotenv=False)

    return ConfigLoadResult(config=result, warnings=warnings)


def load_config_or_exit(
    *,
    env_path: str | None = None,
    legacy_json_path: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ConfigLoadResult:
    """Like :func:`load_config`, but prints a diagnostic and exits on failure.

    Also logs any accumulated warnings to ``logging.getLogger("hate_crack")``
    at warning level before returning.
    """
    try:
        result = load_config(
            env_path=env_path,
            legacy_json_path=legacy_json_path,
            environ=environ,
        )
    except ConfigFileJSONError as exc:
        # Mirrors main.py:300-310's JSONDecodeError handler exactly: this is
        # a malformed file, not a malformed value, so "remove the offending
        # line" is not actionable advice -- deleting the whole file and
        # letting it regenerate from defaults is.
        print(f"\nError: {exc.path} contains invalid JSON")
        print(f"  File: {exc.path}")
        print(f"  Line {exc.lineno}, column {exc.colno}: {exc.msg}")
        print("\nTo fix:")
        print("  1. Edit the file and fix the JSON syntax, or")
        print("  2. Delete the file to regenerate from defaults")
        sys.exit(1)
    except ConfigFileUnreadableError as exc:
        # Mirrors _load_config_defaults()'s OSError branch in main.py: name
        # the file and, when detectable, call out a dangling symlink.
        print(f"\nError: {exc.path} could not be read")
        print(f"  File: {exc.path}")
        if os.path.islink(exc.path) and not os.path.exists(exc.path):
            print(
                "  This is a dangling symlink: the link exists but its target is missing."
            )
        else:
            print(f"  Reason: {exc.os_error.strerror or exc.os_error}")
        print("\nTo fix:")
        print("  1. Check the file's permissions and that its target exists, or")
        print("  2. Remove or repair the file so it can be read")
        sys.exit(1)
    except ConfigValueError as exc:
        source = exc.source
        shown = "<redacted>" if exc.key in SECRET_ENV_KEYS else exc.raw
        print("\nError: invalid configuration value")
        print(f"  File: {source}")
        if exc.key not in ("<config.json>", "<.env>"):
            print(f"  Key: {exc.key}")
        if shown:
            print(f"  Value: {shown!r}")
        print(f"  Problem: {exc.reason}")
        print("\nTo fix:")
        print(f"  1. Edit {source} and correct the value, or")
        print("  2. Remove the offending line to fall back to the default")
        sys.exit(1)

    for warning in result.warnings:
        logger.warning(warning)

    return result
