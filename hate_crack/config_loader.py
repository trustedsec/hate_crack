"""Split-home configuration loader for hate_crack.

Every configuration key has exactly one home file, declared by its ``home``
field in :mod:`hate_crack.config_schema`: `.env` for the twelve third-party
integration keys, ``config.json`` for the other thirty-five settings. Both
files are first-class and permanent; neither is on its way out, and there is
no removal timeline for either.

Precedence for a single key, highest first:

1. The real process environment (``os.environ``).
2. That key's own home file -- and only that file.
3. The schema default.

There is deliberately **no cross-file precedence**. A key found in the file
that is not its home is ignored, with a warning naming the key and the file
it belongs in; ``.env`` never wins for a ``config.json`` key, and vice
versa. ``os.environ`` is exempt from the split because an environment
variable is an ephemeral override rather than a home -- that exemption is
what keeps the documented ``HASHVIEW_URL`` / ``HASHVIEW_API_KEY`` overrides
(and the ``HASHVIEW_TEST_LOCAL=1`` harness) working, and it applies to
``config.json``-homed keys too.

This module intentionally does NOT import ``hate_crack.main`` -- ``main.py``
imports this module, and an import back would be a cycle. It performs no
hashcat-specific logic; it only produces the same ``dict`` shape that
``main.py``'s ``config_parser`` has today, keyed by legacy JSON key names.

The `.env` layer and the environment layer both hand this module raw strings,
but they do not agree on what an empty string means -- deliberately. See
:func:`_apply_string_layer` for the full rationale: in short, an empty value
written to a *file* is an explicit user statement (e.g. "no potfile path"),
while an empty value in the real environment is treated as unset, matching
the ``os.environ.get(...) or config_parser[...]`` pattern ``main.py`` used
before the loader existed.
"""

from __future__ import annotations

import json
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
    validate_choices,
)

# environ layer only (see _apply_string_layer): csv_list and charset treat an
# explicitly-present empty string as "empty list", not "unset", even though
# every other type in that layer treats "" as unset and falls through to the
# next-lower layer. The .env layer has no need for this carve-out -- there,
# presence is explicit for every type, empty string included.
_EMPTY_STRING_MEANS_EMPTY_LIST: frozenset[str] = frozenset({"csv_list", "charset"})


class ConfigLoadResult(NamedTuple):
    """Result of :func:`load_config`: the merged config plus any warnings."""

    config: dict[str, Any]
    warnings: list[str]


def candidate_roots() -> list[str]:
    """Directory search order for ``.env`` and ``config.json``.

    **This is the single definition of that order.**
    ``hate_crack.main._candidate_roots()`` and ``hate_crack.api``'s config
    resolution both delegate here; they used to keep their own copies, which
    is a drift that stays invisible until someone's config stops being found.
    The order is: the repo root, the installed package directory, then
    ``~/.hate_crack``.
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
    """Locate ``.env`` and ``config.json`` using the shared search order.

    Returns ``(env_path, json_path)``. Either element is ``None`` if no
    matching file was found in any candidate directory. The two are resolved
    independently -- they are separate, equally first-class files, and it is
    normal for them to live in different candidate directories.
    """
    env_path: str | None = None
    legacy_json_path: str | None = None
    for candidate in candidate_roots():
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
    """A ``config.json`` file exists but fails to parse as JSON.

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


def _read_json_file(json_path: str) -> dict[str, Any]:
    try:
        with open(json_path) as fh:
            return json.load(fh)
    except json.JSONDecodeError as exc:
        raise ConfigFileJSONError(json_path, exc.lineno, exc.colno, exc.msg) from exc
    except OSError as exc:
        raise ConfigFileUnreadableError(json_path, exc) from exc


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


def _apply_json_layer(
    result: dict[str, Any],
    json_data: Mapping[str, Any],
    json_path: str,
    warnings: list[str],
) -> None:
    """Apply ``config.json``, which owns the ``home="json"`` keys only.

    An integration key left behind in ``config.json`` -- typically after the
    one-shot migration that copied it into `.env` -- is *ignored*, not merged
    as a lower-precedence layer, and earns a warning naming the file it now
    belongs in. Silently honouring it would recreate the cross-file
    precedence the split exists to remove, and would mean a user who edited
    ``HASHMOB_API_KEY`` in `.env` kept getting the stale value.
    """
    for key, value in json_data.items():
        entry = BY_LEGACY.get(key)
        if entry is None:
            # An unrecognized key in config.json is ignored silently, matching
            # the long-standing tolerance of extra keys in that file (people
            # keep notes and retired settings in there).
            continue
        if entry.home != "json":
            warnings.append(
                f"Config key {key!r} in {json_path} is ignored: it belongs in "
                f"the .env file, as {entry.env}. Remove it from {json_path}."
            )
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
                f"Config key {key!r} in {json_path} has the wrong type; "
                f"keeping schema default."
            )
            continue
        # JSON values are checked, not coerced, so coerce()'s closed-set
        # validation never runs for them -- do it explicitly here so a bad
        # update_channel in config.json fails exactly like a bad
        # HATE_CRACK_UPDATE_CHANNEL in the environment.
        validate_choices(entry, value, json_path)
        result[entry.legacy] = value


def _apply_string_layer(
    result: dict[str, Any],
    data: Mapping[str, str | None],
    source: str,
    warnings: list[str],
    *,
    is_dotenv: bool,
) -> None:
    """Apply one string-keyed layer (`.env` or the real environment).

    The `.env` layer is restricted to ``home="env"`` keys: a ``config.json``
    setting written into `.env` is ignored and warned about, because a `.env`
    value must never win for a json-homed key. The environment layer has no
    such restriction -- ``os.environ`` may override anything.

    The two layers also disagree on what an empty string means, deliberately:

    - **`.env` layer** (``is_dotenv=True``): presence is explicit, for every
      type, even when the value is empty. A `.env` is a config file we
      generate and the user edits deliberately, so a key written there with
      an empty value (e.g. ``PIPAL_PATH=``) is a statement -- "there is no
      pipal here" -- not an absence, and must not fall through to the schema
      default. Only a key genuinely *absent* from the file, or a bare ``KEY``
      with no ``=`` (``dotenv_values()`` reports that as ``None``), counts as
      unset. Do not "simplify" this back to matching the environ layer -- the
      same rule is what keeps an explicitly-empty ``hcatPotfilePath`` in
      ``config.json`` (a deliberate "pass no --potfile-path to hashcat") from
      silently reverting to the default potfile path.
    - **environ layer** (``is_dotenv=False``): empty means unset and falls
      through to the next-lower layer, matching today's documented behavior
      (``main.py``'s ``os.environ.get("HASHVIEW_URL") or config_parser[...]``
      pattern). An accidentally-empty exported shell variable is common
      enough that treating it as an explicit override would be hostile.
      ``csv_list``/``charset`` keep their own carve-out here: an
      explicitly-present empty string still means "empty list", not "unset".
    """
    for key, raw in data.items():
        entry = BY_ENV.get(key)
        if entry is None:
            if is_dotenv:
                warnings.append(f"Unrecognized key {key!r} in {source} is ignored.")
            continue
        if is_dotenv and entry.home != "env":
            warnings.append(
                f"Config key {key!r} in {source} is ignored: it belongs in "
                f"config.json, as {entry.legacy!r}. Remove it from {source}."
            )
            continue
        if raw is None:
            continue
        if (
            not is_dotenv
            and raw == ""
            and entry.type not in _EMPTY_STRING_MEANS_EMPTY_LIST
        ):
            continue
        result[entry.legacy] = coerce(entry, raw, source)


def load_config(
    *,
    env_path: str | None = None,
    legacy_json_path: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ConfigLoadResult:
    """Load configuration through the split-home precedence stack.

    Returns a :class:`ConfigLoadResult` whose ``config`` dict is keyed by
    legacy JSON key names (e.g. ``hcatPath``) with values coerced to their
    final Python types, and whose ``warnings`` list holds human-readable,
    non-fatal problems encountered while loading.

    Raises :class:`hate_crack.config_schema.ConfigValueError` on a single
    malformed value, :class:`ConfigFileJSONError` on a ``config.json``
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

    # Layer 2a: config.json, for the home="json" keys.
    if legacy_json_path and os.path.isfile(legacy_json_path):
        json_data = _read_json_file(legacy_json_path)
        _apply_json_layer(result, json_data, legacy_json_path, warnings)

    # Layer 2b: .env, for the home="env" keys. Not a higher layer than 2a --
    # the two are disjoint by key, so their order relative to each other is
    # irrelevant by construction.
    if env_path and os.path.isfile(env_path):
        dotenv_data = _read_dotenv(env_path)
        _apply_string_layer(result, dotenv_data, env_path, warnings, is_dotenv=True)

    # Layer 3: real process environment, which may override any key.
    _apply_string_layer(result, environ, "<environment>", warnings, is_dotenv=False)

    _normalize_path_values(result)

    return ConfigLoadResult(config=result, warnings=warnings)


def _normalize_path_values(result: dict[str, Any]) -> None:
    """Expand ``~`` uniformly on every ``path``-typed value, regardless of
    which layer supplied it.

    ``coerce()`` already does this for values sourced from ``.env`` and the
    real environment, but the schema-default layer and the ``config.json``
    layer are never run through ``coerce()`` -- the JSON layer intentionally
    does not, because JSON values are typed already and are only checked, not
    coerced. Without this pass, ``load_config()`` could return a different
    string for the exact same logical path depending on which layer happened
    to supply it (e.g. an unexpanded default vs. an expanded environment
    override). Run once, after all layers have merged, so every ``path`` key
    ends up normalized exactly once regardless of its source.

    ``""`` is left untouched -- an explicitly empty path is a real "disabled"
    sentinel (e.g. ``hcatPotfilePath``), not something to expand into the
    home directory.
    """
    for entry in CONFIG_SCHEMA:
        if entry.type != "path":
            continue
        value = result.get(entry.legacy, "")
        if value == "":
            continue
        result[entry.legacy] = os.path.expanduser(value)


def load_config_or_exit(
    *,
    env_path: str | None = None,
    legacy_json_path: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> ConfigLoadResult:
    """Like :func:`load_config`, but prints a diagnostic and exits on failure.

    Accumulated warnings are returned in the result and **not** emitted here.
    They used to also be logged to ``logging.getLogger("hate_crack")``, which
    meant every warning surfaced twice -- once from that logger and once from
    ``main.py``'s own ``print()`` of the same list. Under the split that is not
    cosmetic: a pre-split ``config.json`` produces one misplaced-key warning per
    integration key, so a migrating user's first sight of the tool was twelve
    warnings rendered as twenty-four near-identical lines, which reads like a
    bug in the very messages that are the whole user-facing story for the split.

    ``main.py`` owns the single channel because these are user guidance, not
    diagnostics for a log file: they tell the reader which key to move to which
    file, and they must be visible on a terminal with no logging handler
    configured. Do not re-add a logging call here without removing that print.
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

    return result
