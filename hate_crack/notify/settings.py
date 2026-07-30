"""Notification settings: dataclass + `.env` write-back.

Settings live in the same `.env` that drives the rest of hate_crack. This
module isolates (a) the typed shape of notification config and (b) the
persistence primitives used by the runtime toggles (menu option 82) and the
``[yes/no/always]`` per-attack prompt.

Persistence goes through ``dotenv.set_key()``, which edits the file in place
-- comments, key order, and unrelated keys all survive a toggle, and the
write itself is a temp-file-plus-``os.replace`` that also restores the
original mode (so a `.env` at ``0600`` stays at ``0600``). The emitted text
for a value comes from :func:`hate_crack.config_writer.emit_value`, so this
module never invents its own spelling of a boolean.

A missing `.env` is an error here, deliberately: toggling a notification
setting must not be the thing that creates a config file (which would also
mean writing one during a ``HATE_CRACK_SKIP_INIT`` run). Callers in
``hate_crack.notify`` already catch ``OSError`` around these functions and
degrade to an in-memory toggle with a warning.
"""

from __future__ import annotations

import errno
import os
from dataclasses import dataclass, field
from typing import Any

from dotenv import get_key, set_key

from hate_crack.config_schema import BY_ENV, coerce
from hate_crack.config_writer import emit_value


@dataclass
class NotifySettings:
    """Typed view of the ``notify_*`` keys from the merged config.

    Defaults mirror ``config_schema.CONFIG_SCHEMA`` so freshly-loaded
    configs and in-memory fallbacks agree.
    """

    enabled: bool = False
    pushover_token: str = ""
    pushover_user: str = ""
    per_crack_enabled: bool = False
    attack_allowlist: list[str] = field(default_factory=list)
    suppress_in_orchestrators: bool = True
    max_cracks_per_burst: int = 5
    poll_interval_seconds: float = 5.0


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return default


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_str(value: Any, default: str) -> str:
    if value is None:
        return default
    return str(value)


def _coerce_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def load_settings(config_parser: dict | None) -> NotifySettings:
    """Build a ``NotifySettings`` from a parsed config dict.

    Unknown / missing / badly-typed keys fall back to dataclass defaults
    so the runtime always has a valid settings object, even when the
    config was written by an older hate_crack install.
    """
    cfg = config_parser or {}
    defaults = NotifySettings()
    return NotifySettings(
        enabled=_coerce_bool(cfg.get("notify_enabled"), defaults.enabled),
        pushover_token=_coerce_str(
            cfg.get("notify_pushover_token"), defaults.pushover_token
        ),
        pushover_user=_coerce_str(
            cfg.get("notify_pushover_user"), defaults.pushover_user
        ),
        per_crack_enabled=_coerce_bool(
            cfg.get("notify_per_crack_enabled"), defaults.per_crack_enabled
        ),
        attack_allowlist=_coerce_list(cfg.get("notify_attack_allowlist")),
        suppress_in_orchestrators=_coerce_bool(
            cfg.get("notify_suppress_in_orchestrators"),
            defaults.suppress_in_orchestrators,
        ),
        max_cracks_per_burst=_coerce_int(
            cfg.get("notify_max_cracks_per_burst"), defaults.max_cracks_per_burst
        ),
        poll_interval_seconds=_coerce_float(
            cfg.get("notify_poll_interval_seconds"), defaults.poll_interval_seconds
        ),
    )


def _require_env_file(env_path: str) -> None:
    if not os.path.isfile(env_path):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), env_path)


def _set_env_key(env_path: str, env_name: str, value: Any) -> None:
    """Write one schema key into an existing `.env`, in place.

    ``quote_mode="auto"`` leaves ``1``/``0`` bare and quotes anything else
    (including an empty value), which is what round-trips through
    ``dotenv_values()``.
    """
    _require_env_file(env_path)
    entry = BY_ENV[env_name]
    set_key(env_path, env_name, emit_value(entry, value), quote_mode="auto")


def _get_env_key(env_path: str, env_name: str) -> Any:
    """Read one schema key back out of ``env_path``, coerced to its type."""
    entry = BY_ENV[env_name]
    raw = get_key(env_path, env_name)
    if raw is None:
        return entry.default
    return coerce(entry, raw, env_path)


def save_enabled(env_path: str, enabled: bool) -> None:
    """Persist ``NOTIFY_ENABLED`` without disturbing the rest of the `.env`."""
    _set_env_key(env_path, "NOTIFY_ENABLED", bool(enabled))


def save_per_crack_enabled(env_path: str, enabled: bool) -> None:
    """Persist ``NOTIFY_PER_CRACK_ENABLED`` without disturbing other keys."""
    _set_env_key(env_path, "NOTIFY_PER_CRACK_ENABLED", bool(enabled))


class AllowlistNameError(ValueError):
    """Raised when an attack name cannot be stored in the allowlist.

    ``NOTIFY_ATTACK_ALLOWLIST`` is a ``csv_list``, so a name containing a comma
    would be written as one element and read back as two -- silently, and only
    noticeable later as an allowlist entry that never matches. No attack name
    contains a comma today (they are Python identifiers), which is exactly why
    this needs to be an explicit error rather than a comment: the day one does,
    the failure should be loud and at the write, not a notification that
    quietly stops firing.
    """


def add_to_allowlist(env_path: str, attack_name: str) -> None:
    """Append ``attack_name`` to ``NOTIFY_ATTACK_ALLOWLIST`` if absent.

    Idempotent: already-present entries are a no-op. Raises
    :class:`AllowlistNameError` for a name a ``csv_list`` cannot represent.
    """
    if not attack_name:
        return
    if "," in attack_name:
        raise AllowlistNameError(
            f"attack name {attack_name!r} contains a comma and cannot be stored "
            "in NOTIFY_ATTACK_ALLOWLIST"
        )
    _require_env_file(env_path)
    current = _get_env_key(env_path, "NOTIFY_ATTACK_ALLOWLIST")
    if not isinstance(current, list):
        current = []
    if attack_name in current:
        return
    _set_env_key(env_path, "NOTIFY_ATTACK_ALLOWLIST", [*current, attack_name])
