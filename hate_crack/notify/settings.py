"""Notification settings: dataclass + atomic ``config.json`` write-back.

The three settings this module persists -- ``notify_enabled``,
``notify_per_crack_enabled`` and ``notify_attack_allowlist`` -- are all
``home="json"`` in :mod:`hate_crack.config_schema`: they are local
preferences, not third-party credentials. (The Pushover token and user *are*
credentials and live in `.env`, but nothing writes those from the menu, so
this module never touches that file.) So persistence goes to ``config.json``.

Writes follow the read-modify-write pattern ``main.py`` used before the
loader existed: ``json.load`` -> mutate the one key -> ``json.dump(...,
indent=2)`` into a temp file in the same directory -> ``os.replace``. Every
unrelated key survives, and a crash mid-write cannot leave a truncated
config behind.

A missing ``config.json`` is an error here, deliberately: toggling a
notification setting must not be the thing that creates a config file (which
would also mean writing one during a ``HATE_CRACK_SKIP_INIT`` run). Callers
in ``hate_crack.notify`` already catch ``OSError`` around these functions and
degrade to an in-memory toggle with a warning.
"""

from __future__ import annotations

import errno
import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any


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


def _require_config_file(config_path: str) -> None:
    if not os.path.isfile(config_path):
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), config_path)


def _atomic_rewrite(config_path: str, mutator) -> None:
    """Read ``config_path``, apply ``mutator(dict)`` in place, write atomically.

    - The file must already exist (see :func:`_require_config_file`); this
      never creates one.
    - Invalid JSON is replaced with the mutator's output rather than raised:
      a pre-existing bad config must not be what blocks a notification
      toggle, and ``main.py`` has already reported it fatally by the time any
      menu action can run.
    - The write goes to a temp file in the same directory and is swapped in
      via ``os.replace``, so a reader never sees a half-written file.
    """
    _require_config_file(config_path)
    data: dict = {}
    try:
        with open(config_path) as fh:
            loaded = json.load(fh)
            if isinstance(loaded, dict):
                data = loaded
    except json.JSONDecodeError:
        data = {}
    mutator(data)
    directory = os.path.dirname(os.path.abspath(config_path)) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as tmp:
            json.dump(data, tmp, indent=2)
        os.replace(tmp_path, config_path)
    except Exception:
        # Best-effort cleanup of the stale temp file on failure.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def save_enabled(config_path: str, enabled: bool) -> None:
    """Persist ``notify_enabled`` without disturbing other config keys."""

    def _apply(data: dict) -> None:
        data["notify_enabled"] = bool(enabled)

    _atomic_rewrite(config_path, _apply)


def save_per_crack_enabled(config_path: str, enabled: bool) -> None:
    """Persist ``notify_per_crack_enabled`` without disturbing other keys."""

    def _apply(data: dict) -> None:
        data["notify_per_crack_enabled"] = bool(enabled)

    _atomic_rewrite(config_path, _apply)


class AllowlistNameError(ValueError):
    """Raised when an attack name cannot be stored in the allowlist.

    The allowlist is stored as a real JSON array now, so a comma survives the
    file itself -- but the key's schema type is still ``csv_list``, which is
    what an ``os.environ`` override of ``NOTIFY_ATTACK_ALLOWLIST`` is parsed
    with. A stored name containing a comma is therefore one env var away from
    being read back as two entries, silently, surfacing much later as an
    allowlist entry that never matches. No attack name contains a comma today
    (they are Python identifiers), which is exactly why this stays an explicit
    error rather than a comment: the day one does, the failure should be loud
    and at the write.
    """


def add_to_allowlist(config_path: str, attack_name: str) -> None:
    """Append ``attack_name`` to ``notify_attack_allowlist`` if absent.

    Idempotent: already-present entries are a no-op. Raises
    :class:`AllowlistNameError` for a name that cannot survive a round-trip.
    """
    if not attack_name:
        return
    if "," in attack_name:
        raise AllowlistNameError(
            f"attack name {attack_name!r} contains a comma and cannot be stored "
            "in notify_attack_allowlist"
        )

    def _apply(data: dict) -> None:
        current = data.get("notify_attack_allowlist")
        if not isinstance(current, list):
            current = []
        if attack_name not in current:
            current.append(attack_name)
        data["notify_attack_allowlist"] = current

    _atomic_rewrite(config_path, _apply)
