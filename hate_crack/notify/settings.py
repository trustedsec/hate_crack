"""Notification settings: dataclass + atomic config persistence.

Settings live in the same ``config.json`` that drives the rest of hate_crack.
This module isolates (a) the typed shape of notification config and
(b) the read-modify-write persistence primitives used by the runtime toggle
and the ``[yes/no/always]`` per-attack prompt.

Persistence follows the same pattern as ``main.py`` (``json.load`` ->
mutate -> ``json.dump(..., indent=2)`` via a temp file and ``os.replace``)
so a crash mid-write cannot corrupt the config.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from typing import Any


@dataclass
class NotifySettings:
    """Typed view of the ``notify_*`` keys from ``config.json``.

    Defaults mirror ``config.json.example`` so freshly-loaded configs and
    in-memory fallbacks agree.
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


def _atomic_rewrite(config_path: str, mutator) -> None:
    """Read config_path, apply ``mutator(dict)`` in place, write atomically.

    - Missing file is treated as empty dict (mutator runs on ``{}``).
    - Invalid JSON is silently replaced with the mutator's output; we do not
      want to block a notification toggle on a pre-existing bad config.
    - Write goes to a temp file in the same directory and is swapped in
      via ``os.replace`` so readers never see a half-written file.
    """
    data: dict = {}
    if os.path.isfile(config_path):
        try:
            with open(config_path) as f:
                loaded = json.load(f)
                if isinstance(loaded, dict):
                    data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}
    mutator(data)
    directory = os.path.dirname(os.path.abspath(config_path)) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".config-", suffix=".json", dir=directory)
    try:
        with os.fdopen(fd, "w") as tmp:
            json.dump(data, tmp, indent=2)
        os.replace(tmp_path, config_path)
    except Exception:
        # Best-effort cleanup of stale temp file on failure.
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
    """Persist ``notify_per_crack_enabled`` without disturbing other config keys."""

    def _apply(data: dict) -> None:
        data["notify_per_crack_enabled"] = bool(enabled)

    _atomic_rewrite(config_path, _apply)


def add_to_allowlist(config_path: str, attack_name: str) -> None:
    """Append ``attack_name`` to ``notify_attack_allowlist`` if absent.

    Idempotent: already-present entries are a no-op.
    """
    if not attack_name:
        return

    def _apply(data: dict) -> None:
        current = data.get("notify_attack_allowlist")
        if not isinstance(current, list):
            current = []
        if attack_name not in current:
            current.append(attack_name)
        data["notify_attack_allowlist"] = current

    _atomic_rewrite(config_path, _apply)
