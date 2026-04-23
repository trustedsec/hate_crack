"""Public notification API for hate_crack.

Overview
========

This package wires per-attack and per-crack notifications into the core
hashcat runner.  The design is intentionally small and functional: a single
module-level ``_settings`` object, a handful of helper functions, and one
``CrackTailer`` thread class where polling state genuinely wants OO.

Wiring
======

At startup ``main.py`` calls :func:`init` with the resolved config path and
parsed config dict.  After that, the rest of the codebase interacts with
this package via:

- :func:`prompt_notify_for_attack`  -- called by attacks.py before an attack
  starts; asks the user ``[y/n/always]`` and stashes per-run consent.
- :func:`start_tailer` / :func:`stop_tailer` -- called by the hashcat
  command wrapper to spin a background watcher on ``{hashfile}.out``.
- :func:`notify_job_done` -- called by the hashcat command wrapper after
  the subprocess exits, fires one summary notification.
- :func:`suppressed_notifications` -- context manager for orchestrator
  attacks that chain many primitives; collapses all nested notifications
  so the orchestrator can fire a single aggregate at the end.

Adding a new backend
====================

The single concrete HTTP call lives in :mod:`hate_crack.notify.pushover`.
To add Slack/webhooks, write a sibling ``_send_slack()`` there (or in a
new module) and dispatch from :func:`notify_job_done` /
:func:`notify_crack`.  No framework, no ABC — one function per transport.
"""

from __future__ import annotations

import logging
from typing import Callable

from hate_crack.notify._suppress import (
    is_suppressed,
    suppressed_notifications,
)
from hate_crack.notify.pushover import _send_pushover
from hate_crack.notify.settings import (
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
    save_per_crack_enabled,
)
from hate_crack.notify.tailer import (
    CrackTailer,
    extract_username_from_out_line,
)

logger = logging.getLogger(__name__)


# Module-level runtime state. Treated as a singleton because the CLI is a
# single-process tool with a single user; no need to pass a context object
# through every attack signature.
_settings: NotifySettings | None = None
_config_path: str | None = None

# Per-run consent cache: attack_name -> bool.  Populated by
# ``prompt_notify_for_attack`` and consulted by ``notify_job_done`` so we
# don't need to re-prompt mid-chain.
_run_consent: dict[str, bool] = {}

# Input function indirection so tests can inject answers without pulling
# in a terminal. Swap via ``set_input_func``.
_input_func: Callable[[str], str] = input


__all__ = [
    "CrackTailer",
    "NotifySettings",
    "add_to_allowlist",
    "clear_state_for_tests",
    "extract_username_from_out_line",
    "get_settings",
    "init",
    "is_suppressed",
    "notify_crack",
    "notify_job_done",
    "prompt_notify_for_attack",
    "set_input_func",
    "start_tailer",
    "stop_tailer",
    "suppressed_notifications",
    "toggle_enabled",
    "toggle_per_crack_enabled",
    "_send_pushover",
]


def init(config_path: str | None, config_parser: dict | None) -> None:
    """Bootstrap the notify subsystem from the resolved config.

    Called once from ``main.py`` after its config-loading block.  Safe to
    call multiple times — the second call replaces settings but does not
    reset per-run consent (the user may already have answered prompts).
    """
    global _settings, _config_path
    _config_path = config_path
    _settings = load_settings(config_parser)


def get_settings() -> NotifySettings:
    """Return the active settings, or fresh defaults if ``init`` never ran."""
    return _settings if _settings is not None else NotifySettings()


def set_input_func(func: Callable[[str], str]) -> None:
    """Test hook: swap the ``input()`` used by :func:`prompt_notify_for_attack`."""
    global _input_func
    _input_func = func


def clear_state_for_tests() -> None:
    """Reset module state.  Only used by the test suite."""
    global _settings, _config_path, _input_func
    _settings = None
    _config_path = None
    _run_consent.clear()
    _input_func = input


def toggle_enabled() -> bool:
    """Flip ``notify_enabled``, persist to ``config.json``, return new state.

    If ``init`` was never called we still toggle an in-memory default — the
    UI update must not crash even if the config file is unreachable.
    """
    global _settings
    if _settings is None:
        _settings = NotifySettings()
    _settings.enabled = not _settings.enabled
    if _config_path:
        try:
            save_enabled(_config_path, _settings.enabled)
        except OSError as exc:
            logger.warning("Could not persist notify_enabled: %s", exc)
    return _settings.enabled


def toggle_per_crack_enabled() -> bool:
    """Flip ``notify_per_crack_enabled``, persist to ``config.json``, return new state.

    If ``init`` was never called we still toggle an in-memory default — the
    UI update must not crash even if the config file is unreachable.
    """
    global _settings
    if _settings is None:
        _settings = NotifySettings()
    _settings.per_crack_enabled = not _settings.per_crack_enabled
    if _config_path:
        try:
            save_per_crack_enabled(_config_path, _settings.per_crack_enabled)
        except OSError as exc:
            logger.warning("Could not persist notify_per_crack_enabled: %s", exc)
    return _settings.per_crack_enabled


def _in_allowlist(attack_name: str) -> bool:
    return attack_name in get_settings().attack_allowlist


def prompt_notify_for_attack(attack_name: str) -> bool:
    """Ask the user whether this attack should fire a notification.

    Returns ``True`` if notifications should fire for this run.

    Flow:

    1. Notifications disabled globally  -> return False silently (no prompt).
    2. Attack already in allowlist       -> return True (no prompt, auto-on).
    3. Otherwise                         -> prompt ``[y/n/always]``:
        * ``y``      -> consent for this run only.
        * ``n`` / "" -> no consent.
        * ``always`` -> persist to allowlist and consent for this run.

    Per-run consent is stashed in ``_run_consent[attack_name]`` so the
    hashcat wrapper can query it at job-done time without re-prompting.
    """
    settings = get_settings()
    if not settings.enabled:
        _run_consent[attack_name] = False
        return False
    if _in_allowlist(attack_name):
        _run_consent[attack_name] = True
        return True

    try:
        raw = _input_func(
            f"\n[notify] Send Pushover notifications for '{attack_name}'? [y/N/always]: "
        )
    except EOFError:
        raw = ""
    answer = (raw or "").strip().lower()
    if answer == "always":
        _run_consent[attack_name] = True
        if _config_path:
            try:
                add_to_allowlist(_config_path, attack_name)
                # Also update the in-memory settings so a later call in the
                # same session sees the allowlist without re-reading config.
                if attack_name not in settings.attack_allowlist:
                    settings.attack_allowlist.append(attack_name)
            except OSError as exc:
                logger.warning("Could not persist allowlist entry: %s", exc)
        return True
    if answer in ("y", "yes"):
        _run_consent[attack_name] = True
        return True
    _run_consent[attack_name] = False
    return False


def _should_fire(attack_name: str) -> bool:
    if is_suppressed():
        return False
    settings = get_settings()
    if not settings.enabled:
        return False
    if _in_allowlist(attack_name):
        return True
    return _run_consent.get(attack_name, False)


def notify_job_done(
    attack_name: str,
    cracked_count: int,
    hash_file: str | None = None,
) -> None:
    """Fire a single "attack complete" notification.

    No-op when suppressed, disabled, or the user declined at the prompt.
    """
    if not _should_fire(attack_name):
        return
    settings = get_settings()
    title = f"hate_crack: {attack_name} complete"
    if hash_file:
        message = (
            f"Attack '{attack_name}' finished.\n"
            f"Cracked so far: {cracked_count}\n"
            f"Hash file: {hash_file}"
        )
    else:
        message = f"Attack '{attack_name}' finished.\nCracked so far: {cracked_count}"
    _send_pushover(settings.pushover_token, settings.pushover_user, title, message)


def notify_crack(label: str, attack_name: str) -> None:
    """Fire a per-crack notification (called from :class:`CrackTailer`)."""
    if not _should_fire(attack_name):
        return
    settings = get_settings()
    title = "hate_crack: new crack"
    message = f"{label} cracked ({attack_name})"
    _send_pushover(settings.pushover_token, settings.pushover_user, title, message)


def _notify_aggregate(count: int, attack_name: str) -> None:
    """Aggregated "N accounts cracked" notification for burst-capped ticks."""
    if not _should_fire(attack_name):
        return
    settings = get_settings()
    title = "hate_crack: crack burst"
    message = f"{count} new accounts cracked ({attack_name})"
    _send_pushover(settings.pushover_token, settings.pushover_user, title, message)


def start_tailer(out_path: str, attack_name: str) -> CrackTailer | None:
    """Start a :class:`CrackTailer` if per-crack notifications are enabled.

    Returns the running tailer (so the caller can stop it later), or
    ``None`` when suppression/disabled/disallowed mean we shouldn't tail.
    """
    if is_suppressed():
        return None
    settings = get_settings()
    if not settings.enabled:
        return None
    if not settings.per_crack_enabled:
        return None
    if not _should_fire(attack_name):
        return None
    tailer = CrackTailer(
        out_path=out_path,
        attack_name=attack_name,
        settings=settings,
        notify_callback=notify_crack,
        aggregate_callback=_notify_aggregate,
    )
    tailer.start()
    return tailer


def stop_tailer(tailer: CrackTailer | None) -> None:
    """Stop a tailer started by :func:`start_tailer`.  ``None`` is a no-op."""
    if tailer is None:
        return
    try:
        tailer.stop()
    except Exception as exc:
        logger.warning("CrackTailer.stop() failed: %s", exc)
