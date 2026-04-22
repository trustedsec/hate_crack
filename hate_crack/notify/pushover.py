"""Pushover HTTP backend.

Single concrete entry point: :func:`_send_pushover`.  Exposed as a module-level
function (not a class) so that wiring in a Slack or generic webhook backend
later is a matter of writing a sibling ``_send_slack()`` alongside this one.

Design invariants:

- The call is a best-effort side effect. A crashed attack is strictly worse
  than a missed notification, so every exception below the ``requests`` layer
  is caught and swallowed (returning ``False``).
- Missing ``requests`` is treated the same as any other transport error —
  we log a warning once and return ``False`` without re-raising.
- Payload contains *only* title + message + credentials. No plaintexts, no
  hash data. The tailer guarantees this at call sites; this function is the
  final safety barrier if a caller passes bad data (we still forward whatever
  string it gives us, but we never introspect outside the message).
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    import requests  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover - requests is a hard dep of the package
    requests = None  # type: ignore[assignment]


PUSHOVER_URL = "https://api.pushover.net/1/messages.json"


def _send_pushover(token: str, user: str, title: str, message: str) -> bool:
    """POST a notification to Pushover.

    Returns ``True`` on HTTP 200, ``False`` on any other outcome. Never
    raises — network errors, missing credentials, and missing ``requests``
    are all funneled into a ``False`` return so the caller can treat the
    notification as a fire-and-forget side effect.
    """
    if not token or not user:
        logger.debug("Pushover not configured: missing token or user")
        return False

    if requests is None:
        logger.warning("Pushover requested but 'requests' is not importable")
        return False

    payload = {
        "token": token,
        "user": user,
        "title": title,
        "message": message,
    }
    try:
        response = requests.post(PUSHOVER_URL, data=payload, timeout=10)
    except Exception as exc:
        # requests.RequestException covers most, but a plugin/mock may raise
        # a bare Exception — we must never let this escape.
        logger.warning("Pushover send failed: %s", exc)
        return False

    status = getattr(response, "status_code", None)
    if status == 200:
        return True
    logger.warning("Pushover send returned HTTP %s", status)
    return False
