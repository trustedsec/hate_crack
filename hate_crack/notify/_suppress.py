"""Thread-local notification suppression.

Multi-phase orchestrators (e.g. ``extensive_crack``) chain many hashcat
invocations.  Without suppression every primitive would fire its own
"job complete" notification — loud, useless, and easy to rate-limit into
the ground.  Callers wrap the chain in :func:`suppressed_notifications`
and then fire exactly one aggregate notification at the end.

Suppression is thread-local so a tailer thread in a different context
can't accidentally silence itself by observing another thread's flag.
"""

from __future__ import annotations

import contextlib
import threading

_suppressed = threading.local()


def is_suppressed() -> bool:
    """Return True if the calling thread is inside a suppression context."""
    return getattr(_suppressed, "active", False)


@contextlib.contextmanager
def suppressed_notifications():
    """Context manager that suppresses notify_* calls on the current thread.

    Nests correctly: the previous state is restored on exit so an outer
    ``with`` block still reflects "suppressed" after an inner one exits.
    """
    prev = getattr(_suppressed, "active", False)
    _suppressed.active = True
    try:
        yield
    finally:
        _suppressed.active = prev
