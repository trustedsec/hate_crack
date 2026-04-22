"""Background tailer that watches ``{hashfile}.out`` for new cracks.

Design rationale:

- Polling (not inotify/fsevents) keeps the implementation portable across
  macOS/Linux without adding a dependency.
- We seek to EOF on start: the hashfile may already contain cracks from a
  previous run, and re-notifying those would be both wrong and spammy.
- Burst cap: if a single poll tick yields more cracks than the user's
  configured threshold, we collapse them into one aggregated notification
  instead of N pings.  Cracks tend to arrive in rule-file bursts, so this
  knob matters.
- The thread is a daemon so a hung tailer can't block process exit.
- ``stop()`` joins with a timeout to guarantee forward progress even if the
  poll loop is stuck on a slow filesystem.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Callable

from hate_crack.notify.settings import NotifySettings

logger = logging.getLogger(__name__)


def extract_username_from_out_line(line: str) -> str | None:
    """Extract a username from a single hashcat ``.out`` line, if present.

    We support the four output layouts hate_crack can produce upstream:

    =======================  ===========================================  ============
    Input shape              Example                                      Returns
    =======================  ===========================================  ============
    bare hash                ``5f4dcc3b5aa:plaintext``                    ``None``
    user:hash:plain          ``alice:5f4dcc:plaintext``                   ``"alice"``
    pwdump                   ``alice:1001:aad3b:31d6:::plaintext``        ``"alice"``
    NetNTLMv2                ``alice::DOMAIN:challenge:response:plain``   ``"alice"``
    =======================  ===========================================  ============

    The function deliberately NEVER returns the plaintext — that would
    defeat the privacy guarantee documented on the notify public API.
    """
    if not line:
        return None
    stripped = line.rstrip("\r\n")
    if not stripped:
        return None

    parts = stripped.split(":")
    if len(parts) < 2:
        return None

    # Bare hash (hash:plain): exactly two colons-separated fields and the
    # first field is a plausible hash — any non-empty first field that is
    # not a pure hex string may still be a username, so we fall through.
    if len(parts) == 2:
        return None

    first = parts[0]
    if not first:
        # Lines that start with ':' aren't in any format we care about.
        return None

    # pwdump: user:RID:LM:NT:::plain  -> field[1] is numeric RID
    if len(parts) >= 7 and parts[1].isdigit():
        return first

    # NetNTLMv2: user::DOMAIN:...  -> field[1] is empty
    if len(parts) >= 5 and parts[1] == "":
        return first

    # user:hash:plain style — assume first field is username.
    # We only claim this when there's at least 3 fields so we don't
    # mis-label a bare ``hash:plain`` as ``username:plain``.
    if len(parts) >= 3:
        return first

    return None


class CrackTailer(threading.Thread):
    """Polls ``out_path`` for new cracked lines and dispatches notifications.

    The tailer is created and started by :func:`hate_crack.notify.start_tailer`
    and stopped by :func:`hate_crack.notify.stop_tailer`.  External callers
    normally don't touch this class directly; it's public for tests.
    """

    daemon = True

    def __init__(
        self,
        out_path: str,
        attack_name: str,
        settings: NotifySettings,
        notify_callback: Callable[[str, str], None],
        aggregate_callback: Callable[[int, str], None],
        *,
        username_extractor: Callable[[str], str | None] | None = None,
    ) -> None:
        super().__init__(name=f"CrackTailer[{attack_name}]", daemon=True)
        self.out_path = out_path
        self.attack_name = attack_name
        self.settings = settings
        self._notify_crack = notify_callback
        self._notify_aggregate = aggregate_callback
        self._extract_username = username_extractor or extract_username_from_out_line
        self._stop = threading.Event()
        # Leftover bytes from the previous read that didn't end in \n.
        self._buffer = b""
        # File position to read from; set on first successful open.
        self._file_pos: int | None = None

    def stop(self) -> None:
        """Signal the thread to exit and join with a bounded timeout.

        Safe to call on a tailer that was never started; in that case the
        signal is still set (so a later ``start()`` would exit immediately)
        and we skip the join that would otherwise raise.
        """
        self._stop.set()
        if self._started.is_set():
            self.join(timeout=10.0)

    def run(self) -> None:  # pragma: no cover - thread entry, exercised via tests
        try:
            self._seek_to_eof()
            # First tick of ``wait()`` blocks for the full interval; this is
            # deliberate so we don't hammer the filesystem immediately after
            # starting if hashcat hasn't written anything yet.
            while not self._stop.wait(self.settings.poll_interval_seconds):
                try:
                    self._poll_once()
                except Exception as exc:
                    logger.warning("CrackTailer poll failed: %s", exc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("CrackTailer crashed: %s", exc)

    def _seek_to_eof(self) -> None:
        """Remember the current EOF so existing cracks aren't re-notified."""
        if os.path.isfile(self.out_path):
            try:
                self._file_pos = os.path.getsize(self.out_path)
            except OSError:
                self._file_pos = 0
        else:
            self._file_pos = 0

    def _poll_once(self) -> None:
        if not os.path.isfile(self.out_path):
            return
        try:
            size = os.path.getsize(self.out_path)
        except OSError:
            return

        if self._file_pos is None:
            self._file_pos = size
            return

        if size < self._file_pos:
            # File was truncated / rewritten — reset rather than read garbage.
            self._file_pos = 0
            self._buffer = b""

        if size == self._file_pos:
            return

        new_lines = self._read_new_lines(size)
        if not new_lines:
            return

        count = len(new_lines)
        if count > self.settings.max_cracks_per_burst:
            self._notify_aggregate(count, self.attack_name)
            return

        for line_bytes in new_lines:
            try:
                line = line_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue
            label = self._extract_username(line) or self.attack_name
            self._notify_crack(label, self.attack_name)

    def _read_new_lines(self, size: int) -> list[bytes]:
        """Read from ``self._file_pos`` up to ``size`` and return full lines.

        Incomplete trailing bytes are buffered for the next tick.
        """
        try:
            with open(self.out_path, "rb") as f:
                f.seek(self._file_pos)
                data = f.read(size - self._file_pos)
        except OSError:
            return []
        self._file_pos = size

        combined = self._buffer + data
        lines = combined.split(b"\n")
        # The last element is either empty (buffer ended on \n) or a partial
        # line — stash it for next poll either way.
        self._buffer = lines.pop() if lines else b""
        return [line for line in lines if line]
