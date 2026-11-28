"""Read what hashcat wrote to a session's log during one run.

hashcat appends a ``status-after-work`` line to ``sessions/<session>.log`` for
every queue item (each wordlist or mask) it finishes. The value is its
``devices_status``: ``5`` when the item was exhausted, ``9`` (``STATUS_BYPASS``)
when it was skipped -- by pressing ``b``, by ``--bypass-eta`` /
``--bypass-threshold``, or because a mask was too long for the kernel.

Since hashcat b1b1f3ea (2026-11-27) a queue whose last item was bypassed exits
1, the same code as a genuine exhaustion, so the exit code alone can no longer
tell the coverage store that the keyspace was enumerated. This module answers
"was anything bypassed in *this* run?" by remembering each log's size before
launch and reading only what was appended after it -- the log accumulates
across runs that share a session name.

Locations are computed from environment variables only, never by running
hashcat, so this is safe to call while ``subprocess.Popen`` is patched.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterable, Mapping, Sequence

from hate_crack import hashcat_paths

STATUS_BYPASS = "9"
_KEY = "status-after-work"


def session_name(cmd: Sequence[str]) -> str | None:
    """The ``--session`` value in a hashcat argv, or ``None``.

    hashcat honours the last ``--session``, and attacks append the operator's
    ``hcatTuning`` after their own, so the last valid occurrence wins.
    """
    name: str | None = None
    for index, arg in enumerate(cmd):
        if arg == "--session":
            if index + 1 < len(cmd):
                name = str(cmd[index + 1])
        elif isinstance(arg, str) and arg.startswith("--session="):
            name = arg.split("=", 1)[1] or name
    return name


def candidate_log_paths(session: str, hcat_bin: str) -> list[str]:
    """Every place this hashcat might keep ``<session>.log``, deduplicated.

    hashcat 7+ installed builds use the XDG data dir, pre-7 builds use
    ``~/.hashcat``, and a build run from its own folder keeps state beside
    the binary.
    """
    name = f"{session}.log"
    dirs = [hashcat_paths.modern_data_dir(), hashcat_paths.legacy_data_dir()]
    resolved = shutil.which(hcat_bin) or hcat_bin
    if os.path.isabs(resolved):
        dirs.append(os.path.dirname(os.path.realpath(resolved)))
    paths: list[str] = []
    for directory in dirs:
        path = os.path.join(directory, "sessions", name)
        if path not in paths:
            paths.append(path)
    return paths


def snapshot(paths: Iterable[str]) -> dict[str, int]:
    """Byte size of each log right now; ``0`` for one that does not exist."""
    sizes: dict[str, int] = {}
    for path in paths:
        try:
            sizes[path] = os.path.getsize(path)
        except OSError:
            sizes[path] = 0
    return sizes


def _bypassed_in(data: bytes) -> bool:
    for raw in data.splitlines():
        fields = raw.decode("utf-8", "replace").split("\t")
        if (
            len(fields) >= 4
            and fields[2] == _KEY
            and fields[3].strip() == STATUS_BYPASS
        ):
            return True
    return False


def bypassed_since(offsets: Mapping[str, int]) -> bool | None:
    """Whether any log gained a bypass line after its recorded offset.

    ``None`` means no log could be read at all, so the run's outcome is
    unknown and the caller keeps its exit-code-only behaviour.
    """
    readable = False
    for path, offset in offsets.items():
        try:
            if not os.path.isfile(path):
                continue
            # A log smaller than its snapshot was truncated or replaced, so
            # everything in it is new.
            start = offset if os.path.getsize(path) >= offset else 0
            with open(path, "rb") as fh:
                fh.seek(start)
                data = fh.read()
        except OSError:
            continue
        readable = True
        if _bypassed_in(data):
            return True
    return False if readable else None
