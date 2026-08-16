"""Resolve the per-user directories hashcat keeps its state in.

hashcat <= 6 kept everything under ``~/.hashcat``. hashcat 7 moved per-user
data to ``$XDG_DATA_HOME/hashcat`` (default ``~/.local/share/hashcat``) and the
kernel cache to ``$XDG_CACHE_HOME/hashcat`` (default ``~/.cache/hashcat``). It
prints a notice for as long as the old directory exists and never migrates or
deletes anything itself, so the directory has to be dealt with by hand.

That matters here because hate_crack used to ship the pre-7 potfile path as its
default *and* ``os.makedirs()`` it on every hashcat invocation. The old
directory therefore reappeared the moment hate_crack ran, so hashcat's notice
could never be cleared, and ``--potfile-path`` pointed at an empty file while
hashcat's real potfile sat in the new location -- cracks made outside
hate_crack were invisible to it.

The ``"auto"`` sentinel exists so the shipped default is a fixed literal (the
config drift-guard compares ``config.json.example`` against the schema) while
still resolving to whatever the installed hashcat actually uses. ``""`` keeps
its existing meaning: pass no ``--potfile-path`` at all.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from typing import NamedTuple, Optional

# The config value that means "ask the installed hashcat where its data lives".
AUTO = "auto"

_POTFILE_NAME = "hashcat.potfile"

# hashcat 7 is the release that moved per-user state out of ~/.hashcat.
_XDG_MAJOR = 7

_version_cache: dict[str, Optional[int]] = {}


def reset_version_cache() -> None:
    """Drop the memoized ``hashcat --version`` lookups (used by tests)."""
    _version_cache.clear()


def hashcat_major_version(hcat_bin: str = "hashcat") -> Optional[int]:
    """Return hashcat's major version, or ``None`` if it cannot be determined.

    ``hashcat --version`` prints something like ``v7.1.2-472-g33a1886ba``. The
    result is memoized per binary because this is consulted on every path
    resolution and a subprocess spawn per hashcat invocation is not free.
    """
    if hcat_bin in _version_cache:
        return _version_cache[hcat_bin]

    major: Optional[int] = None
    try:
        proc = subprocess.run(
            [hcat_bin, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0:
            text = proc.stdout.decode("utf-8", "replace")
            match = re.search(r"v?(\d+)\.\d+", text)
            if match:
                major = int(match.group(1))
    except (OSError, subprocess.SubprocessError, ValueError):
        major = None

    _version_cache[hcat_bin] = major
    return major


def legacy_data_dir() -> str:
    """The pre-7 directory: ``~/.hashcat``."""
    return os.path.expanduser("~/.hashcat")


def _xdg_dir(env_var: str, fallback: str) -> str:
    """Mirror hashcat's own XDG handling, including the parts that look wrong.

    hashcat branches on ``getenv(...) != NULL`` and interpolates the value
    verbatim, so a *relative* ``XDG_DATA_HOME`` really does send it to a
    cwd-relative directory, and an empty one really does send it to
    ``/hashcat``. Rejecting those as invalid would be defensible in isolation
    but would point hate_crack at a directory hashcat is not using, which is
    the whole class of bug this module exists to close. Verified against
    hashcat v7.1.2, not inferred: ``XDG_DATA_HOME=relative/path`` creates
    ``./relative/path/hashcat`` and leaves ``~/.local/share`` untouched.

    The result is made absolute so hate_crack holds a stable path even though
    hashcat resolves its copy per run.
    """
    base = os.environ.get(env_var)
    if base is None:
        return os.path.expanduser(fallback)
    return os.path.abspath(f"{base}/hashcat")


def modern_data_dir() -> str:
    """The hashcat 7 per-user data directory (potfile, sessions)."""
    return _xdg_dir("XDG_DATA_HOME", "~/.local/share/hashcat")


def modern_cache_dir() -> str:
    """The hashcat 7 kernel-cache directory."""
    return _xdg_dir("XDG_CACHE_HOME", "~/.cache/hashcat")


def hashcat_data_dir(hcat_bin: str = "hashcat") -> str:
    """Resolve the directory the installed hashcat keeps per-user state in.

    Version is the authority. When hashcat cannot be run at all (not installed
    yet, not on PATH in a worktree) fall back to whichever directory already
    exists, preferring the modern one, so a machine that has already moved on
    is not dragged back to the legacy layout.
    """
    major = hashcat_major_version(hcat_bin)
    if major is not None:
        return modern_data_dir() if major >= _XDG_MAJOR else legacy_data_dir()

    modern = modern_data_dir()
    if os.path.isdir(modern):
        return modern
    if os.path.isdir(legacy_data_dir()):
        return legacy_data_dir()
    return modern


def default_potfile_path(hcat_bin: str = "hashcat") -> str:
    """The potfile path the installed hashcat would use on its own."""
    return os.path.join(hashcat_data_dir(hcat_bin), _POTFILE_NAME)


def resolve_potfile_setting(
    raw: object,
    *,
    base_dir: str,
    hcat_bin: str = "hashcat",
) -> str:
    """Turn a raw ``hcatPotfilePath`` config value into an absolute path.

    ``""`` stays empty (the "pass no ``--potfile-path``" sentinel) and ``AUTO``
    resolves to hashcat's own location. Anything else is expanded and, if
    relative, anchored to ``base_dir`` -- matching the pre-existing behavior.
    """
    value = (str(raw) if raw is not None else "").strip()
    if value == "":
        return ""
    if value.lower() == AUTO:
        return default_potfile_path(hcat_bin)
    expanded = os.path.expanduser(value)
    if not os.path.isabs(expanded):
        expanded = os.path.join(base_dir, expanded)
    return expanded


class LegacyHome(NamedTuple):
    """What, if anything, is stranded in the pre-7 ``~/.hashcat``."""

    path: str
    potfile_bytes: int
    session_count: int
    other_entries: int

    @property
    def has_content(self) -> bool:
        return (
            self.potfile_bytes > 0 or self.session_count > 0 or self.other_entries > 0
        )


def inspect_legacy_home(hcat_bin: str = "hashcat") -> Optional[LegacyHome]:
    """Summarize ``~/.hashcat``, or return ``None`` if there is nothing there.

    A ``~/.hashcat`` that is a *symlink* onto the current data directory counts
    as nothing: hand-migrating with ``ln -s`` is a reasonable thing to have
    done, and following the link would report the live, in-use potfile and
    sessions as stranded and tell the operator to delete them.
    """
    path = legacy_data_dir()
    if not os.path.isdir(path):
        return None
    if os.path.realpath(path) == os.path.realpath(hashcat_data_dir(hcat_bin)):
        return None

    potfile_bytes = 0
    session_count = 0
    other_entries = 0
    try:
        entries = sorted(os.listdir(path))
    except OSError:
        return LegacyHome(path, 0, 0, 0)

    for name in entries:
        full = os.path.join(path, name)
        if name == _POTFILE_NAME:
            try:
                potfile_bytes = os.path.getsize(full)
            except OSError:
                potfile_bytes = 0
        elif name == "sessions" and os.path.isdir(full):
            try:
                session_count = len(os.listdir(full))
            except OSError:
                session_count = 0
        else:
            other_entries += 1

    return LegacyHome(path, potfile_bytes, session_count, other_entries)


def legacy_home_warning(hcat_bin: str = "hashcat") -> Optional[str]:
    """Return the operator-facing notice about a stranded ``~/.hashcat``.

    ``None`` when there is nothing to say: no legacy directory, an empty one,
    or a hashcat old enough that the legacy directory is still the real home.
    """
    if hashcat_data_dir(hcat_bin) == legacy_data_dir():
        return None
    legacy = inspect_legacy_home(hcat_bin)
    if legacy is None or not legacy.has_content:
        return None

    held = []
    if legacy.potfile_bytes > 0:
        held.append(f"{legacy.potfile_bytes / 1_048_576:.1f} MiB potfile")
    if legacy.session_count > 0:
        held.append(f"{legacy.session_count} session(s)")
    if legacy.other_entries > 0:
        held.append(f"{legacy.other_entries} other file(s)")

    return (
        f"[!] Found legacy {legacy.path} (the hashcat <= 6 layout), holding "
        + ", ".join(held)
        + ".\n"
        f"    hashcat now keeps per-user data in {modern_data_dir()}\n"
        f"    and its kernel cache in {modern_cache_dir()}.\n"
        "    Nothing there is being used. Copy it across with:\n"
        "        hate_crack.py --migrate-hashcat-home\n"
        "    then delete the old directory yourself."
    )


class MigrationResult(NamedTuple):
    copied: list[str]
    skipped: list[str]
    source: str
    destination: str


def migrate_legacy_home(
    *, dry_run: bool = False, hcat_bin: str = "hashcat"
) -> MigrationResult:
    """Copy ``~/.hashcat`` contents into hashcat's current data directory.

    Never overwrites and never deletes. A name that already exists at the
    destination is copied alongside it with a ``.from-legacy`` suffix rather
    than merged, because merging two potfiles is a judgement call that belongs
    to the operator, not to a startup helper.
    """
    source = legacy_data_dir()
    destination = hashcat_data_dir(hcat_bin)
    copied: list[str] = []
    skipped: list[str] = []

    if not os.path.isdir(source):
        return MigrationResult(copied, skipped, source, destination)
    # realpath, not abspath: a hand-migrated `ln -s ~/.local/share/hashcat
    # ~/.hashcat` compares unequal under abspath, and the loop would then walk
    # the destination's own entries and duplicate every one of them onto
    # itself as `<name>.from-legacy`.
    if os.path.realpath(source) == os.path.realpath(destination):
        return MigrationResult(copied, skipped, source, destination)

    try:
        entries = sorted(os.listdir(source))
    except OSError as exc:
        raise OSError(f"Cannot read {source}: {exc}") from exc

    if not dry_run:
        os.makedirs(destination, exist_ok=True)

    for name in entries:
        src = os.path.join(source, name)
        dst = os.path.join(destination, name)
        if os.path.exists(dst):
            dst = dst + ".from-legacy"
            if os.path.exists(dst):
                skipped.append(name)
                continue
        if dry_run:
            copied.append(name)
            continue
        # Stage under a `.partial` name and rename on success. A potfile can be
        # hundreds of MB, so a copy that dies on ENOSPC part-way through would
        # otherwise leave a truncated file sitting at the destination -- and if
        # the destination did not previously exist, that truncated file becomes
        # hashcat's live potfile while this reports only "skipped".
        staged = dst + ".partial"
        try:
            _remove(staged)
            if os.path.isdir(src) and not os.path.islink(src):
                shutil.copytree(src, staged, dirs_exist_ok=False)
            else:
                shutil.copy2(src, staged)
            os.replace(staged, dst)
            copied.append(name)
        except (OSError, shutil.Error):
            _remove(staged)
            skipped.append(name)

    return MigrationResult(copied, skipped, source, destination)


def _remove(path: str) -> None:
    """Best-effort delete of a staging path (never a user's own file)."""
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        elif os.path.lexists(path):
            os.unlink(path)
    except OSError:
        pass
