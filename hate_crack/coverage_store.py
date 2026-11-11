"""The SQLite file behind attack coverage, one per hash file.

The store sits beside the hash file it describes, as
``<realpath(hash_file)>.coverage.sqlite3`` -- next to ``.out``, ``.rosetta/``
and the Pipal hints -- so coverage is archived, moved and deleted with the
engagement, and no engagement's identifiers accumulate in ``~/.hate_crack``.

Everything is an integer. Targets, wordlists and variants are interned into
small tables, and a covered rule or mask line is a signed 64-bit blake2b of
its bytes (see ``attack_coverage.entry_hash``). The ``covered`` primary key
leads with the probe scope -- target, wordlist, variant, kind -- so a
membership test is a range scan inside one slice of one engagement.

Wordlists are identified by ``(realpath, size, mtime_ns)`` from one ``stat()``
and are never opened. The store this replaced content-hashed them, which made
the first plan against a 40 GB corpus a full sequential read before hashcat
started.

**Failure is loud, then inert.** A store that cannot be opened or written
prints one ``[!] Coverage disabled for ...`` line and then answers every
question with "unknown", which ``plan_run`` turns into an unfiltered run. The
store this replaced swallowed those errors silently, and a read-only file went
unnoticed for six weeks.
"""

import ctypes
import ctypes.util
import json
import os
import sqlite3
import stat as stat_module
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from hate_crack.ui import get_ui

STORE_SUFFIX = ".coverage.sqlite3"
SCHEMA_VERSION = 1

# Stored as integers; the names exist only at the API boundary.
KINDS = {"history": 0, "rule": 1, "mask": 2, "wordlist": 3}

# wl_id for a run with no wordlist (a mask attack). Real ids start at 1.
NO_WORDLIST = 0

_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id     INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS wordlists (
    id       INTEGER PRIMARY KEY,
    realpath TEXT NOT NULL,
    size     INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    UNIQUE (realpath, size, mtime_ns)
);
CREATE TABLE IF NOT EXISTS variants (
    id      INTEGER PRIMARY KEY,
    variant TEXT NOT NULL UNIQUE
);
-- One row per hashcat invocation; also the run history. new_entries is how
-- many covered rows this run added, which is what summary() reports per
-- attack now that covered rows carry no run id.
CREATE TABLE IF NOT EXISTS runs (
    id          INTEGER PRIMARY KEY,
    target_id   INTEGER NOT NULL,
    attack      TEXT NOT NULL,
    kind        INTEGER NOT NULL,
    detail      TEXT NOT NULL DEFAULT '',
    ran_at      TEXT NOT NULL,
    new_entries INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS runs_target ON runs (target_id, attack, kind);
-- Which wordlists a run declared. Only has_prior_run reads this, to decide
-- whether to ask the up-front batch question without reading a rule file.
CREATE TABLE IF NOT EXISTS run_wordlists (
    run_id INTEGER NOT NULL,
    wl_id  INTEGER NOT NULL,
    PRIMARY KEY (run_id, wl_id)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS run_wordlists_wl ON run_wordlists (wl_id);
-- Column order is load-bearing: the first four columns are the probe scope.
CREATE TABLE IF NOT EXISTS covered (
    target_id  INTEGER NOT NULL,
    wl_id      INTEGER NOT NULL,
    variant_id INTEGER NOT NULL,
    kind       INTEGER NOT NULL,
    entry_h    INTEGER NOT NULL,
    PRIMARY KEY (target_id, wl_id, variant_id, kind, entry_h)
) WITHOUT ROWID;
"""

# Membership inside one probe scope, as one static statement with one bound
# JSON array: json_each sidesteps SQLite's parameter limit without building
# placeholders by interpolation.
_COVERED_IN_JSON = (
    "SELECT entry_h FROM covered "
    "WHERE target_id = ? AND wl_id = ? AND variant_id = ? AND kind = ? "
    "AND entry_h IN (SELECT value FROM json_each(?))"
)
_COVERED_VIA_PROBE = (
    "SELECT covered.entry_h FROM covered "
    "JOIN coverage_probe ON covered.entry_h = coverage_probe.h "
    "WHERE covered.target_id = ? AND covered.wl_id = ? "
    "AND covered.variant_id = ? AND covered.kind = ?"
)
_INSERT_COVERED = (
    "INSERT OR IGNORE INTO covered "
    "(target_id, wl_id, variant_id, kind, entry_h) VALUES (?, ?, ?, ?, ?)"
)
_PRIOR_RUN = "SELECT 1 FROM runs WHERE target_id = ? AND attack = ? LIMIT 1"
_PRIOR_RUN_KIND = (
    "SELECT 1 FROM runs WHERE target_id = ? AND attack = ? AND kind = ? LIMIT 1"
)
_PRIOR_RUN_WORDLISTS = (
    "SELECT 1 FROM runs JOIN run_wordlists ON run_wordlists.run_id = runs.id "
    "WHERE runs.target_id = ? AND runs.attack = ? "
    "AND run_wordlists.wl_id IN (SELECT value FROM json_each(?)) LIMIT 1"
)
_PRIOR_RUN_WORDLISTS_KIND = (
    "SELECT 1 FROM runs JOIN run_wordlists ON run_wordlists.run_id = runs.id "
    "WHERE runs.target_id = ? AND runs.attack = ? AND runs.kind = ? "
    "AND run_wordlists.wl_id IN (SELECT value FROM json_each(?)) LIMIT 1"
)

# --- location ----------------------------------------------------------------


def store_path_for(hash_file: str) -> Path:
    """Where the coverage store for ``hash_file`` lives."""
    return Path(os.path.realpath(hash_file) + STORE_SUFFIX)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# --- network filesystem detection --------------------------------------------
#
# WAL keeps its index in shared memory beside the database, which SMB and NFS
# do not coordinate between hosts. On a network filesystem the store falls back
# to a rollback journal. Detection failure means "local": WAL on a local disk
# is what the old store always did.

_LINUX_NETWORK_FSTYPES = frozenset(
    {"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p"}
)

# <sys/mount.h>: the filesystem is stored locally.
_MNT_LOCAL = 0x00001000


class _DarwinStatfs(ctypes.Structure):
    # struct statfs with 64-bit inodes, the only layout on arm64 and the
    # default on x86_64 since 10.6. Verified on arm64 (sizeof == 2168):
    # APFS volumes set MNT_LOCAL, an NFS mount does not.
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", ctypes.c_int32 * 2),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _darwin_is_network_fs(directory: str) -> bool:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    try:
        statfs = libc["statfs$INODE64"]  # x86_64 exports the 64-bit-inode ABI here
    except AttributeError:
        statfs = libc.statfs  # arm64 has only the 64-bit-inode ABI
    statfs.argtypes = [ctypes.c_char_p, ctypes.POINTER(_DarwinStatfs)]
    statfs.restype = ctypes.c_int
    buf = _DarwinStatfs()
    if statfs(os.fsencode(directory), ctypes.byref(buf)) != 0:
        return False
    return not buf.f_flags & _MNT_LOCAL


def _linux_is_network_fs(directory: str) -> bool:
    real = os.path.realpath(directory)
    best_mount, best_type = "", ""
    with open("/proc/self/mounts", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            fields = line.split()
            if len(fields) < 3:
                continue
            # Mount points escape spaces and friends as octal (\040).
            mount = fields[1].encode().decode("unicode_escape")
            inside = real == mount or real.startswith(mount.rstrip("/") + "/")
            if inside and len(mount) >= len(best_mount):
                best_mount, best_type = mount, fields[2]
    return best_type in _LINUX_NETWORK_FSTYPES


def _platform_is_network_fs(directory: str) -> bool:
    if sys.platform == "darwin":
        return _darwin_is_network_fs(directory)
    if sys.platform.startswith("linux"):
        return _linux_is_network_fs(directory)
    return False


def is_network_fs(directory: str) -> bool:
    """Best effort: is ``directory`` on a network filesystem? Never raises."""
    try:
        return _platform_is_network_fs(directory)
    except (OSError, ValueError, AttributeError, UnicodeError):
        return False


# --- store -------------------------------------------------------------------


class CoverageStore:
    """One hash file's coverage store.

    No method raises :class:`sqlite3.Error`. The first failure disables the
    store for the rest of the process with one visible warning, and every
    later call answers "unknown" -- an unfiltered run costs time, a crash
    costs the operator their session.
    """

    def __init__(self, path: Path | str):
        self._path = Path(path)
        self._conn: sqlite3.Connection | None = None
        self._disabled: str | None = None
        self._ids: dict[tuple[str, object], int] = {}

    # -- connection ------------------------------------------------------

    @property
    def disabled_reason(self) -> str | None:
        return self._disabled

    def _label(self) -> str:
        name = self._path.name
        return name[: -len(STORE_SUFFIX)] if name.endswith(STORE_SUFFIX) else name

    def _disable(self, reason: str) -> None:
        if self._disabled is not None:
            return
        self._disabled = reason
        get_ui().warn(f"[!] Coverage disabled for {self._label()}: {reason}")
        self.close()

    def _connect(self) -> sqlite3.Connection | None:
        if self._conn is not None:
            return self._conn
        if self._disabled is not None:
            return None
        conn = None
        try:
            conn = sqlite3.connect(str(self._path), timeout=30.0)
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, SCHEMA_VERSION):
                conn.close()
                self._disable(f"{self._path.name} has unknown schema version {version}")
                return None
            if is_network_fs(str(self._path.parent)):
                conn.execute("PRAGMA journal_mode=DELETE")
            else:
                conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            # Writes even when nothing else would, so a read-only file is
            # caught here rather than at the end of a long hashcat run.
            conn.execute("PRAGMA user_version = 1")
            conn.commit()
        except (sqlite3.Error, OSError) as exc:
            if conn is not None:
                conn.close()
            self._disable(str(exc))
            return None
        self._conn = conn
        return conn

    def available(self) -> bool:
        """Can this store be used? Connects on first call."""
        return self._connect() is not None

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # -- interning -------------------------------------------------------

    def _intern_target(self, conn: sqlite3.Connection, sha256: str) -> int:
        key = ("target", sha256)
        if key not in self._ids:
            conn.execute("INSERT OR IGNORE INTO targets (sha256) VALUES (?)", (sha256,))
            self._ids[key] = conn.execute(
                "SELECT id FROM targets WHERE sha256 = ?", (sha256,)
            ).fetchone()[0]
        return self._ids[key]

    def _intern_variant(self, conn: sqlite3.Connection, variant: str) -> int:
        key = ("variant", variant)
        if key not in self._ids:
            conn.execute(
                "INSERT OR IGNORE INTO variants (variant) VALUES (?)", (variant,)
            )
            self._ids[key] = conn.execute(
                "SELECT id FROM variants WHERE variant = ?", (variant,)
            ).fetchone()[0]
        return self._ids[key]

    def _existing_target_id(self, conn: sqlite3.Connection, sha256: str) -> int | None:
        row = conn.execute(
            "SELECT id FROM targets WHERE sha256 = ?", (sha256,)
        ).fetchone()
        return row[0] if row else None

    def _existing_variant_id(
        self, conn: sqlite3.Connection, variant: str
    ) -> int | None:
        row = conn.execute(
            "SELECT id FROM variants WHERE variant = ?", (variant,)
        ).fetchone()
        return row[0] if row else None

    def wordlist_id(self, path: str) -> int | None:
        """Identity of a wordlist from one ``stat()``. The file is never opened.

        ``None`` -- which makes the plan inert -- for a path that cannot be
        stat'd, is not a regular file, or when the store is unavailable. A
        directory is refused deliberately: it stats fine, but its mtime does
        not change when a file inside it is edited.
        """
        try:
            real = os.path.realpath(path)
            st = os.stat(real)
        except OSError:
            return None
        if not stat_module.S_ISREG(st.st_mode):
            return None
        conn = self._connect()
        if conn is None:
            return None
        stamp = (real, st.st_size, st.st_mtime_ns)
        key = ("wordlist", stamp)
        if key in self._ids:
            return self._ids[key]
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO wordlists (realpath, size, mtime_ns) "
                    "VALUES (?, ?, ?)",
                    stamp,
                )
                row = conn.execute(
                    "SELECT id FROM wordlists "
                    "WHERE realpath = ? AND size = ? AND mtime_ns = ?",
                    stamp,
                ).fetchone()
        except sqlite3.Error as exc:
            self._disable(str(exc))
            return None
        self._ids[key] = row[0]
        return row[0]

    # -- coverage --------------------------------------------------------

    def covered(
        self,
        target: str,
        wl_id: int,
        variant: str,
        kind: str,
        hashes: Sequence[int],
    ) -> set[int]:
        """The subset of ``hashes`` already covered in this exact scope.

        Read-only: an unknown target or variant covers nothing and creates no
        row. Any failure answers "nothing covered" -- the run proceeds in full.
        """
        if not hashes:
            return set()
        conn = self._connect()
        if conn is None:
            return set()
        try:
            target_id = self._existing_target_id(conn, target)
            variant_id = self._existing_variant_id(conn, variant)
            if target_id is None or variant_id is None:
                return set()
            scope = (target_id, wl_id, variant_id, KINDS[kind])
            try:
                rows = conn.execute(
                    _COVERED_IN_JSON, (*scope, json.dumps(list(hashes)))
                ).fetchall()
            except (sqlite3.Error, OverflowError):
                # No JSON1, or a payload over the C binding's INT_MAX limit
                # (OverflowError is not a sqlite3.Error subclass).
                rows = self._covered_via_probe_table(conn, scope, hashes)
        except sqlite3.Error as exc:
            self._disable(str(exc))
            return set()
        return {row[0] for row in rows}

    def _covered_via_probe_table(
        self,
        conn: sqlite3.Connection,
        scope: tuple[int, int, int, int],
        hashes: Sequence[int],
    ) -> list[tuple[int]]:
        conn.execute(
            "CREATE TEMP TABLE IF NOT EXISTS coverage_probe "
            "(h INTEGER PRIMARY KEY) WITHOUT ROWID"
        )
        conn.execute("DELETE FROM coverage_probe")
        conn.executemany(
            "INSERT OR IGNORE INTO coverage_probe (h) VALUES (?)",
            [(h,) for h in hashes],
        )
        return conn.execute(_COVERED_VIA_PROBE, scope).fetchall()

    def record(
        self,
        *,
        target: str,
        kind: str,
        variant: str,
        attack: str,
        wordlist_ids: Sequence[int],
        rows: Iterable[tuple[int, int]],
        detail: str = "",
    ) -> int:
        """Log one completed run and its coverage, atomically.

        ``rows`` are ``(wl_id, entry_h)``. Returns how many were new. A repeat
        adds no rows (``INSERT OR IGNORE``) but still logs the run, because a
        run that added nothing still establishes that this attack has seen
        these wordlists. Any failure rolls the whole run back.
        """
        kind_id = KINDS[kind]
        rows = list(rows)
        conn = self._connect()
        if conn is None:
            return 0
        try:
            with conn:
                target_id = self._intern_target(conn, target)
                variant_id = self._intern_variant(conn, variant)
                run_id = conn.execute(
                    "INSERT INTO runs (target_id, attack, kind, detail, ran_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (target_id, attack, kind_id, detail, _now()),
                ).lastrowid
                conn.executemany(
                    "INSERT OR IGNORE INTO run_wordlists (run_id, wl_id) VALUES (?, ?)",
                    [(run_id, wl_id) for wl_id in wordlist_ids],
                )
                before = conn.total_changes
                conn.executemany(
                    _INSERT_COVERED,
                    [
                        (target_id, wl_id, variant_id, kind_id, entry_h)
                        for wl_id, entry_h in rows
                    ],
                )
                added = conn.total_changes - before
                conn.execute(
                    "UPDATE runs SET new_entries = ? WHERE id = ?", (added, run_id)
                )
        except sqlite3.Error as exc:
            # The interned ids may have been rolled back with the run.
            self._ids.clear()
            self._disable(f"could not record coverage: {exc}")
            return 0
        return added

    def log_run(
        self, target: str, attack: str, kind: str = "history", detail: str = ""
    ) -> None:
        """Log a run that covers nothing filterable (a dynamic generator)."""
        self.record(
            target=target,
            kind=kind,
            variant="",
            attack=attack,
            wordlist_ids=(),
            rows=(),
            detail=detail,
        )

    def has_prior_run(
        self,
        target: str,
        attack: str,
        wordlist_ids: Sequence[int],
        kind: str = "",
    ) -> bool:
        """Has ``attack`` run against ``target`` with any of these wordlists?

        Same semantics as the store this replaced: "any", not "all"; ``kind``
        narrows to one coverage dimension; with no wordlists, falls back to
        whether the attack ran against the target at all. Never writes.
        """
        conn = self._connect()
        if conn is None:
            return False
        try:
            target_id = self._existing_target_id(conn, target)
            if target_id is None:
                return False
            if not wordlist_ids:
                if kind:
                    row = conn.execute(
                        _PRIOR_RUN_KIND, (target_id, attack, KINDS[kind])
                    ).fetchone()
                else:
                    row = conn.execute(_PRIOR_RUN, (target_id, attack)).fetchone()
            elif kind:
                row = conn.execute(
                    _PRIOR_RUN_WORDLISTS_KIND,
                    (target_id, attack, KINDS[kind], json.dumps(list(wordlist_ids))),
                ).fetchone()
            else:
                row = conn.execute(
                    _PRIOR_RUN_WORDLISTS,
                    (target_id, attack, json.dumps(list(wordlist_ids))),
                ).fetchone()
        except sqlite3.Error:
            # No JSON1 answers "no prior run": one absent prompt, never a skip.
            return False
        return row is not None

    # -- history ---------------------------------------------------------

    def summary(self, target: str) -> dict:
        """Totals for one target, plus ``(attack, entries, runs)`` per attack."""
        empty = {"entries": 0, "runs": 0, "by_attack": [], "last_run": None}
        conn = self._connect()
        if conn is None:
            return empty
        try:
            target_id = self._existing_target_id(conn, target)
            if target_id is None:
                return empty
            entries = conn.execute(
                "SELECT COUNT(*) FROM covered WHERE target_id = ?", (target_id,)
            ).fetchone()[0]
            runs, last_run = conn.execute(
                "SELECT COUNT(*), MAX(ran_at) FROM runs WHERE target_id = ?",
                (target_id,),
            ).fetchone()
            by_attack = conn.execute(
                "SELECT attack, SUM(new_entries), COUNT(*) FROM runs "
                "WHERE target_id = ? GROUP BY attack ORDER BY attack",
                (target_id,),
            ).fetchall()
        except sqlite3.Error:
            return empty
        return {
            "entries": entries,
            "runs": runs,
            "by_attack": [(row[0], row[1], row[2]) for row in by_attack],
            "last_run": last_run,
        }

    def history(self, target: str) -> list[tuple[str, str, str]]:
        """``(attack, detail, ran_at)`` for a target, oldest first."""
        conn = self._connect()
        if conn is None:
            return []
        try:
            target_id = self._existing_target_id(conn, target)
            if target_id is None:
                return []
            return [
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT attack, detail, ran_at FROM runs "
                    "WHERE target_id = ? ORDER BY id",
                    (target_id,),
                ).fetchall()
            ]
        except sqlite3.Error:
            return []

    def forget_target(self, target: str) -> int:
        """Drop one target's coverage and history. Returns covered rows deleted."""
        conn = self._connect()
        if conn is None:
            return 0
        try:
            target_id = self._existing_target_id(conn, target)
            if target_id is None:
                return 0
            with conn:
                deleted = conn.execute(
                    "DELETE FROM covered WHERE target_id = ?", (target_id,)
                ).rowcount
                conn.execute(
                    "DELETE FROM run_wordlists WHERE run_id IN "
                    "(SELECT id FROM runs WHERE target_id = ?)",
                    (target_id,),
                )
                conn.execute("DELETE FROM runs WHERE target_id = ?", (target_id,))
        except sqlite3.Error as exc:
            self._disable(str(exc))
            return 0
        return max(deleted, 0)


# --- legacy store ------------------------------------------------------------

LEGACY_STORE_NAME = "attack_coverage.sqlite3"


def _human_size(size: int) -> str:
    for unit, scale in (("GB", 1024**3), ("MB", 1024**2), ("KB", 1024)):
        if size >= scale:
            return f"{size / scale:.1f} {unit}"
    return f"{size} bytes"


def remove_legacy_store(home: str | None = None) -> None:
    """Delete the central store that predates per-hash-file coverage.

    Its content-hashed keys cannot be converted without the rule files and
    variants it never recorded, so it is removed rather than migrated. Runs at
    every startup and costs one ``stat()`` once the file is gone. Never raises:
    a failure warns and startup continues.
    """
    base = Path(home if home is not None else os.path.expanduser("~"))
    base = base / ".hate_crack" / "coverage"
    legacy = base / LEGACY_STORE_NAME
    try:
        legacy.stat()
    except (FileNotFoundError, NotADirectoryError):
        return
    except OSError as exc:
        get_ui().warn(f"[!] Could not remove the legacy coverage store {legacy}: {exc}")
        return
    # The main db goes LAST: if anything fails part-way it is still there, so
    # the next start retries instead of orphaning the -wal/-shm siblings.
    files = [
        base / (LEGACY_STORE_NAME + "-wal"),
        base / (LEGACY_STORE_NAME + "-shm"),
        legacy,
    ]
    size = 0
    for path in files:
        try:
            size += path.stat().st_size
        except OSError:
            pass
    for path in files:
        try:
            path.unlink(missing_ok=True)
        except OSError as exc:
            get_ui().warn(
                f"[!] Could not remove the legacy coverage store {legacy}: {exc}"
            )
            return
    try:
        base.rmdir()
    except OSError:
        pass  # not empty: leave whatever else is in there alone
    get_ui().say(
        f"[*] Removed the legacy coverage store ({_human_size(size)}); "
        "coverage now lives beside each hash file."
    )
