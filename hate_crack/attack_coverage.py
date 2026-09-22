"""Per-target record of which rule lines, mask lines and wordlists were tried.

Across a long engagement the same hash file is attacked in many sessions with a
rotating set of wordlists, rule files and mask lists, and there is otherwise no
way to know whether a given rule or mask has already been run against it. This
module is the store that answers that question, plus the planner that turns an
answer into a skip-or-filter decision.

Three identity decisions carry the design:

- **The target is content-addressed** (sha256 of the hash file), so coverage
  survives the file being renamed or moved between sessions. hate_crack does
  not use hashcat's ``--left``, so the hash file's content is stable for the
  life of an engagement.
- **Rules and masks are tracked per entry, not per file.** The same rule line
  routinely appears in more than one rule file, so a file-level record would
  fail to recognise that a later custom file re-runs ground ``best64.rule``
  already covered.
- **Wordlists are tracked per file**, because per-word tracking is not viable
  at wordlist scale. The fingerprint is a content sha256 memoized on
  ``(size, mtime)``, so a multi-gigabyte corpus is hashed once rather than on
  every attack.

A key combines all of those dimensions: a rule counts as covered only for the
specific wordlist it ran against, because ``best64.rule`` over one corpus tries
entirely different candidates than the same rules over another.

**Why SQLite rather than a flat key file** (the shape
``hate_crack.hashview_cache`` uses): that cache is bounded by the size of a
hash list, in the thousands. This one is bounded by rules times wordlists.
``d3ad0ne.rule`` and ``T0XlC.rule`` together are ~38k rules, and
``hcatDictionary`` runs the pair once per wordlist -- so a single Dictionary
attack over five wordlists produces ~191k keys. An append-only file would grow
by that much on every repeat run even when coverage did not change, and
membership testing would mean loading the whole thing into a set before every
attack. A primary key gives deduplication for free, membership becomes a query
over just the entries this run cares about, and there is somewhere to put the
run history the issue asks for. ``sqlite3`` is in the standard library, so none
of this costs a dependency.
"""

import array
import hashlib
import json
import os
import sqlite3
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence, cast

# Import HashcatRosetta for mask canonicalization. Like hate_crack.llm, this
# module needs its own path setup rather than relying on main.py's: main.py
# imports attack_coverage (~line 86) *before* its own sys.path insertion
# (~line 99), so a bare `import hashcat_rosetta` here would always fail. See
# hate_crack.llm's identical guard for why these are kept separate per module.
_ROSETTA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "HashcatRosetta")
)
# Holds the ImportError when HashcatRosetta could not be imported, else None.
ROSETTA_MASK_IMPORT_ERROR = None
try:
    if _ROSETTA_DIR not in sys.path:
        sys.path.insert(0, _ROSETTA_DIR)
    from hashcat_rosetta.mask import expand_custom_charsets as _rosetta_expand_charsets
    from hashcat_rosetta.mask import parse_hcmask_line as _rosetta_parse_hcmask_line
except ImportError as _rosetta_mask_import_error:
    ROSETTA_MASK_IMPORT_ERROR = _rosetta_mask_import_error
    _rosetta_expand_charsets = None
    _rosetta_parse_hcmask_line = None

COVERAGE_DIRNAME = "coverage"
DB_FILENAME = "attack_coverage.sqlite3"

_READ_CHUNK = 1024 * 1024

# Above this, say so before spending minutes reading a corpus.
_LARGE_FILE_NOTICE_BYTES = 1024 * 1024 * 1024

# Membership test for an arbitrarily large key set, as one static statement
# with a single bound parameter. json_each sidesteps SQLite's 999-parameter
# limit without interpolating anything into the SQL.
_COVERED_IN_JSON = (
    "SELECT key FROM covered WHERE key IN (SELECT value FROM json_each(?))"
)

# "Has this attack run against this target with any of these wordlists?", as
# one static statement. See CoverageStore.has_prior_run.
_PRIOR_RUN_WITH_WORDLIST = (
    "SELECT 1 FROM runs "
    "JOIN run_wordlists ON run_wordlists.run_id = runs.id "
    "WHERE runs.target = ? AND runs.attack = ? "
    "AND run_wordlists.wordlist IN (SELECT value FROM json_each(?)) LIMIT 1"
)

# The same question narrowed to one coverage dimension. Separate constants
# rather than a conditional fragment so both stay static SQL.
_PRIOR_RUN_WITH_WORDLIST_AND_KIND = (
    "SELECT 1 FROM runs "
    "JOIN run_wordlists ON run_wordlists.run_id = runs.id "
    "WHERE runs.target = ? AND runs.attack = ? AND runs.kind = ? "
    "AND run_wordlists.wordlist IN (SELECT value FROM json_each(?)) LIMIT 1"
)

# Schema notes, all measured at the realistic scale of ~191k keys (the
# d3ad0ne+T0XlC pair over five wordlists, which is one Dictionary attack):
#
# - `covered` is normalized down to (key, run_id) rather than carrying the
#   target/attack/timestamp on every row. Denormalized it cost 39.6 MB for one
#   run; normalized it is 27.5 MB, because "Dictionary" and a timestamp were
#   being stored 191,000 times instead of once.
# - `covered` is WITHOUT ROWID *because* it is now narrow. A wide WITHOUT ROWID
#   table is a pessimization -- it puts the whole row in the key B-tree and
#   measured slower to insert with no size win. Narrow, it earns its keep.
# - Lookup speed was never the deciding factor: a 38k-key membership test runs
#   in ~57 ms, and every schema variant tried landed within 10 ms of that,
#   because the primary key index serves them all. What the primary key really
#   buys is INSERT OR IGNORE deduplication, which is why the store stays at
#   27.5 MB after ten identical runs where an append-only file reached 124 MB.
_SCHEMA = """
-- One row per hashcat invocation. This is also the run history: a dynamic
-- candidate generator (PRINCE, PCFG, OMEN, Markov, LLM) has no fixed set to
-- diff, so it is never filtered -- it just lands here with no linked keys,
-- which is what lets an operator answer "did I already run PRINCE on this?".
CREATE TABLE IF NOT EXISTS runs (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    target  TEXT NOT NULL,
    kind    TEXT NOT NULL DEFAULT '',
    attack  TEXT NOT NULL DEFAULT '',
    detail  TEXT NOT NULL DEFAULT '',
    ran_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS runs_target ON runs (target);

CREATE TABLE IF NOT EXISTS covered (
    key    TEXT PRIMARY KEY,
    run_id INTEGER NOT NULL REFERENCES runs (id)
) WITHOUT ROWID;

-- Justified by forget_target(), which otherwise full-scans every engagement's
-- keys. It is the only secondary index here: each one is write amplification
-- on a bulk insert of ~191k rows.
CREATE INDEX IF NOT EXISTS covered_run ON covered (run_id);

-- Which wordlists a run declared, by fingerprint. "Declared", not "enumerated":
-- a wordlist-kind plan links every wordlist in the spec, including one that
-- filtering then dropped from the command. That is deliberate -- a dropped
-- wordlist was dropped for being covered already, so it has a row regardless --
-- but it means a row here is not proof that this particular invocation read
-- that file. Nothing keys coverage off these rows; only has_prior_run reads
-- them, and only to decide whether to ask a question.
--
-- This exists so that "has
-- this attack run against this target with this corpus before?" can be
-- answered without reading a single rule file -- the question the up-front
-- batch prompt asks, where diffing a YOLO-sized batch of rule files first is
-- exactly the slow silent wait it was written to avoid. It cannot be answered
-- from `covered`, whose keys hash the fingerprint in beyond recovery.
--
-- CREATE TABLE IF NOT EXISTS is the whole migration story for an engagement
-- whose store predates this table: it appears on the next connect, empty, and
-- an empty answer is "no prior run", which is the safe direction.
CREATE TABLE IF NOT EXISTS run_wordlists (
    run_id   INTEGER NOT NULL REFERENCES runs (id),
    wordlist TEXT NOT NULL,
    PRIMARY KEY (run_id, wordlist)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS run_wordlists_fp ON run_wordlists (wordlist);

CREATE TABLE IF NOT EXISTS wordlist_fingerprints (
    path     TEXT PRIMARY KEY,
    size     INTEGER NOT NULL,
    mtime_ns INTEGER NOT NULL,
    sha256   TEXT NOT NULL
) WITHOUT ROWID;

-- Dictionary tables. Each interns one dimension of what used to be hashed
-- into entry_key's opaque digest, so the target-independent parts survive
-- the engagement boundary and can be computed once ever.
--
-- `entry` is BLOB, not TEXT, and this is load-bearing. read_entries decodes
-- with surrogateescape because rule files here are not all UTF-8 (rulegen.py
-- writes latin-1). When a str with a lone surrogate is bound to the database,
-- Python's sqlite3 raises UnicodeEncodeError trying to encode it as UTF-8.
-- The _entry_blob function prevents this by encoding with surrogatepass first,
-- converting the str to bytes before binding. Storing as BLOB keeps the round
-- trip lossless and keeps two rules differing only in undecodable bytes
-- distinct -- the property whose loss once collapsed 154 distinct Spoonman
-- rules into shared keys.
CREATE TABLE IF NOT EXISTS entries (
    id    INTEGER PRIMARY KEY,
    kind  TEXT NOT NULL,
    entry BLOB NOT NULL,
    UNIQUE (kind, entry)
);
CREATE TABLE IF NOT EXISTS targets   (id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS wordlists (id INTEGER PRIMARY KEY, sha256 TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS variants  (id INTEGER PRIMARY KEY, variant TEXT NOT NULL UNIQUE);

-- Parsed-and-interned entry ids per rule or mask file, as a packed int64
-- array.
--
-- Content-addressed, NOT keyed on (path, size, mtime). A stat memo is safe
-- for wordlist_fingerprints but not here. Today the rule file is re-read on
-- every plan, so a stale cache is impossible; caching the parse introduces a
-- staleness window that did not exist, and it fails in the worst direction.
-- A file edited without changing size or mtime -- cp -p, rsync -t, a tar
-- extraction, a same-nanosecond rewrite -- would yield a manifest missing
-- the new lines, and those lines would be dropped from the filtered file
-- handed to hashcat and never run. rulegen.py writes rule files here, so
-- this is a real class of file, not a hypothetical.
--
-- A manifest hit skips intern_entries -- the per-line hashing, the Rosetta
-- mask parse, and every dictionary round trip. The file is still read once
-- to verify it hasn't changed (cheap for large files) and entries are
-- parsed from it. Two bonuses fall out: a moved or copied file reuses its
-- manifest, and one path used as both rule and mask cannot collide.
CREATE TABLE IF NOT EXISTS file_manifests (
    content_sha256 TEXT NOT NULL,
    kind           TEXT NOT NULL,
    entry_ids      BLOB NOT NULL,
    PRIMARY KEY (content_sha256, kind)
) WITHOUT ROWID;

-- The interned replacement for `covered`. Five integers per row.
--
-- Primary key column order is load-bearing: leading with target_id and
-- wl_id turns a probe into a range scan over only this engagement's rows
-- for this corpus, instead of scattered lookups across every hex key in
-- the store. Measured 80.4 MB per million rows with the old hex TEXT key
-- against 11.5 MB all-integer.
--
-- run_id is a non-key column so summary() can keep reporting per-attack
-- entry counts. It keeps the existing first-writer semantics: a repeat adds
-- no row, so run_id names when an entry was FIRST covered. That matches the
-- old INSERT OR IGNORE behaviour rather than being new here. SQLite does not
-- enforce REFERENCES without PRAGMA foreign_keys=ON, which this store does
-- not set; the clause is documentation.
CREATE TABLE IF NOT EXISTS covered_v2 (
    target_id  INTEGER NOT NULL,
    wl_id      INTEGER NOT NULL,
    variant_id INTEGER NOT NULL,
    entry_id   INTEGER NOT NULL,
    run_id     INTEGER NOT NULL REFERENCES runs (id),
    PRIMARY KEY (target_id, wl_id, variant_id, entry_id)
) WITHOUT ROWID;

-- Migration bookkeeping for the transition from `covered` to `covered_v2`.
-- schema_meta is a one-row version marker guarding the one-time sweep below;
-- legacy_targets names every target whose coverage may still live only in
-- the old hex-keyed `covered` table, so covered_ids knows which targets need
-- a dual-read. A target is dropped from legacy_targets once its old rows are
-- converted (a later task), which is why the sweep guard cannot key off
-- emptiness -- emptiness is also the normal post-conversion steady state.
CREATE TABLE IF NOT EXISTS schema_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS legacy_targets (target TEXT PRIMARY KEY) WITHOUT ROWID;

-- Which (target, scope, kind, wordlist, variant) combinations have had their
-- pre-interning coverage carried across, so the old table is consulted once
-- per combination rather than on every run.
--
-- `scope` is not a path: two plan shapes have no single file. It is the
-- manifest content hash where one exists, the opaque _chain_entry string for
-- a chained -r a -r b run, and the literal "wordlist" for a wordlist-kind
-- run. `kind` is in the key because one path can serve as both a rule file
-- and a mask file.
CREATE TABLE IF NOT EXISTS converted (
    target  TEXT NOT NULL,
    scope   TEXT NOT NULL,
    kind    TEXT NOT NULL,
    wl      TEXT NOT NULL,
    variant TEXT NOT NULL,
    PRIMARY KEY (target, scope, kind, wl, variant)
) WITHOUT ROWID;
"""


def _coverage_dir() -> Path:
    """Directory holding the coverage store.

    Honours HATE_CRACK_COVERAGE_DIR for test isolation and ad-hoc scripting.
    Only pytest tests are automatically isolated via the conftest.py fixture;
    ad-hoc scripts and agent commands must set this variable themselves to
    avoid writing to the operator's real multi-gigabyte store.

    An empty or whitespace-only HATE_CRACK_COVERAGE_DIR raises rather than
    falling back to the real store, because an empty value almost always means
    a caller intended isolation and computed the path wrong.

    Mirrors hashview_cache._cache_path()'s ~/.hate_crack construction, with
    its own subdirectory so the store sits beside the potfile and
    hashcat_debug rather than among them.
    """
    override = os.environ.get("HATE_CRACK_COVERAGE_DIR")
    if override is not None:
        if not override.strip():
            raise ValueError(
                "HATE_CRACK_COVERAGE_DIR is set but empty. Refusing to fall "
                "back to the operator's real coverage store -- an empty "
                "override almost always means a caller meant to isolate and "
                "computed the path wrong."
            )
        return Path(override).expanduser()
    return Path(os.path.expanduser("~")) / ".hate_crack" / COVERAGE_DIRNAME


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(_READ_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


# --- store -----------------------------------------------------------------


class CoverageStore:
    """SQLite-backed coverage store.

    Every method swallows :class:`sqlite3.Error` and degrades to "we know
    nothing", because a broken or read-only store must never take an attack
    down with it. Losing a record costs one redundant run later; raising here
    costs the operator their session.
    """

    def __init__(self, path: Path | str | None = None):
        self._path = Path(path) if path is not None else _coverage_dir() / DB_FILENAME
        self._conn: sqlite3.Connection | None = None
        # In-process fingerprint memo, so repeated attacks in one session skip
        # even the database round trip.
        self._fingerprints: dict[str, tuple[int, int, str]] = {}

    # -- connection --------------------------------------------------------

    def _connect(self) -> sqlite3.Connection | None:
        if self._conn is not None:
            return self._conn
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._path), timeout=30.0)
            # WAL plus a busy timeout so two hate_crack instances in the same
            # engagement directory do not lock each other out.
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(_SCHEMA)
            self._sweep_legacy(conn)
            conn.commit()
        except (sqlite3.Error, OSError):
            return None
        self._conn = conn
        return conn

    _SCHEMA_VERSION = "2"

    def _sweep_legacy(self, conn: sqlite3.Connection) -> None:
        """One-time: mark every pre-interning target as needing dual-read.

        Guarded on a schema_meta row, NOT on whether legacy_targets is empty.
        An empty legacy_targets is also the normal steady state once
        `coverage compact` has finished, and keying on emptiness would
        re-sweep forever and resurrect targets that were deliberately
        converted and dropped.

        Unconditional otherwise: it always runs
        `INSERT ... SELECT DISTINCT target FROM runs` rather than first
        checking whether an old `covered` table existed. `_SCHEMA` always
        creates `covered` via `CREATE TABLE IF NOT EXISTS`, so by the time
        this runs the table is present regardless of whether the store was
        fresh or pre-existing -- a presence check cannot tell the two apart.
        What actually makes this a no-op for a fresh store is that a fresh
        store's `runs` table is empty, so the SELECT DISTINCT yields nothing
        to insert.
        """
        try:
            row = conn.execute(
                "SELECT v FROM schema_meta WHERE k = 'version'"
            ).fetchone()
            if row is not None:
                try:
                    already_swept = int(row[0]) >= int(self._SCHEMA_VERSION)
                except (TypeError, ValueError):
                    already_swept = False
                if already_swept:
                    return
            conn.execute(
                "INSERT OR IGNORE INTO legacy_targets (target) "
                "SELECT DISTINCT target FROM runs"
            )
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (k, v) VALUES ('version', ?)",
                (self._SCHEMA_VERSION,),
            )
        except sqlite3.Error:
            pass

    def is_legacy_target(self, target: str) -> bool:
        conn = self._connect()
        if conn is None:
            return False
        try:
            row = conn.execute(
                "SELECT 1 FROM legacy_targets WHERE target = ?", (target,)
            ).fetchone()
        except sqlite3.Error:
            return False
        return row is not None

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass
            self._conn = None

    # -- diagnostics -------------------------------------------------------

    @property
    def path(self) -> Path:
        """Read-only path to the store database file."""
        return self._path

    # -- coverage ----------------------------------------------------------

    def covered(self, keys: Sequence[str]) -> set[str]:
        """Return the subset of ``keys`` already recorded.

        Queried rather than loaded wholesale: a Dictionary attack asks about
        ~191k keys, and only those matter.

        The whole key set goes over as one JSON parameter. The obvious
        alternative -- an ``IN (?,?,?...)`` clause -- would have to be built by
        string interpolation and chunked under SQLite's 999-parameter limit;
        this is a single static statement with one bound value, and measured
        slightly faster besides (57 ms against 65 ms for the chunked form).
        """
        if not keys:
            return set()
        conn = self._connect()
        if conn is None:
            return set()
        payload = json.dumps(list(keys))
        try:
            rows = conn.execute(_COVERED_IN_JSON, (payload,)).fetchall()
        except (sqlite3.Error, OverflowError):
            # OverflowError: CPython's sqlite3 module cannot bind a single
            # parameter longer than INT_MAX bytes, which a big rule file run
            # against many large wordlists can reach -- it is raised at the
            # C binding layer before SQLite itself is involved, so it is not
            # a sqlite3.Error subclass.
            return self._covered_via_temp_table(conn, keys)
        return {row[0] for row in rows}

    def _covered_via_temp_table(
        self, conn: sqlite3.Connection, keys: Sequence[str]
    ) -> set[str]:
        """Fallback for a SQLite built without the JSON1 extension.

        Correct but slower: the planner joins from ``covered``, so this scales
        with the size of the store rather than the size of the probe. Still
        static SQL, which is the point -- the alternative fallback would mean
        interpolating placeholders after all.
        """
        try:
            conn.execute(
                "CREATE TEMP TABLE IF NOT EXISTS coverage_probe "
                "(key TEXT PRIMARY KEY) WITHOUT ROWID"
            )
            conn.execute("DELETE FROM coverage_probe")
            conn.executemany(
                "INSERT OR IGNORE INTO coverage_probe (key) VALUES (?)",
                [(key,) for key in keys],
            )
            rows = conn.execute(
                "SELECT covered.key FROM covered "
                "JOIN coverage_probe ON covered.key = coverage_probe.key"
            ).fetchall()
        except sqlite3.Error:
            return set()
        return {row[0] for row in rows}

    def covered_lookup(self) -> Callable[[Sequence[str]], set[str]]:
        return self.covered

    def covered_ids(
        self,
        target_id: int,
        probes: Sequence[tuple[int, int, int]],
        legacy: "LegacyProbe | None" = None,
    ) -> set[tuple[int, int, int]]:
        """Which (wl_id, variant_id, entry_id) triples are already covered.

        Probes go through a temp table rather than an IN list. The old hex
        path used json_each to dodge SQLite's 999-parameter limit; a temp
        table does the same for composite keys, which json_each cannot
        express, and it lets the planner use covered_v2's primary key.

        ``legacy``, when given, carries the pre-interning hex keys for the
        same probes. It is only consulted for a target the sweep marked as
        legacy -- an ordinary target never touches the old `covered` table.
        """
        if not probes:
            return set()
        conn = self._connect()
        if conn is None:
            return set()
        try:
            with conn:
                conn.execute(
                    "CREATE TEMP TABLE IF NOT EXISTS cov_probe "
                    "(wl_id INTEGER, variant_id INTEGER, entry_id INTEGER, "
                    " PRIMARY KEY (wl_id, variant_id, entry_id)) WITHOUT ROWID"
                )
                conn.execute("DELETE FROM cov_probe")
                conn.executemany(
                    "INSERT OR IGNORE INTO cov_probe (wl_id, variant_id, entry_id) VALUES (?, ?, ?)",
                    probes,
                )
            rows = conn.execute(
                "SELECT c.wl_id, c.variant_id, c.entry_id FROM covered_v2 c "
                "JOIN cov_probe p ON c.wl_id = p.wl_id "
                "AND c.variant_id = p.variant_id AND c.entry_id = p.entry_id "
                "WHERE c.target_id = ?",
                (target_id,),
            ).fetchall()
        except (sqlite3.Error, OverflowError):
            return set()
        found = {(row[0], row[1], row[2]) for row in rows}
        if legacy is not None and self.is_legacy_target(legacy.target):
            found |= self._covered_legacy(legacy, probes)
        return found

    def _covered_legacy(
        self, legacy: "LegacyProbe", probes: Sequence[tuple[int, int, int]]
    ) -> set[tuple[int, int, int]]:
        """Which probes the pre-interning `covered` table already holds."""
        conn = self._connect()
        if conn is None:
            return set()
        wanted = {p: legacy.keys[p] for p in probes if p in legacy.keys}
        if not wanted:
            return set()
        try:
            hits = self.covered(list(wanted.values()))
        except sqlite3.Error:
            return set()
        return {p for p, key in wanted.items() if key in hits}

    def convert_scope(
        self,
        target: str,
        scope: str,
        kind: str,
        wl: str,
        variant: str,
        rows: Sequence[tuple[int, int, int]],
        run_id: int,
        target_id: int,
    ) -> bool:
        """Carry one combination's legacy coverage into covered_v2.

        Rows first, marker last, both in one transaction. The order is
        load-bearing: a crash between them in the reverse order would leave
        the combination flagged converted with its coverage never carried
        over, and the old table would never be consulted for it again.
        Returns True only when both landed.
        """
        conn = self._connect()
        if conn is None:
            return False
        try:
            with conn:
                if rows:
                    conn.executemany(
                        "INSERT OR IGNORE INTO covered_v2 "
                        "(target_id, wl_id, variant_id, entry_id, run_id) "
                        "VALUES (?, ?, ?, ?, ?)",
                        [(target_id, w, v, e, run_id) for (w, v, e) in rows],
                    )
                conn.execute(
                    "INSERT OR IGNORE INTO converted "
                    "(target, scope, kind, wl, variant) VALUES (?, ?, ?, ?, ?)",
                    (target, scope, kind, wl, variant),
                )
        except sqlite3.Error:
            return False
        return True

    def is_converted(
        self, target: str, scope: str, kind: str, wl: str, variant: str
    ) -> bool:
        conn = self._connect()
        if conn is None:
            return False
        try:
            row = conn.execute(
                "SELECT 1 FROM converted WHERE target = ? AND scope = ? "
                "AND kind = ? AND wl = ? AND variant = ?",
                (target, scope, kind, wl, variant),
            ).fetchone()
        except sqlite3.Error:
            return False
        return row is not None

    # -- dictionaries ------------------------------------------------------

    def intern_target(self, sha: str) -> int | None:
        """Intern a target SHA into the targets table, returning its id."""
        conn = self._connect()
        if conn is None:
            return None
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO targets (sha256) VALUES (?)", (sha,)
                )
                row = conn.execute(
                    "SELECT id FROM targets WHERE sha256 = ?", (sha,)
                ).fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def intern_wordlist(self, fingerprint: str) -> int | None:
        """Intern a wordlist fingerprint into the wordlists table, returning its id."""
        conn = self._connect()
        if conn is None:
            return None
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO wordlists (sha256) VALUES (?)",
                    (fingerprint,),
                )
                row = conn.execute(
                    "SELECT id FROM wordlists WHERE sha256 = ?", (fingerprint,)
                ).fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def intern_variant(self, variant: str) -> int | None:
        """Intern a variant string into the variants table, returning its id."""
        conn = self._connect()
        if conn is None:
            return None
        try:
            with conn:
                conn.execute(
                    "INSERT OR IGNORE INTO variants (variant) VALUES (?)", (variant,)
                )
                row = conn.execute(
                    "SELECT id FROM variants WHERE variant = ?", (variant,)
                ).fetchone()
        except sqlite3.Error:
            return None
        return row[0] if row else None

    def intern_entries(self, kind: str, entries: Sequence[str]) -> list[int] | None:
        """Intern many entries at once, preserving input order.

        Mask entries are canonicalized first, matching entry_key's existing
        behaviour exactly, so old and new agree on mask identity and the
        migration changes nothing about which masks are considered the same.
        """
        if not entries:
            return []
        conn = self._connect()
        if conn is None:
            return None
        entries_to_store = [
            canonical_mask_entry(e) if kind == "mask" else e for e in entries
        ]
        blobs = [_entry_blob(e) for e in entries_to_store]
        try:
            with conn:
                conn.executemany(
                    "INSERT OR IGNORE INTO entries (kind, entry) VALUES (?, ?)",
                    [(kind, blob) for blob in blobs],
                )
            with conn:
                conn.execute(
                    "CREATE TEMP TABLE IF NOT EXISTS intern_probe (entry BLOB PRIMARY KEY) WITHOUT ROWID"
                )
                conn.execute("DELETE FROM intern_probe")
                conn.executemany(
                    "INSERT OR IGNORE INTO intern_probe (entry) VALUES (?)",
                    [(blob,) for blob in blobs],
                )
            rows = conn.execute(
                "SELECT entries.entry, entries.id FROM entries "
                "JOIN intern_probe ON entries.entry = intern_probe.entry "
                "WHERE entries.kind = ?",
                (kind,),
            ).fetchall()
        except sqlite3.Error:
            return None
        by_blob = {bytes(row[0]): row[1] for row in rows}
        resolved = [by_blob.get(blob) for blob in blobs]
        if any(value is None for value in resolved):
            return None
        return cast(list[int], resolved)

    def precompute(self, paths: Iterable[tuple[str, str]]) -> tuple[int, int]:
        """Build manifests for (path, kind) pairs ahead of time.

        Manifests build lazily on first use anyway, so this only moves the
        cost off the first attack of an engagement.
        """
        built = failed = 0
        for path, kind in paths:
            if self.file_entry_ids(path, kind) is None:
                failed += 1
            else:
                built += 1
        return built, failed

    def entry_text(self, entry_id: int) -> str | None:
        """Decode one interned entry back to its original text."""
        conn = self._connect()
        if conn is None:
            return None
        try:
            row = conn.execute(
                "SELECT entry FROM entries WHERE id = ?", (entry_id,)
            ).fetchone()
        except sqlite3.Error:
            return None
        return _entry_text(row[0]) if row else None

    # -- file manifests ----------------------------------------------------

    def file_entry_ids(
        self, path: str, kind: str
    ) -> tuple[list[str], list[int]] | None:
        """Entries and their interned ids for one rule or mask file.

        Returns (entries, entry_ids) in file order, or None when identity
        cannot be established. The entries are the literal file content, and
        filters must output exactly what was written. A manifest hit skips
        intern_entries -- the per-line hashing, the Rosetta mask parse, and
        every dictionary round trip. A manifest miss reads the file, interns
        the entries, and caches the ids for future calls.

        The file is read exactly once per call, and the same bytes are used
        to compute the content digest and parse entries. This makes it
        impossible for digest and entries to come from different content.

        The entries are returned alongside the ids so that filtering can write
        them directly without any dictionary lookups. The dictionary holds
        canonical forms for mask entries (with NUL separators), so reading
        entries back out would corrupt the output file.
        """
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
        except OSError:
            return None

        entries = read_entries_from_bytes(raw)
        if not entries:
            return None

        digest = hashlib.sha256(raw).hexdigest()

        conn = self._connect()
        if conn is None:
            return None

        try:
            row = conn.execute(
                "SELECT entry_ids FROM file_manifests "
                "WHERE content_sha256 = ? AND kind = ?",
                (digest, kind),
            ).fetchone()
        except sqlite3.Error:
            row = None

        if row is not None:
            ids = _unpack_ids(row[0])
            if ids is not None and len(ids) == len(entries):
                # Cache hit: return file entries with cached ids.
                # Intern_entries is skipped; this is the expensive part.
                return entries, ids

        ids = self.intern_entries(kind, entries)
        if ids is None:
            return None

        try:
            packed_ids = _pack_ids(ids)
        except (OverflowError, TypeError):
            # Entry ids overflow or corrupt. Do not cache.
            return entries, ids

        try:
            with conn:
                conn.execute(
                    "INSERT OR REPLACE INTO file_manifests "
                    "(content_sha256, kind, entry_ids) VALUES (?, ?, ?)",
                    (digest, kind, packed_ids),
                )
        except sqlite3.Error:
            # A manifest we could not persist is a cache miss next time, not
            # a correctness problem. The ids in hand are still valid.
            pass
        return entries, ids

    def log_run(
        self,
        target: str,
        attack: str = "",
        kind: str = "",
        detail: str = "",
    ) -> int | None:
        """Record that an attack ran. Returns its run id, or None on failure.

        Every invocation gets a row, filterable or not -- that is what makes
        this table the run history as well as the parent of ``covered``.
        """
        conn = self._connect()
        if conn is None:
            return None
        try:
            cursor = conn.execute(
                "INSERT INTO runs (target, kind, attack, detail, ran_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (target, kind, attack, detail, _now()),
            )
            conn.commit()
        except sqlite3.Error:
            return None
        return cursor.lastrowid

    def has_prior_run(
        self,
        target: str,
        attack: str,
        wordlist_fps: Sequence[str],
        kind: str = "",
    ) -> bool:
        """Has ``attack`` already run against ``target`` using any of these
        wordlists?

        "Any", not "all": one overlapping corpus is enough for per-entry
        filtering to have something to skip, which is what the caller is really
        asking about.

        ``kind`` narrows the question to one coverage dimension, and a caller
        that is about to diff a dimension must pass it. Keys are keyed *by*
        kind (see :func:`entry_key`), so a ``"wordlist"``-kind run -- a
        rule-less dictionary pass -- can never cover a single ``"rule"``-kind
        key. Answering the unscoped question let one rule-less Quick Crack make
        every later rules run announce "has run against this hash file before"
        and offer to skip rule lines of which none were covered: a prompt whose
        only possible answer was a no-op. Left empty, the older cross-dimension
        answer is unchanged.

        With no fingerprints -- a mask-only attack, or a caller that cannot
        establish them -- this falls back to the coarser question of whether the
        attack has run against the target at all, because that is the only one
        the store can answer. Callers that *do* have wordlists must pass them:
        the coarse answer is what made a brand-new corpus look like a repeat.

        The fingerprints go over as one JSON parameter, the same static-SQL
        shape :meth:`covered` uses and for the same reason -- an ``IN (?,?,?)``
        clause would have to be built by interpolation and chunked under
        SQLite's 999-parameter limit, and a Weakpass directory really can hold
        hundreds of lists. Unlike :meth:`covered` this one has no JSON1
        fallback: a SQLite built without it answers "no prior run", which costs
        an operator one absent prompt rather than a wrong skip, because the
        per-entry diff in ``plan_run`` still asks about any genuine overlap.
        """
        conn = self._connect()
        if conn is None:
            return False
        try:
            if not wordlist_fps:
                if kind:
                    row = conn.execute(
                        "SELECT 1 FROM runs WHERE target = ? AND attack = ? "
                        "AND kind = ? LIMIT 1",
                        (target, attack, kind),
                    ).fetchone()
                else:
                    row = conn.execute(
                        "SELECT 1 FROM runs WHERE target = ? AND attack = ? LIMIT 1",
                        (target, attack),
                    ).fetchone()
            elif kind:
                row = conn.execute(
                    _PRIOR_RUN_WITH_WORDLIST_AND_KIND,
                    (target, attack, kind, json.dumps(list(wordlist_fps))),
                ).fetchone()
            else:
                row = conn.execute(
                    _PRIOR_RUN_WITH_WORDLIST,
                    (target, attack, json.dumps(list(wordlist_fps))),
                ).fetchone()
        except sqlite3.Error:
            return False
        return row is not None

    def record(
        self,
        keys: Iterable[str],
        target: str = "",
        kind: str = "",
        attack: str = "",
        detail: str = "",
        wordlist_fps: Sequence[str] = (),
    ) -> int:
        """Log a run and link its coverage. Returns newly-inserted key count.

        ``INSERT OR IGNORE`` means a repeat adds no keys and leaves the original
        run's link in place, so a key records when it was *first* covered and
        the store does not grow on repeats.

        ``wordlist_fps`` are linked to the run so :meth:`has_prior_run` can
        scope its answer to a corpus. They are recorded even when ``keys`` is
        empty, because a run that added no new keys still establishes that this
        attack has seen this corpus.
        """
        keys = list(keys)
        conn = self._connect()
        if conn is None:
            return 0
        run_id = self.log_run(target, attack=attack, kind=kind, detail=detail)
        if run_id is None:
            return 0
        if wordlist_fps:
            try:
                conn.executemany(
                    "INSERT OR IGNORE INTO run_wordlists (run_id, wordlist) "
                    "VALUES (?, ?)",
                    [(run_id, fingerprint) for fingerprint in wordlist_fps],
                )
                conn.commit()
            except sqlite3.Error:
                pass
        if not keys:
            return 0
        try:
            cursor = conn.executemany(
                "INSERT OR IGNORE INTO covered (key, run_id) VALUES (?, ?)",
                [(key, run_id) for key in keys],
            )
            conn.commit()
        except sqlite3.Error:
            return 0
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def record_ids(
        self,
        target_id: int,
        rows: Sequence[tuple[int, int, int]],
        run_id: int,
    ) -> int:
        """Link interned coverage to a run. Returns newly-inserted count."""
        if not rows:
            return 0
        conn = self._connect()
        if conn is None:
            return 0
        try:
            prepared = [(target_id, w, v, e, run_id) for (w, v, e) in rows]
        except (ValueError, TypeError):
            # A malformed row is a caller-contract violation, not an
            # environmental failure. Return 0 rather than raising: this
            # class's whole premise is that "a broken store must never take
            # an attack down with it", and recording nothing is the safe
            # direction -- it can only cost a redundant run later, never mark
            # an entry covered that was not run.
            return 0
        try:
            with conn:
                cursor = conn.executemany(
                    "INSERT OR IGNORE INTO covered_v2 "
                    "(target_id, wl_id, variant_id, entry_id, run_id) "
                    "VALUES (?, ?, ?, ?, ?)",
                    prepared,
                )
        except (sqlite3.Error, OverflowError):
            return 0
        return cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0

    def record_plan(self, plan: "RunPlan", attack: str = "", detail: str = "") -> int:
        """Log a run for `plan` and link its interned coverage."""
        conn = self._connect()
        if conn is None or plan.target_id is None:
            return 0
        run_id = self.log_run(plan.target, attack=attack, kind=plan.kind, detail=detail)
        if run_id is None:
            return 0
        if plan.wordlist_fps:
            try:
                with conn:
                    conn.executemany(
                        "INSERT OR IGNORE INTO run_wordlists (run_id, wordlist) "
                        "VALUES (?, ?)",
                        [(run_id, fp) for fp in plan.wordlist_fps],
                    )
            except sqlite3.Error:
                pass
        return self.record_ids(plan.target_id, plan.record_rows, run_id)

    def forget_target(self, target: str) -> int:
        """Drop all coverage and history for one target, so it can be re-attacked.

        The ``covered_run`` index is what keeps this from full-scanning every
        engagement's keys.
        """
        conn = self._connect()
        if conn is None:
            return 0
        try:
            with conn:
                cursor = conn.execute(
                    "DELETE FROM covered WHERE run_id IN "
                    "(SELECT id FROM runs WHERE target = ?)",
                    (target,),
                )
                removed = (
                    cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
                )
                target_row = conn.execute(
                    "SELECT id FROM targets WHERE sha256 = ?", (target,)
                ).fetchone()
                if target_row is not None:
                    cv2_cursor = conn.execute(
                        "DELETE FROM covered_v2 WHERE target_id = ?", (target_row[0],)
                    )
                    if cv2_cursor.rowcount and cv2_cursor.rowcount > 0:
                        removed += cv2_cursor.rowcount
                conn.execute("DELETE FROM converted WHERE target = ?", (target,))
                conn.execute("DELETE FROM legacy_targets WHERE target = ?", (target,))
                conn.execute(
                    "DELETE FROM run_wordlists WHERE run_id IN "
                    "(SELECT id FROM runs WHERE target = ?)",
                    (target,),
                )
                conn.execute("DELETE FROM runs WHERE target = ?", (target,))
        except sqlite3.Error:
            return 0
        return removed

    # -- compaction ----------------------------------------------------------

    def compact(self, sources: Iterable[tuple[str, str]]) -> dict:
        """Eagerly convert every legacy target's coverage, then reclaim space.

        Sweeps every (target, source, wordlist, variant) combination it can
        enumerate -- ``sources`` (rule/mask files) crossed with every
        wordlist fingerprint already seen for that target (``run_wordlists``)
        and every recorded variant -- plus a separate wordlist-kind sweep
        over ``run_wordlists`` directly, since that shape has no source file
        (a rule-less dictionary attack's old key is
        ``entry_key(target, "wordlist", "", fingerprint, variant)``).

        A target is removed from ``legacy_targets`` once every one of its old
        ``covered`` keys has been reconstructed and accounted for -- this is
        the only place anything empties ``legacy_targets``, since
        ``_sweep_legacy`` only ever adds to it and ``convert_scope`` never
        touches it. That makes this method the only path by which the
        eventual drop becomes reachable at all.

        Only drops the old ``covered`` table (and its ``covered_run`` index,
        and VACUUMs) when the sweep leaves nothing unconvertible anywhere,
        ``legacy_targets`` ends up empty, AND the table still exists to be
        dropped. That last condition is what makes a second call against an
        already-compacted store report ``dropped_old_table: False`` instead
        of "dropping" an already-gone table on every call forever -- without
        it, an idempotency check could never distinguish "just did the real
        work" from "there was never anything to do this time".

        Never drops while anything remains; reports what was left behind
        rather than dropping silently. Every failure to read degrades to
        counting the target's coverage as unconvertible -- conservative,
        never a false claim of success.
        """
        conn = self._connect()
        empty = {"converted": 0, "unconvertible": 0, "dropped_old_table": False}
        if conn is None:
            return empty

        try:
            legacy = [
                row[0]
                for row in conn.execute("SELECT target FROM legacy_targets").fetchall()
            ]
        except sqlite3.Error:
            return empty

        sources = list(sources)
        converted_total = 0
        unconvertible_total = 0

        for target in legacy:
            target_id_of = self.intern_target(target)
            try:
                old_keys = {
                    row[0]
                    for row in conn.execute(
                        "SELECT key FROM covered WHERE run_id IN "
                        "(SELECT id FROM runs WHERE target = ?)",
                        (target,),
                    ).fetchall()
                }
                run_wl_fps = [
                    row[0]
                    for row in conn.execute(
                        "SELECT DISTINCT wordlist FROM run_wordlists WHERE run_id IN "
                        "(SELECT id FROM runs WHERE target = ?)",
                        (target,),
                    ).fetchall()
                ]
                variant_rows = [
                    row[0]
                    for row in conn.execute("SELECT variant FROM variants").fetchall()
                ]
            except sqlite3.Error:
                # Cannot even read this target's old coverage; be
                # conservative rather than guess it is fine.
                unconvertible_total += 1
                continue
            if target_id_of is None:
                unconvertible_total += len(old_keys)
                continue
            if "" not in variant_rows:
                variant_rows.append("")

            claimed: set[str] = set()

            # File-backed sources crossed with every wordlist and variant
            # seen for this target.
            for path, kind in sources:
                loaded = self.file_entry_ids(path, kind)
                if loaded is None:
                    continue
                entries, entry_ids = loaded
                try:
                    scope = _sha256_file(path)
                except OSError:
                    continue
                for variant in variant_rows:
                    variant_id = self.intern_variant(variant)
                    if variant_id is None:
                        continue
                    # "" is always tried alongside every wordlist fingerprint
                    # actually seen for this target -- not only as a fallback
                    # for an empty list. A mask (or, in principle, a rule)
                    # scope can legitimately have no wordlist of its own (a
                    # pure `-a 3` mask attack) even when this same target has
                    # *other* runs that did record real wordlist
                    # fingerprints in run_wordlists; omitting "" whenever any
                    # fingerprint exists would silently miss that
                    # no-wordlist legacy key. See plan_run's mask branch,
                    # where wordlist_fps is empty for a pure mask attack and
                    # _convert_legacy_if_needed's slots fallback becomes
                    # exactly [("", ...)].
                    for fp in dict.fromkeys([*run_wl_fps, ""]):
                        # A wordlist-less scope (a pure `-a 3` mask attack,
                        # or in principle a wordlist-less rule scope) is keyed
                        # in covered_v2/plan_run with the sentinel wl_id 0 --
                        # never a real interned row. intern_wordlist("")
                        # returns the *real* id of the interned "" row, which
                        # is a different, unreachable coordinate: nothing in
                        # _plan_entries or _convert_legacy_if_needed ever
                        # probes wl_id == intern_wordlist(""), only wl_id ==
                        # 0 for this shape. Writing there would "convert"
                        # successfully and then, once the old table is
                        # dropped, be permanently unreadable. See plan_run's
                        # mask branch: `wl_ids=[]` for a pure mask attack, and
                        # `_convert_legacy_if_needed`'s own fallback is
                        # `wl_ids[0] if wl_ids else 0` -- 0, not
                        # intern_wordlist(""). The wordlist-*kind* sweep below
                        # is a genuinely different shape and correctly uses
                        # intern_wordlist("") -- do not unify the two.
                        wl_id = 0 if fp == "" else self.intern_wordlist(fp)
                        if wl_id is None:
                            continue
                        reconstructed = {
                            entry_key(target, kind, fp, entry, variant): (
                                wl_id,
                                variant_id,
                                eid,
                            )
                            for entry, eid in zip(entries, entry_ids)
                        }
                        if self.is_converted(target, scope, kind, fp, variant):
                            # Already carried over by an earlier compact --
                            # safe to claim now, since that earlier call's
                            # convert_scope already succeeded.
                            claimed |= reconstructed.keys()
                            continue
                        hit_keys = reconstructed.keys() & old_keys
                        if not hit_keys:
                            # Nothing here to carry over, but still mark this
                            # combination converted so future compacts skip
                            # the same empty query.
                            run_id = self.log_run(
                                target, kind=kind, detail="legacy-conversion"
                            )
                            if run_id is not None and self.convert_scope(
                                target,
                                scope,
                                kind,
                                fp,
                                variant,
                                [],
                                run_id,
                                target_id_of,
                            ):
                                converted_total += 1
                                # Only claim once convert_scope has actually
                                # committed -- claiming first and writing
                                # second would mark a key "accounted for"
                                # before it is safely represented anywhere,
                                # so any failure between the two would lose it
                                # silently rather than count as unconvertible.
                                claimed |= reconstructed.keys()
                            continue
                        # hit_keys was already derived from old_keys, a
                        # direct successful read -- no need to re-verify it
                        # through covered_ids (which can itself fail and
                        # return set(), degrading silently by its own
                        # documented contract). Write what the old table
                        # itself already proved is covered.
                        probes_by_key = {
                            k: v for k, v in reconstructed.items() if k in hit_keys
                        }
                        run_id = self.log_run(
                            target, kind=kind, detail="legacy-conversion"
                        )
                        if run_id is not None and self.convert_scope(
                            target,
                            scope,
                            kind,
                            fp,
                            variant,
                            list(probes_by_key.values()),
                            run_id,
                            target_id_of,
                        ):
                            converted_total += 1
                            claimed |= reconstructed.keys()

            # Wordlist-kind reconstruction: no file, driven by run_wordlists
            # directly. Legacy key formula matches the wordlist-kind branch
            # of plan_run/_convert_legacy_if_needed exactly:
            # entry_key(target, "wordlist", "", fingerprint, variant), with
            # scope being the wordlist's own fingerprint (not a shared
            # literal "wordlist" scope -- see _convert_legacy_if_needed's
            # call site in plan_run for why that used to collapse every
            # wordlist-kind plan for a target onto one marker).
            empty_wl = self.intern_wordlist("")
            for variant in variant_rows:
                variant_id = self.intern_variant(variant)
                if variant_id is None or empty_wl is None:
                    continue
                for fp in run_wl_fps:
                    key = entry_key(target, "wordlist", "", fp, variant)
                    if self.is_converted(target, fp, "wordlist", "", variant):
                        # Already carried over by an earlier compact.
                        claimed.add(key)
                        continue
                    if key not in old_keys:
                        run_id = self.log_run(
                            target, kind="wordlist", detail="legacy-conversion"
                        )
                        if run_id is not None and self.convert_scope(
                            target,
                            fp,
                            "wordlist",
                            "",
                            variant,
                            [],
                            run_id,
                            target_id_of,
                        ):
                            converted_total += 1
                            claimed.add(key)
                        continue
                    ids = self.intern_entries("wordlist", [fp])
                    if not ids:
                        # Leave unclaimed: costs a blocked drop and a retry,
                        # never a silently lost key.
                        continue
                    probe = (empty_wl, variant_id, ids[0])
                    # probe is already known covered -- it came from `key`
                    # being present in old_keys, a direct successful read.
                    # No need to re-verify through covered_ids, which can
                    # itself fail and silently return set() by its own
                    # documented contract.
                    run_id = self.log_run(
                        target, kind="wordlist", detail="legacy-conversion"
                    )
                    if run_id is not None and self.convert_scope(
                        target,
                        fp,
                        "wordlist",
                        "",
                        variant,
                        [probe],
                        run_id,
                        target_id_of,
                    ):
                        converted_total += 1
                        claimed.add(key)

            unclaimed = old_keys - claimed
            unconvertible_total += len(unclaimed)
            if not unclaimed:
                try:
                    with conn:
                        conn.execute(
                            "DELETE FROM legacy_targets WHERE target = ?", (target,)
                        )
                except sqlite3.Error:
                    pass

        try:
            remaining_legacy = conn.execute(
                "SELECT COUNT(*) FROM legacy_targets"
            ).fetchone()[0]
        except sqlite3.Error:
            remaining_legacy = 1  # cannot confirm empty, so do not drop

        dropped = False
        if unconvertible_total == 0 and remaining_legacy == 0:
            try:
                table_exists = (
                    conn.execute(
                        "SELECT 1 FROM sqlite_master WHERE type = 'table' "
                        "AND name = 'covered'"
                    ).fetchone()
                    is not None
                )
            except sqlite3.Error:
                table_exists = False
            if table_exists:
                try:
                    with conn:
                        conn.execute("DROP TABLE IF EXISTS covered")
                        conn.execute("DROP INDEX IF EXISTS covered_run")
                    # The drop itself is the meaningful, destructive part;
                    # VACUUM is a disk-reclaiming follow-on. Mark dropped
                    # True as soon as the drop's own transaction commits, so
                    # a VACUUM failure (which cannot run inside a
                    # transaction, hence separately below) is never reported
                    # as "nothing happened" when the table is, in fact,
                    # already gone.
                    dropped = True
                except sqlite3.Error:
                    dropped = False
                if dropped:
                    try:
                        conn.execute("VACUUM")
                    except sqlite3.Error:
                        pass

        return {
            "converted": converted_total,
            "unconvertible": unconvertible_total,
            "dropped_old_table": dropped,
        }

    # -- history -----------------------------------------------------------

    def summary(self, target: str) -> dict:
        """Counts for one target: total entries, runs, and a per-attack split.

        ``by_attack`` rows are ``(attack, entries, runs)``. An attack with zero
        entries but a nonzero run count is one that was logged rather than
        filtered -- a dynamic generator, or a repeat that added no new keys.

        During the migration window, a converted target's ``entries`` count
        may temporarily include the same coverage twice -- once in the legacy
        table, once carried over into the interned one -- until
        ``coverage compact`` drops the legacy table for that target. This is
        a reporting artifact only; it does not affect what gets filtered.
        """
        empty = {"entries": 0, "runs": 0, "by_attack": [], "last_run": None}
        conn = self._connect()
        if conn is None:
            return empty
        try:
            target_row = conn.execute(
                "SELECT id FROM targets WHERE sha256 = ?", (target,)
            ).fetchone()
            target_id = target_row[0] if target_row is not None else None
            entries = conn.execute(
                "SELECT (SELECT COUNT(*) FROM covered WHERE run_id IN "
                "        (SELECT id FROM runs WHERE target = ?)) + "
                "       (SELECT COUNT(*) FROM covered_v2 WHERE target_id = "
                "        (SELECT id FROM targets WHERE sha256 = ?))",
                (target, target),
            ).fetchone()[0]
            runs, last_run = conn.execute(
                "SELECT COUNT(*), MAX(ran_at) FROM runs WHERE target = ?",
                (target,),
            ).fetchone()
            by_attack = conn.execute(
                "SELECT runs.attack, "
                "  SUM((SELECT COUNT(*) FROM covered WHERE covered.run_id = runs.id)) + "
                "  SUM((SELECT COUNT(*) FROM covered_v2 "
                "       WHERE covered_v2.target_id = ? "
                "         AND covered_v2.run_id = runs.id)), "
                "  COUNT(DISTINCT runs.id) "
                "FROM runs WHERE runs.target = ? "
                "GROUP BY runs.attack ORDER BY runs.attack",
                (target_id, target),
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
        """(attack, detail, ran_at) rows for a target, oldest first."""
        conn = self._connect()
        if conn is None:
            return []
        try:
            return [
                (row[0], row[1], row[2])
                for row in conn.execute(
                    "SELECT attack, detail, ran_at FROM runs "
                    "WHERE target = ? ORDER BY id",
                    (target,),
                ).fetchall()
            ]
        except sqlite3.Error:
            return []

    # -- wordlist fingerprints --------------------------------------------

    def clear_fingerprint_memo(self) -> None:
        """Drop the in-process memo. The persisted memo is untouched."""
        self._fingerprints.clear()

    def wordlist_fingerprint(self, path: str) -> str | None:
        """Content sha256 of a wordlist, memoized on (size, mtime).

        The memo is what makes a content hash affordable: rehashing a 31 GB
        corpus on every attack would cost minutes of I/O per run, so the digest
        is recomputed only when size or mtime says the file actually changed.
        """
        try:
            real = os.path.realpath(path)
            stat = os.stat(real)
        except OSError:
            return None

        stamp = (stat.st_size, stat.st_mtime_ns)

        cached = self._fingerprints.get(real)
        if cached is not None and cached[:2] == stamp:
            return cached[2]

        conn = self._connect()
        if conn is not None:
            try:
                row = conn.execute(
                    "SELECT size, mtime_ns, sha256 FROM wordlist_fingerprints "
                    "WHERE path = ?",
                    (real,),
                ).fetchone()
            except sqlite3.Error:
                row = None
            if row is not None and (row[0], row[1]) == stamp:
                self._fingerprints[real] = (stamp[0], stamp[1], row[2])
                return row[2]

        if stat.st_size >= _LARGE_FILE_NOTICE_BYTES:
            # Otherwise this is minutes of dead silence before hashcat even
            # starts: the first fingerprint of a multi-gigabyte corpus is a
            # full sequential read, and it happens inside plan_run.
            print(
                f"[*] Coverage: fingerprinting {os.path.basename(real)} "
                f"({stat.st_size / 1e9:.1f} GB) for the first time; "
                "subsequent runs reuse it."
            )
        try:
            digest = _sha256_file(real)
        except OSError:
            return None

        self._fingerprints[real] = (stamp[0], stamp[1], digest)
        if conn is not None:
            try:
                conn.execute(
                    "INSERT INTO wordlist_fingerprints "
                    "(path, size, mtime_ns, sha256) VALUES (?, ?, ?, ?) "
                    "ON CONFLICT(path) DO UPDATE SET "
                    "size=excluded.size, mtime_ns=excluded.mtime_ns, "
                    "sha256=excluded.sha256",
                    (real, stat.st_size, stat.st_mtime_ns, digest),
                )
                conn.commit()
            except sqlite3.Error:
                pass
        return digest


_default_store: CoverageStore | None = None


def get_store() -> CoverageStore:
    """The process-wide store. Created lazily so importing costs no I/O.

    Never raises. A malformed HATE_CRACK_COVERAGE_DIR degrades to a throwaway
    temporary directory rather than either aborting the attack or silently
    falling back to the operator's real store. Coverage is then ineffective
    for this session, which is the safe direction -- everything runs and
    nothing is falsely marked covered -- and the warning makes it visible
    rather than silent.
    """
    global _default_store
    if _default_store is None:
        try:
            _default_store = CoverageStore()
        except ValueError as exc:
            fallback = Path(tempfile.mkdtemp(prefix="hate_crack-coverage-"))
            print(
                f"WARNING: {exc} Coverage will not persist this session; "
                f"using {fallback}. Attacks run unfiltered.",
                file=sys.stderr,
            )
            _default_store = CoverageStore(fallback / DB_FILENAME)
    return _default_store


def reset_store() -> None:
    """Drop the process-wide store (used by tests and by config reloads)."""
    global _default_store
    if _default_store is not None:
        _default_store.close()
    _default_store = None


# --- target identity -------------------------------------------------------


_target_memo: dict[str, tuple[int, int, str]] = {}


def clear_target_memo() -> None:
    _target_memo.clear()


def target_id(hash_file: str) -> str | None:
    """Content hash of the hash file, or None if it cannot be read.

    Returning None rather than raising lets every caller treat "we cannot
    identify this target" as "do not filter", which is the safe direction: an
    unfiltered run wastes time, a wrongly filtered one silently skips work.

    Memoized on ``(size, mtime_ns)`` for the life of the process. Hash files are
    usually small, but not always -- a large NTLM dump runs to hundreds of
    megabytes, and ``hcatCorporateMasks`` asks once per mask length, so an
    unmemoized read multiplied that by eight.
    """
    try:
        stat = os.stat(hash_file)
    except OSError:
        return None

    stamp = (stat.st_size, stat.st_mtime_ns)
    cached = _target_memo.get(hash_file)
    if cached is not None and cached[:2] == stamp:
        return cached[2]

    try:
        digest = _sha256_file(hash_file)
    except OSError:
        return None
    _target_memo[hash_file] = (stamp[0], stamp[1], digest)
    return digest


# --- rule / mask entry parsing --------------------------------------------


def read_entries_from_bytes(raw: bytes) -> list[str]:
    """Parse rule or .hcmask entries from raw bytes.

    Complements read_entries(path). Decodes with surrogateescape so the round
    trip is lossless (rule files in this project are not all UTF-8), drops
    blank lines and ``#`` comments, and collapses duplicates while preserving
    first-seen order.

    Splitting is on ``\\n``/``\\r\\n`` only, unlike str.splitlines(), which
    also breaks on ``\\x0b``, ``\\x0c``, ``\\x1c``-``\\x1e`` and
    U+2028/2029/0085 -- every one of which a rule can legitimately append.
    """
    text = raw.decode("utf-8", errors="surrogateescape")
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]

    entries: list[str] = []
    seen: set[str] = set()
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line in seen:
            continue
        seen.add(line)
        entries.append(line)
    return entries


def read_entries(path: str) -> list[str]:
    """Read a rule or .hcmask file into its individual entries.

    Only the line terminator is removed. Rule lines are whitespace-significant
    -- ``$ `` appends a space, and stripping it would silently rewrite the rule
    as ``$`` -- so no other trimming happens. Blank lines and ``#`` comments are
    dropped, and duplicates are collapsed while preserving first-seen order so
    a filtered file we later write keeps the author's ordering.

    Read as bytes and decoded with ``surrogateescape`` so the round trip is
    lossless. Two reasons this matters rather than being pedantry: rule files in
    this project are not all UTF-8 (``rulegen.py`` writes latin-1), and
    ``errors="replace"`` would turn an undecodable byte into U+FFFD -- so the
    filtered file we hand back to hashcat would contain a *different rule*, and
    the store would record the mangled entry as covered permanently. Splitting
    is on ``\\n``/``\\r\\n`` only, unlike ``str.splitlines()``, which also
    breaks on ``\\x0b``, ``\\x0c``, ``\\x1c``-``\\x1e`` and U+2028/2029/0085 --
    every one of which a rule can legitimately append.

    Entries stay verbatim here even for .hcmask files, because the return value
    is also what gets written back out as a filtered file for hashcat to run.
    Mask normalization belongs in the key, not the content:
    :func:`canonical_mask_entry` does it at :func:`entry_key` time.
    """
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        return []
    return read_entries_from_bytes(raw)


# --- keys ------------------------------------------------------------------


def canonical_mask_entry(entry: str) -> str:
    """Reduce a mask entry to the candidate set it enumerates.

    Two hcmask lines with different text can try exactly the same candidates,
    and keying on raw text records the second one as uncovered. Only the custom
    charset fields cause this, in three ways HashcatRosetta's expansion
    resolves: a charset can be spelled as a token (``?d`` and ``0123456789``
    expand identically), hashcat deduplicates it (``aa`` is the charset ``a``),
    and its character order changes only the enumeration order, not the set.

    Whitespace is *not* normalized, deliberately. A mask is
    whitespace-significant in the same way a rule is -- a trailing space in
    ``?d?d `` is a literal space position, and a mask with one genuinely
    enumerates different candidates than a mask without it.

    Returns the entry unchanged when it has no custom charsets (so the
    overwhelmingly common plain-mask key is bit-identical to what earlier
    versions recorded), when the mask does not parse, or when the Rosetta
    submodule is unavailable. An unparseable mask is hashcat's problem to
    report, not this function's -- it must still get a stable key.
    """
    if _rosetta_parse_hcmask_line is None or _rosetta_expand_charsets is None:
        return entry
    if "," not in entry:
        # Fast path: no field separator means no custom charsets, so the
        # canonical form is the raw text. Avoids a parse per mask per key.
        return entry
    try:
        parsed = _rosetta_parse_hcmask_line(entry)
        if not parsed.custom:
            return entry
        expanded = _rosetta_expand_charsets(parsed.custom)
    except Exception:
        # Includes MaskError; a bad mask keys on its raw text.
        return entry

    # Sort within each charset (order is enumeration order only), but keep the
    # charsets in slot order -- ?1 and ?2 are not interchangeable.
    normalized = ["".join(sorted(set(charset))) for charset in expanded]
    return "\x00".join(normalized) + "\x00" + parsed.mask


def entry_key(
    target: str,
    kind: str,
    wordlist_fp: str,
    entry: str,
    variant: str = "",
) -> str:
    """Key one (target, kind, wordlist, entry, variant) tuple.

    ``variant`` carries the run modifiers that change what an entry actually
    tries -- an ``--increment 1-8`` mask run covers different candidates than
    the same mask without it -- so the two are never conflated.

    Mask entries are keyed on their canonical form (see
    :func:`canonical_mask_entry`) so two spellings of the same charset are not
    recorded as two separate masks. Rule entries are keyed on raw text: a rule
    has no equivalent normalization, and its whitespace is significant.

    The encode must be *injective*, which ``errors="replace"`` is not: it maps
    every byte ``read_entries`` could not decode to the same U+FFFD, so rules
    differing only in non-UTF-8 bytes -- ``$\\xc3$\\xa1`` and ``$\\xc3$\\xa9``,
    say -- shared a key, and running one marked the other covered. Bandrel's
    Spoonman rule file alone collapsed 154 distinct rules that way.
    ``surrogatepass`` distinguishes them and, unlike ``surrogateescape``, cannot
    raise on a surrogate outside the ``\\udc80``-``\\udcff`` range -- an encode
    error here would take down an attack the store exists only to speed up.
    """
    if kind == "mask":
        entry = canonical_mask_entry(entry)
    payload = f"{target}\x00{kind}\x00{wordlist_fp}\x00{variant}\x00{entry}"
    return hashlib.sha256(payload.encode("utf-8", errors="surrogatepass")).hexdigest()


def _entry_blob(entry: str) -> bytes:
    """Encode entry text for the BLOB dictionary column.

    surrogatepass, matching entry_key, because the encode must be injective:
    errors="replace" maps every undecodable byte to U+FFFD, so rules
    differing only in those bytes would share a row and running one would
    mark the other covered.
    """
    return entry.encode("utf-8", errors="surrogatepass")


def _entry_text(blob: bytes) -> str:
    return bytes(blob).decode("utf-8", errors="surrogatepass")


# int64 rather than int32: the entry dictionary is append-only and never
# garbage collected, so ids grow monotonically for the life of the store.
# Byte order is pinned little-endian, with a conditional byteswap() on a
# big-endian host, so every host writes the same on-disk format and a store
# file is portable between architectures. What this does not buy: a manifest
# written by a build without the byteswap, on a big-endian host, would decode
# to wrong ids on a little-endian reader with no length error - a silent
# failure in the covered-when-untried direction - and that is undetectable
# from the blob alone, so nothing guards against it. The wire format itself
# is pinned by test_pack_ids_wire_format_is_little_endian.


def _pack_ids(ids: Sequence[int]) -> bytes:
    """Pack entry ids as little-endian int64 array."""
    buf = array.array("q", ids)
    if sys.byteorder != "little":
        buf.byteswap()
    return buf.tobytes()


def _unpack_ids(blob: bytes) -> list[int] | None:
    """Unpack entry ids from little-endian int64 array, or None if malformed."""
    if len(blob) % 8 != 0:
        return None
    buf = array.array("q")
    try:
        buf.frombytes(bytes(blob))
    except (ValueError, TypeError):
        return None
    if sys.byteorder != "little":
        buf.byteswap()
    return list(buf)


# --- planning --------------------------------------------------------------


@dataclass(frozen=True)
class CoverageSpec:
    """What an about-to-run hashcat invocation actually covers.

    Attack functions build this alongside the command they assemble, because
    the assembled ``cmd`` list alone cannot say which argument is a wordlist and
    which is a mask. Only the dimensions a run genuinely enumerates are filled
    in; dynamic candidate generators pass no spec at all.
    """

    hash_file: str
    wordlists: tuple[str, ...] = ()
    rule_files: tuple[str, ...] = ()
    mask_files: tuple[str, ...] = ()
    masks: tuple[str, ...] = ()
    # Run modifiers that change what an entry tries (e.g. "inc:1-8").
    variant: str = ""
    # Record what this run covers, but never filter it against what is already
    # covered. The two directions are not symmetric for a run that enumerates a
    # *superset* of its declared entries -- ``--loopback`` being the case that
    # motivates this. Such a run really does try every declared entry, so
    # recording it is sound and lets a later ordinary run of the same wordlist
    # and rules be recognised as a repeat. Filtering it would be unsound,
    # because the extra candidates differ every time.
    record_only: bool = False


@dataclass(frozen=True)
class LegacyProbe:
    """Old-schema hex keys for the same probes, used only for legacy targets.

    `keys` maps each (wl_id, variant_id, entry_id) triple to the sha256 key
    the pre-interning schema would have recorded for it, so a lookup can
    union both tables during the transition.
    """

    target: str
    keys: dict[tuple[int, int, int], str]


@dataclass(frozen=True)
class RunPlan:
    """The filtering decision for one run.

    ``kind`` names the dimension that was diffed, which tells the caller how to
    apply ``filtered_entries``: rewrite ``source_path``'s file for ``"rule"``
    and ``"mask"``, or drop positional arguments for ``"wordlist"``. An inert
    plan (``kind == ""``) means coverage could not be established, so the run
    must proceed untouched.
    """

    kind: str = ""
    skip: bool = False
    covered_count: int = 0
    total_count: int = 0
    filtered_entries: list[str] | None = None
    source_path: str | None = None
    # Interned (wl_id, variant_id, entry_id) triples this run covers, for
    # the store to link to the run row. Replaces the old record_keys list of
    # sha256 hex strings.
    record_rows: list[tuple[int, int, int]] = field(default_factory=list)
    target: str = ""
    # Interned id of `target`, so the caller can record without re-interning.
    target_id: int | None = None
    # Fingerprints of the wordlists this run enumerates, for the store to link
    # to the run row. Carried separately from the keys because a "wordlist"-kind
    # plan keys *on* them, so they cannot be recovered from the keying slots.
    wordlist_fps: tuple[str, ...] = ()

    @property
    def has_overlap(self) -> bool:
        return self.covered_count > 0

    @property
    def is_inert(self) -> bool:
        return not self.kind


_INERT = RunPlan()


def set_lookup(covered: set) -> Callable:
    """Adapt a plain set of probe triples to the lookup callable."""
    return lambda _target_id, probes: {p for p in probes if p in covered}


def _NOTHING_COVERED(_target_id, probes) -> set:  # noqa: N802
    """Lookup used by record-only runs: report no overlap, so nothing filters."""
    return set()


def _chain_entry(rule_files: tuple[str, ...]) -> str | None:
    """Collapse chained rule files into one opaque, order-sensitive entry.

    ``-r a -r b`` makes hashcat apply the *cartesian product* of both files, so
    dropping an individual line from either file would silently remove every
    combination it participated in. Such a run is therefore tracked as a single
    all-or-nothing unit rather than filtered per entry.
    """
    parts = []
    for path in rule_files:
        entries = read_entries(path)
        if not entries:
            return None
        parts.append(hashlib.sha256("\n".join(entries).encode()).hexdigest())
    return "chain:" + ":".join(parts)


def _convert_legacy_if_needed(
    store: "CoverageStore",
    target: str,
    target_id_of: int,
    kind: str,
    scope: str,
    entries: list[str],
    entry_ids: list[int],
    wordlist_fps: Sequence[str],
    wl_ids: Sequence[int],
    variant: str,
    variant_id: int,
) -> None:
    """For a legacy target, carry this (scope, kind, wordlist, variant)
    combination's pre-interning coverage into covered_v2, once per wordlist.

    Self-limiting: is_converted() short-circuits every call after the first
    for a given combination, so the old table is queried at most once per
    combination rather than on every plan. Runs BEFORE _plan_entries, so
    _plan_entries's own lookup (plain covered_ids, no legacy= kwarg) already
    sees the converted rows in covered_v2 -- the legacy dual-read is used
    only inside this conversion step, never in the hot filtering path.

    A run failure anywhere degrades silently: convert_scope, is_converted,
    covered_ids and log_run all already return their own safe defaults on
    failure, so a store that cannot write here simply never converts and the
    dual-read keeps consulting the old table on every future plan for this
    combination -- slower, never wrong.
    """
    if not store.is_legacy_target(target):
        return
    slots = list(zip(wordlist_fps, wl_ids)) or [("", wl_ids[0] if wl_ids else 0)]
    for fp, wl_id in slots:
        if store.is_converted(target, scope, kind, fp, variant):
            continue
        legacy = LegacyProbe(
            target=target,
            keys={
                (wl_id, variant_id, eid): entry_key(target, kind, fp, entry, variant)
                for entry, eid in zip(entries, entry_ids)
            },
        )
        probes = [(wl_id, variant_id, eid) for eid in entry_ids]
        hits = store.covered_ids(target_id_of, probes, legacy=legacy)
        run_id = store.log_run(target, kind=kind, detail="legacy-conversion")
        if run_id is not None:
            store.convert_scope(
                target, scope, kind, fp, variant, list(hits), run_id, target_id_of
            )


def plan_run(
    spec: CoverageSpec,
    lookup: Callable | None = None,
    store: CoverageStore | None = None,
) -> RunPlan:
    """Decide what of ``spec`` still needs running, given what is covered.

    Every failure to establish identity returns an inert plan, so the run
    proceeds in full. That bias is deliberate: an unfiltered run costs time,
    while a wrongly filtered one silently skips untried candidates.
    """
    target = target_id(spec.hash_file)
    if target is None:
        return _INERT

    store = store if store is not None else get_store()

    target_id_of = store.intern_target(target)
    variant_id = store.intern_variant(spec.variant)
    if target_id_of is None or variant_id is None:
        return _INERT

    if lookup is None:
        lookup = store.covered_ids
    if spec.record_only:
        # Answering "nothing is covered" makes _plan_entries treat every entry
        # as novel: no overlap to report, so no prompt and no filtering, while
        # record_rows still covers the whole declared set.
        lookup = _NOTHING_COVERED

    wordlist_fps: list[str] = []
    wl_ids: list[int] = []
    for path in spec.wordlists:
        fingerprint = store.wordlist_fingerprint(path)
        if fingerprint is None:
            # A glob that matched nothing, or a list that vanished. Either way
            # we cannot say what this run covers.
            return _INERT
        wl_id = store.intern_wordlist(fingerprint)
        if wl_id is None:
            return _INERT
        wordlist_fps.append(fingerprint)
        wl_ids.append(wl_id)

    if spec.rule_files:
        if len(spec.rule_files) > 1:
            entry = _chain_entry(spec.rule_files)
            if entry is None:
                return _INERT
            ids = store.intern_entries("rule", [entry])
            if ids is None:
                return _INERT
            _convert_legacy_if_needed(
                store,
                target,
                target_id_of,
                "rule",
                entry,
                [entry],
                ids,
                wordlist_fps,
                wl_ids,
                spec.variant,
                variant_id,
            )
            return _plan_entries(
                kind="rule",
                entries=[entry],
                entry_ids=ids,
                wl_ids=wl_ids,
                variant_id=variant_id,
                target=target,
                target_id=target_id_of,
                lookup=lookup,
                source_path=None,
                filterable=False,
                run_wordlist_fps=wordlist_fps,
            )
        loaded = store.file_entry_ids(spec.rule_files[0], "rule")
        if loaded is None:
            return _INERT
        entries, ids = loaded
        try:
            scope = _sha256_file(spec.rule_files[0])
        except OSError:
            scope = None
        if scope is not None:
            _convert_legacy_if_needed(
                store,
                target,
                target_id_of,
                "rule",
                scope,
                entries,
                ids,
                wordlist_fps,
                wl_ids,
                spec.variant,
                variant_id,
            )
        return _plan_entries(
            kind="rule",
            entries=entries,
            entry_ids=ids,
            wl_ids=wl_ids,
            variant_id=variant_id,
            target=target,
            target_id=target_id_of,
            lookup=lookup,
            source_path=spec.rule_files[0],
            filterable=True,
            run_wordlist_fps=wordlist_fps,
        )

    if spec.mask_files or spec.masks:
        mask_entries: list[str] = []
        for path in spec.mask_files:
            loaded = store.file_entry_ids(path, "mask")
            if loaded is None:
                return _INERT
            mask_entries.extend(loaded[0])
        mask_entries.extend(spec.masks)
        # Preserve order while dropping duplicates across the combined sources.
        mask_entries = list(dict.fromkeys(mask_entries))
        if not mask_entries:
            return _INERT
        ids = store.intern_entries("mask", mask_entries)
        if ids is None:
            return _INERT
        single_file = (
            spec.mask_files[0] if len(spec.mask_files) == 1 and not spec.masks else None
        )
        if single_file is not None:
            try:
                scope = _sha256_file(single_file)
            except OSError:
                scope = None
            if scope is not None:
                _convert_legacy_if_needed(
                    store,
                    target,
                    target_id_of,
                    "mask",
                    scope,
                    mask_entries,
                    ids,
                    wordlist_fps,
                    wl_ids,
                    spec.variant,
                    variant_id,
                )
        return _plan_entries(
            kind="mask",
            entries=mask_entries,
            entry_ids=ids,
            wl_ids=wl_ids,
            variant_id=variant_id,
            target=target,
            target_id=target_id_of,
            lookup=lookup,
            source_path=single_file,
            filterable=single_file is not None,
            run_wordlist_fps=wordlist_fps,
        )

    if spec.wordlists:
        # A rule-less dictionary attack: the wordlist itself is the unit. This
        # is the one shape where the entries being diffed ARE wordlist
        # fingerprints, so they intern as kind "wordlist" and wl_id collapses
        # to the single empty slot.
        ids = store.intern_entries("wordlist", wordlist_fps)
        if ids is None:
            return _INERT
        empty_wl = store.intern_wordlist("")
        if empty_wl is None:
            return _INERT
        # Scope is per-wordlist, not per-plan: the literal "wordlist" scope
        # this used to share across every wordlist-kind plan for a target
        # collapsed all of them onto one marker, so the first plan_run for
        # any wordlist silently short-circuited conversion for every other
        # wordlist that target would ever run -- a common shape (a
        # rule-less dictionary attack repeated against several wordlists)
        # abandoned legacy coverage it should have recognized. Each
        # wordlist's own fingerprint is a natural content-addressed scope
        # (a replaced corpus invalidates its own marker, matching how the
        # file-backed branches already behave), so convert one wordlist at
        # a time.
        #
        # The key-formula arguments -- wordlist_fps=[""], wl_ids=[empty_wl]
        # -- do NOT change with the loop. They are what keeps the internal
        # legacy-key formula exactly entry_key(target, "wordlist", "",
        # fingerprint, variant), byte-identical to the old code; only the
        # scope argument becomes per-wordlist.
        for fp, eid in zip(wordlist_fps, ids):
            _convert_legacy_if_needed(
                store,
                target,
                target_id_of,
                "wordlist",
                fp,
                [fp],
                [eid],
                [""],
                [empty_wl],
                spec.variant,
                variant_id,
            )
        return _plan_entries(
            kind="wordlist",
            entries=wordlist_fps,
            entry_ids=ids,
            wl_ids=[empty_wl],
            variant_id=variant_id,
            target=target,
            target_id=target_id_of,
            lookup=lookup,
            source_path=None,
            filterable=True,
            display=list(spec.wordlists),
            run_wordlist_fps=wordlist_fps,
        )

    return _INERT


def _plan_entries(
    *,
    kind: str,
    entries: list[str],
    entry_ids: list[int],
    wl_ids: list[int],
    variant_id: int,
    target: str,
    target_id: int,
    lookup: Callable[[int, Sequence[tuple[int, int, int]]], set],
    source_path: str | None,
    filterable: bool,
    display: list[str] | None = None,
    run_wordlist_fps: Sequence[str] = (),
) -> RunPlan:
    # A mask run has no wordlist, but still needs one slot to key against.
    slots = wl_ids or [0]

    probes_by_entry = [
        [(wl, variant_id, entry_id) for wl in slots] for entry_id in entry_ids
    ]
    all_probes = [p for probes in probes_by_entry for p in probes]
    already = lookup(target_id, all_probes)

    novel: list[str] = []
    novel_display: list[str] = []
    record_rows: list[tuple[int, int, int]] = []

    for index, probes in enumerate(probes_by_entry):
        # Only fully-covered entries are dropped. An entry already tried
        # against one wordlist but not another must still run.
        if all(probe in already for probe in probes):
            continue
        novel.append(entries[index])
        novel_display.append(display[index] if display else entries[index])
        record_rows.extend(probes)

    covered_count = len(entries) - len(novel)

    common = dict(
        kind=kind,
        covered_count=covered_count,
        total_count=len(entries),
        source_path=source_path,
        target=target,
        target_id=target_id,
        wordlist_fps=tuple(run_wordlist_fps),
    )
    if not novel:
        return RunPlan(skip=True, **common)
    return RunPlan(
        skip=False,
        filtered_entries=novel_display if (filterable and covered_count) else None,
        record_rows=record_rows,
        **common,
    )
