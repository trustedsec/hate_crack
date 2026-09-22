#!/usr/bin/env python3
"""Benchmark the whole coverage planning path against a real store.

The spec's original 1.5 s planning figure was measured against an *empty*
store and only timed the membership test (``covered_ids``). That undercounts
the real path in two ways: a populated store's file manifests may already
hold hundreds of thousands of rows to search through, and the membership
test alone omits the step the design review flagged as the actual gap --
writing the filtered file hashcat is handed.

This tool times the whole path for a sample of real rule files against a
copy of a real store:

1. ``file_entry_ids(path, "rule")`` -- reads the file once, hashes its whole
   content, and either hits the file-manifest cache or interns every line.
   This alone covers the content hash and the manifest lookup/build.
2. ``covered_ids(target_id, probes)`` -- the membership test, run against a
   throwaway target interned solely for this benchmark so a real operator
   target's coverage is never touched.
3. A real write of a filtered file to a temp path, using the entries
   ``file_entry_ids`` already returned in memory -- never a second read of
   the source file and never a dictionary round trip -- mirroring the
   discipline ``hate_crack.main._write_filtered_entries`` follows for a real
   run.

Usage:

    uv run python tools/coverage_benchmark.py \\
        --store /tmp/cov-bench.sqlite3 --rules-dir /usr/local/share/hashcat/rules

``--store`` must point at a store you are willing to have grow: on the first
touch of a rule file the store has never seen, ``file_entry_ids`` builds and
persists a fresh manifest for it, which is itself part of what this tool is
measuring. Never point ``--store`` at the operator's live
``~/.hate_crack/coverage/attack_coverage.sqlite3`` -- copy it first.

Exits 0 on success. Exits 1 if the store cannot be opened, or the rules
directory cannot be listed, or contains no ``.rule`` files.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hate_crack import attack_coverage  # noqa: E402


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Benchmark the whole coverage planning path (content hash, "
            "manifest lookup, membership test, filtered-file write) against "
            "a copy of a real coverage store."
        )
    )
    parser.add_argument(
        "--store",
        required=True,
        help="Path to a coverage store SQLite file. Use a COPY, never the "
        "operator's live store -- this tool can grow it.",
    )
    parser.add_argument(
        "--rules-dir",
        required=True,
        help="Directory of .rule files to sample, one level deep.",
    )
    return parser.parse_args(argv)


def _list_rule_files(rules_dir: str) -> list[str]:
    try:
        entries = sorted(os.listdir(rules_dir))
    except OSError as exc:
        print(f"[!] Cannot list --rules-dir {rules_dir}: {exc}", file=sys.stderr)
        return []
    paths = []
    for entry in entries:
        full = os.path.join(rules_dir, entry)
        if os.path.isfile(full) and entry.endswith(".rule"):
            paths.append(full)
    return paths


def _store_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return -1


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if not os.path.isfile(args.store):
        print(f"[!] --store {args.store} does not exist.", file=sys.stderr)
        return 1

    rule_files = _list_rule_files(args.rules_dir)
    if not rule_files:
        print(
            f"[!] No .rule files found directly under {args.rules_dir}.",
            file=sys.stderr,
        )
        return 1

    size_before = _store_size(args.store)

    store = attack_coverage.CoverageStore(path=args.store)

    # A throwaway target and variant, interned solely for this benchmark run,
    # so the membership test has something real to query against without
    # ever touching a real operator target's recorded coverage.
    throwaway_sha = hashlib.sha256(
        f"coverage-benchmark-throwaway-{time.time_ns()}".encode()
    ).hexdigest()
    target_id = store.intern_target(throwaway_sha)
    variant_id = store.intern_variant("")
    wl_id = store.intern_wordlist("")
    if target_id is None or variant_id is None or wl_id is None:
        print(f"[!] Could not open/write to store {args.store}.", file=sys.stderr)
        return 1

    file_entry_times: list[float] = []
    covered_ids_times: list[float] = []
    write_times: list[float] = []
    total_start = time.perf_counter()
    files_ok = 0
    files_failed = 0

    for path in rule_files:
        t0 = time.perf_counter()
        loaded = store.file_entry_ids(path, "rule")
        t1 = time.perf_counter()
        if loaded is None:
            files_failed += 1
            continue
        entries, entry_ids = loaded

        probes = [(wl_id, variant_id, eid) for eid in entry_ids]
        _already_covered = store.covered_ids(target_id, probes)
        t2 = time.perf_counter()
        # A fresh throwaway target has nothing covered yet, so every entry is
        # written -- this is the worst case for the write step, matching a
        # first-ever run against a target.

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                suffix=".rule",
                prefix="hate_crack_coverage_bench_",
                delete=False,
            ) as handle:
                tmp_path = handle.name
                for entry in entries:
                    handle.write(
                        entry.encode("utf-8", errors="surrogateescape") + b"\n"
                    )
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
        t3 = time.perf_counter()

        file_entry_times.append(t1 - t0)
        covered_ids_times.append(t2 - t1)
        write_times.append(t3 - t2)
        files_ok += 1

    total_elapsed = time.perf_counter() - total_start
    size_after = _store_size(args.store)

    print("=== coverage_benchmark.py results ===")
    print(f"store: {args.store}")
    print(f"rules_dir: {args.rules_dir}")
    print(f"files sampled: {len(rule_files)}")
    print(f"files ok: {files_ok}")
    print(f"files failed (file_entry_ids returned None): {files_failed}")
    print()
    print(f"total wall time (whole path, all files): {total_elapsed:.6f} s")
    if files_ok:
        print(f"average per file (whole path): {total_elapsed / files_ok:.6f} s")
        print(
            "average file_entry_ids (content hash + manifest): "
            f"{sum(file_entry_times) / files_ok:.6f} s"
        )
        print(
            "average covered_ids (membership test): "
            f"{sum(covered_ids_times) / files_ok:.6f} s"
        )
        print(f"average filtered-file write: {sum(write_times) / files_ok:.6f} s")
    print()
    print(f"store size before: {size_before} bytes ({size_before / 1e6:.2f} MB)")
    print(f"store size after:  {size_after} bytes ({size_after / 1e6:.2f} MB)")
    print(f"store size delta:  {size_after - size_before} bytes")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
