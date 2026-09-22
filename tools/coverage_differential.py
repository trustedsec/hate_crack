#!/usr/bin/env python3
"""Differential oracle: the interned coverage path must agree with the legacy one.

The legacy hex-key path (``entry_key``, ``CoverageStore.covered``,
``CoverageStore.record``) predates the interning rewrite and is the only
independent authority for what "covered" actually means -- a unit test
written by the same agent that wrote the interned code shares its
misconceptions. This tool builds the same coverage state through both paths
and asks both "is this entry covered?", then reports where they disagree.

The two disagreement directions are NOT equally dangerous:

- ``only_legacy``: the legacy path calls an entry covered and the interned
  path does not. This means the interned path will re-try a candidate the
  legacy path considered already tried -- wasted GPU time, but safe.
- ``only_interned``: the interned path calls an entry covered and the legacy
  path does not. This is the dangerous direction: it means the interned path
  will silently *skip* a candidate the legacy path would have run, and
  nothing in any log says so. This is exactly the failure mode false-covered
  bugs take in this codebase.

Usage:

    uv run python tools/coverage_differential.py \\
        --store /tmp/cov-copy.sqlite3 --rules-dir /usr/local/share/hashcat/rules \\
        --masks-dir /usr/local/share/hashcat/masks --target <sha256>

Exits non-zero only when ``only_interned`` is non-empty anywhere in the scan
-- that asymmetry is deliberate; see the ``__main__`` block below.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hate_crack.attack_coverage import CoverageStore, entry_key  # noqa: E402


@dataclass(frozen=True)
class DiffResult:
    agreed: int
    only_legacy: list[str] = field(default_factory=list)
    only_interned: list[str] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.only_legacy and not self.only_interned


def compare(
    store: CoverageStore,
    target: str,
    sources: Sequence[tuple[str, str]],
    wordlist_fp: str,
    variant: str,
) -> DiffResult:
    """Compare legacy and interned coverage membership over ``sources``.

    ``sources`` is a sequence of ``(path, kind)`` pairs, each read and probed
    through both the legacy ``entry_key``/``covered`` path and the interned
    ``file_entry_ids``/``covered_ids`` path. Results are unioned across all
    sources by entry text.
    """
    legacy_covered: set[str] = set()
    interned_covered: set[str] = set()
    all_entries: set[str] = set()

    target_id = store.intern_target(target)
    wl_id = store.intern_wordlist(wordlist_fp)
    variant_id = store.intern_variant(variant)

    for path, kind in sources:
        loaded = store.file_entry_ids(path, kind)
        if loaded is None:
            continue
        entries, ids = loaded
        all_entries.update(entries)

        # Legacy: compute one entry_key per entry, ask the legacy path which
        # keys are covered, then map hits back to entry text BY POSITION.
        # Positional, not a dict keyed by hash: two distinct mask spellings
        # (e.g. "abc,?1?1" and "cba,?1?1") canonicalize to the SAME
        # entry_key, so a dict built from zip(keys, entries) would silently
        # collapse onto whichever entry text was inserted last and lose the
        # other -- the same family of bug this whole tool exists to catch.
        keys = [
            entry_key(target, kind, wordlist_fp, entry, variant) for entry in entries
        ]
        legacy_hits = store.covered(keys)
        for position, key in enumerate(keys):
            if key in legacy_hits:
                legacy_covered.add(entries[position])

        # Interned: build probes from the ids returned in file order, ask
        # covered_ids which triples are covered, then map hits back to entry
        # text BY POSITION -- never by a dictionary lookup, since interned
        # entries may be canonicalized (masks) and not match the literal
        # file text.
        if target_id is None or wl_id is None or variant_id is None:
            continue
        probes = [(wl_id, variant_id, eid) for eid in ids]
        interned_hits = store.covered_ids(target_id, probes)
        for position, probe in enumerate(probes):
            if probe in interned_hits:
                interned_covered.add(entries[position])

    only_legacy = sorted(legacy_covered - interned_covered)
    only_interned = sorted(interned_covered - legacy_covered)
    agreed = len(all_entries) - len(only_legacy) - len(only_interned)

    return DiffResult(
        agreed=agreed, only_legacy=only_legacy, only_interned=only_interned
    )


def record_via_both(
    store: CoverageStore,
    target: str,
    sources: Sequence[tuple[str, str]],
    wordlist_fp: str,
    variant: str,
    subset: Sequence[str] | None = None,
    subset_index: Sequence[int] | None = None,
) -> None:
    """Record the same logical coverage through both the legacy and interned
    recording paths, so ``compare`` starts from a shared, consistent state.

    Exactly one of ``subset`` (entry texts) or ``subset_index`` (positions
    within each source's file order) must be given -- passing both, or
    neither, is a caller error and raises ``ValueError`` rather than
    guessing which one the caller meant.
    """
    if (subset is None) == (subset_index is None):
        raise ValueError(
            "record_via_both requires exactly one of subset or subset_index"
        )

    target_id = store.intern_target(target)
    wl_id = store.intern_wordlist(wordlist_fp)
    variant_id = store.intern_variant(variant)

    legacy_run_id = store.log_run(target, kind="", attack="differential-oracle")
    interned_run_id = store.log_run(target, kind="", attack="differential-oracle")

    for path, kind in sources:
        loaded = store.file_entry_ids(path, kind)
        if loaded is None:
            continue
        entries, ids = loaded

        if subset_index is not None:
            positions = list(subset_index)
        else:
            assert subset is not None
            wanted = set(subset)
            positions = [i for i, entry in enumerate(entries) if entry in wanted]

        if not positions:
            continue

        legacy_keys = [
            entry_key(target, kind, wordlist_fp, entries[i], variant) for i in positions
        ]
        if legacy_run_id is not None:
            store.record(
                legacy_keys,
                target=target,
                kind=kind,
                attack="differential-oracle",
                wordlist_fps=(wordlist_fp,) if wordlist_fp else (),
            )

        if (
            target_id is not None
            and wl_id is not None
            and variant_id is not None
            and interned_run_id is not None
        ):
            rows = [(wl_id, variant_id, ids[i]) for i in positions]
            store.record_ids(target_id, rows, interned_run_id)


def _list_files(directory: str) -> list[str]:
    try:
        entries = sorted(os.listdir(directory))
    except OSError as exc:
        print(f"[!] Cannot list directory {directory}: {exc}", file=sys.stderr)
        return []
    return [
        os.path.join(directory, entry)
        for entry in entries
        if os.path.isfile(os.path.join(directory, entry))
    ]


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare legacy and interned coverage membership over rule and "
            "mask files. Exits non-zero if only_interned is non-empty -- "
            "that is the dangerous direction, a candidate the interned path "
            "would silently skip that the legacy path would have run."
        )
    )
    parser.add_argument("--store", required=True, help="Path to a coverage store.")
    parser.add_argument(
        "--rules-dir", default=None, help="Directory of .rule files, one level deep."
    )
    parser.add_argument(
        "--masks-dir", default=None, help="Directory of mask files, one level deep."
    )
    parser.add_argument(
        "--target", required=True, help="Target sha256 to compare against."
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)

    if not os.path.isfile(args.store):
        print(f"[!] --store {args.store} does not exist.", file=sys.stderr)
        return 1

    sources: list[tuple[str, str]] = []
    if args.rules_dir:
        sources.extend((p, "rule") for p in _list_files(args.rules_dir))
    if args.masks_dir:
        sources.extend((p, "mask") for p in _list_files(args.masks_dir))

    if not sources:
        print("[!] No files discovered under --rules-dir/--masks-dir.", file=sys.stderr)
        return 1

    store = CoverageStore(path=args.store)
    result = compare(store, args.target, sources, "", "")

    print("=== coverage_differential.py results ===")
    print(f"store: {args.store}")
    print(f"target: {args.target}")
    print(f"sources scanned: {len(sources)}")
    print(f"agreed: {result.agreed}")
    print(f"only_legacy (safe, redundant work): {len(result.only_legacy)}")
    print(
        f"only_interned (DANGEROUS, silently skipped candidates): {len(result.only_interned)}"
    )
    if result.only_interned:
        print("First 20 only_interned entries:")
        for entry in result.only_interned[:20]:
            print(f"  {entry!r}")

    # Deliberate asymmetry: only_interned is a false-covered bug -- a
    # candidate the interned path will silently never try. only_legacy is a
    # false-not-covered miss, which just re-tries a candidate: wasteful but
    # never wrong, so it does not fail the gate by itself.
    if result.only_interned:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
