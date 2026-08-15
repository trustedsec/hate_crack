"""Strict JSON loading for the config-example drift guards.

``json.load`` accepts duplicate object keys and silently keeps the last one,
which is legal JSON but wrong for a file whose whole job is to enumerate the
settings exactly once. A duplicated key sails through every drift guard in the
suite: ``set(example.keys())`` collapses the pair, the key counts match, and
the types match — the file is malformed and nothing says so. That happened for
real while adding ``hcatCorpusProfileMaxLines``: an edit script wrote through
both the root path and the package symlink that points at it, producing two
identical lines, and the full suite stayed green.

Used by the tests that read ``config.json.example``; nothing in the package
imports it. The production loader keeps standard ``json`` semantics, since a
duplicate in an operator's own ``config.json`` is their file to write and
last-wins is the behaviour every other JSON tool would give them.
"""

from __future__ import annotations

import json
from typing import Any


class DuplicateJSONKeyError(ValueError):
    """Raised when a JSON object holds the same key more than once."""


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """object_pairs_hook that raises instead of letting the last value win.

    Receives every object in the document, nested ones included, so a
    duplicate at any depth is caught rather than just at the top level.
    """
    seen: set[str] = set()
    duplicates: list[str] = []
    for key, _value in pairs:
        if key in seen:
            duplicates.append(key)
        seen.add(key)
    if duplicates:
        raise DuplicateJSONKeyError(
            "duplicate key(s) in JSON object: " + ", ".join(sorted(set(duplicates)))
        )
    return dict(pairs)


def loads_strict(text: str) -> dict[str, Any]:
    """Parse *text*, raising DuplicateJSONKeyError on any repeated key."""
    return json.loads(text, object_pairs_hook=_reject_duplicates)


def load_strict(path) -> dict[str, Any]:
    """Read and parse *path*, raising DuplicateJSONKeyError on a repeated key."""
    with open(path) as fh:
        return json.load(fh, object_pairs_hook=_reject_duplicates)
