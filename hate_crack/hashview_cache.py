"""Cross-run cache of hashes already uploaded to Hashview.

Tracks (hash, hash_type) pairs that have been successfully uploaded so
repeat uploads (upload_cracked_hashes, upload_hashfile) can skip them
before doing any verification or network work.
"""

import hashlib
import os
from pathlib import Path
from typing import Iterable

CACHE_FILENAME = "hashview_uploaded_cache.txt"


def _cache_path() -> Path:
    # Mirrors the inline ~/.hate_crack construction main.py's omen
    # model_info.json cache uses (main.py ~line 4093). Deliberately NOT
    # hate_crack.api._get_hate_path(), which resolves the bundled
    # hashcat-utils/PACK assets directory -- a different thing entirely.
    return Path(os.path.expanduser("~")) / ".hate_crack" / CACHE_FILENAME


def cache_key(hash_value: str, hash_type) -> str:
    return hashlib.sha256(f"{hash_value}:{hash_type}".encode()).hexdigest()


def load_cache() -> set:
    path = _cache_path()
    if not path.exists():
        return set()
    with path.open("r", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def append_to_cache(keys: Iterable[str]) -> None:
    keys = list(keys)
    if not keys:
        return
    path = _cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for key in keys:
            f.write(key + "\n")
