"""Detect ``username:hash`` format in hashcat input files.

This module owns the allowlist/blocklist of hash modes and the regex-based
per-line validation used to decide whether to pass ``--username`` to hashcat.
"""
from __future__ import annotations

import re
from typing import Final

# Modes where bare hashes are the normal input AND files commonly carry a
# ``username:`` prefix. Value is the expected hex length of the hash field.
USERNAME_HASH_MODES: Final[dict[str, int]] = {
    "0":    32,   # MD5
    "10":   32,   # md5($pass.$salt)
    "20":   32,   # md5($salt.$pass)
    "30":   32,   # md5(unicode($pass).$salt)
    "40":   32,   # md5($salt.unicode($pass))
    "50":   32,   # HMAC-MD5
    "60":   32,   # HMAC-MD5(key=$pass)
    "100":  40,   # SHA1
    "101":  40,   # nsldap/SHA1(Base64)
    "110":  40,   # sha1($pass.$salt)
    "120":  40,   # sha1($salt.$pass)
    "130":  40,   # sha1(unicode($pass).$salt)
    "140":  40,   # sha1($salt.unicode($pass))
    "150":  40,   # HMAC-SHA1
    "160":  40,   # HMAC-SHA1(key=$pass)
    "900":  32,   # MD4
    "1000": 32,   # NTLM bare
    "1400": 64,   # SHA2-256
    "1410": 64, "1420": 64, "1430": 64, "1440": 64, "1450": 64, "1460": 64,
    "1700": 128,  # SHA2-512
    "1710": 128, "1720": 128, "1730": 128, "1740": 128, "1750": 128, "1760": 128,
    "3000": 16,   # LM (single half)
}

# Modes explicitly excluded even if they appear in allowlist (they don't, but
# this constant is the documentation of the intentional blocklist). Binary
# formats, IKE-PSK, and NetNTLM (already preprocessed elsewhere).
USERNAME_DETECT_BLOCKLIST: Final[frozenset[str]] = frozenset({
    "2500", "22000", "2501", "16800", "16801", "22001",  # WPA variants (binary)
    "5300", "5400",                                       # IKE-PSK
    "5500", "5600",                                       # NetNTLM (own preprocess)
    "1800", "3200",                                       # non-hex hash formats
})


def detect_username_hash_format(
    hash_file: str,
    hash_type: str,
    *,
    sample_size: int = 10,
) -> bool:
    """Return True if every sampled non-empty line of ``hash_file`` looks like
    ``username:<hex_hash>`` with the expected hex length for ``hash_type``.

    Returns False if:
    - ``hash_type`` is in the blocklist
    - ``hash_type`` is not in the allowlist
    - the file is missing/unreadable/empty
    - any sampled non-empty non-comment line does not match the pattern
    """
    if hash_type in USERNAME_DETECT_BLOCKLIST:
        return False
    hex_len = USERNAME_HASH_MODES.get(hash_type)
    if hex_len is None:
        return False

    pattern = re.compile(rf"^[^:]+:[0-9a-fA-F]{{{hex_len}}}$")

    try:
        with open(hash_file, "r", encoding="utf-8-sig") as fh:
            samples: list[str] = []
            for raw in fh:
                line = raw.strip().replace("\x00", "")
                if not line or line.startswith("#"):
                    continue
                samples.append(line)
                if len(samples) >= sample_size:
                    break
    except OSError:
        return False

    if not samples:
        return False

    return all(pattern.match(line) for line in samples)
