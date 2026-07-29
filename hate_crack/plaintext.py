"""Recover the plaintext password from a line of a corpus file.

Every part of hate_crack that learns from a corpus — the LLM modes, the
statistics in :mod:`hate_crack.corpus_stats`, the baseword/rule derivation in
:mod:`hate_crack.rulegen` — has to answer the same question first: given this
line, what was the password? The answer is not "the whole line", because the
files operators actually reach for are hashcat's own output.

Two things have to be undone:

* **The hash prefix.** hashcat writes ``hash:plain`` (or ``hash:salt:plain``),
  so a line from a ``.out`` file carries the hash in front of the password.
* **The ``$HEX[...]`` wrapper.** hashcat applies it to any plaintext holding
  non-ASCII bytes or the output separator.

Both are undone conservatively: a line that does not clearly carry a hash is
returned intact. That matters because the same functions read plain wordlists,
where an entry may legitimately contain a colon — a URL, a ratio, a time of day
— and splitting it would silently corrupt the corpus. Guessing wrong in that
direction is worse than not splitting at all, because nothing downstream can
detect it.

This module deliberately has no imports from the rest of the package so both
rulegen and corpus_stats can depend on it.
"""

import binascii

# Lengths of a hex-encoded hash for the algorithms hate_crack actually sees:
# LM/MySQL323 (16), MD4/MD5/NTLM (32), SHA1/MySQL41 (40), RIPEMD/SHA224 (48/56),
# SHA256 (64), SHA384 (96), SHA512 (128).
HEX_HASH_LENGTHS = frozenset({16, 32, 40, 48, 56, 64, 96, 128})

_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _is_hex(value):
    return bool(value) and all(c in _HEX_DIGITS for c in value)


def is_hash_token(token):
    """True if *token* has the shape of a hash rather than a password.

    Recognizes hex digests at a known length, and crypt-style strings
    (``$2y$10$...``, ``$6$...``). Length is what does the work: requiring an
    exact digest length is why ``deadbeef`` and ``aabbcc`` — plausible
    passwords, and plausible hash *stand-ins* in a test fixture — are left
    alone, while a real 32-character NTLM digest is not.
    """
    if not token:
        return False
    if token.startswith("$HEX["):
        # A wrapped plaintext, not a hash — see decode_hex_wrapper.
        return False
    if token.startswith("$") and token.count("$") >= 3:
        return True
    return len(token) in HEX_HASH_LENGTHS and _is_hex(token)


def looks_like_hash_line(line):
    """True if *line* looks like an uncracked hash record, not a cracked one.

    Operators keep raw NTDS dumps (``user:rid:lm:nt:::``) in the same working
    directory as cracked output, under similar names. A dump yields confident
    nonsense rather than an error, so callers warn on it.
    """
    if line.endswith(":::"):
        return True
    # The empty-LM constant, present on every account in an NTDS dump.
    if "aad3b435b51404eeaad3b435b51404ee" in line:
        return True
    fields = line.split(":")
    # A bare digest with no plaintext after it.
    if len(fields) == 1:
        return is_hash_token(fields[0])
    return False


def strip_hash_prefix(line):
    """Return the plaintext portion of *line*, dropping any leading hash fields.

    Scans left to right and drops each leading field that has the shape of a
    hash, then returns the remainder joined back together — so a plaintext that
    itself contains colons survives intact, and a hash carrying its own colons
    is fully consumed. A line whose first field is not hash-shaped is returned
    unchanged.
    """
    if ":" not in line:
        return line
    fields = line.split(":")
    idx = 0
    while idx < len(fields) - 1 and is_hash_token(fields[idx]):
        idx += 1
    if idx == 0:
        return line
    return ":".join(fields[idx:])


def decode_hex_wrapper(plaintext):
    """Expand hashcat's ``$HEX[...]`` wrapper to the bytes it encodes.

    Decoded to latin-1 so one byte maps to one character, matching how a corpus
    is read elsewhere: hashcat rules address bytes, not codepoints. Returns
    *plaintext* unchanged if it is not a well-formed wrapper, so malformed input
    degrades to the previous behaviour rather than vanishing.
    """
    if not (plaintext.startswith("$HEX[") and plaintext.endswith("]")):
        return plaintext
    try:
        return binascii.unhexlify(plaintext[5:-1]).decode("latin-1")
    except (binascii.Error, ValueError):
        return plaintext


def usable_plaintext(raw):
    """Return the password from a raw corpus line, or "" if there is none.

    Blank and whitespace-only lines are discarded. Leading hash fields are
    dropped and a ``$HEX[...]`` wrapper is decoded, both only when clearly
    present.
    """
    stripped = raw.strip()
    if not stripped:
        return ""
    stripped = strip_hash_prefix(stripped)
    if not stripped:
        return ""
    return decode_hex_wrapper(stripped)
