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

Surrounding whitespace is a third case, and it is the one place these functions
are deliberately lossy by default. :func:`usable_plaintext` strips it, because
most callers want a token to count or to show a model and a stray space there is
noise. But a leading or trailing space can genuinely be part of a password —
0.06% of a sampled corpus — and a caller that has to reproduce the password
exactly cannot afford to lose it, so ``keep_whitespace=True`` turns the
stripping off. The default stays as it is because three callers share this
function (rulegen, corpus_stats, llm) and only one of them needs the exact
bytes; changing the default would alter the other two silently.

This module deliberately has no imports from the rest of the package so both
rulegen and corpus_stats can depend on it.
"""

import binascii

# Magic bytes at the start of every gzip stream (RFC 1952 SS1FLG SS2FLG).
_GZIP_MAGIC = b"\x1f\x8b"


def is_gzipped(path: str) -> bool:
    """True if *path* starts with the gzip magic bytes.

    Filename extensions lie: hate_crack downloads wordlists as gzip and names
    them from a server-supplied ``Content-Disposition`` header, so a
    compressed body routinely lands under a plain ``.txt`` name. Checking the
    actual bytes is the only way to catch that before handing raw gzip data to
    an external binary that expects text.
    """
    try:
        with open(path, "rb") as f:
            return f.read(2) == _GZIP_MAGIC
    except OSError:
        return False


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


def encode_hex_wrapper(raw):
    """Return *raw* password bytes as text, wrapping in ``$HEX[...]`` if needed.

    The inverse of :func:`decode_hex_wrapper`, and the safe way to move a
    cracked plaintext out of a byte stream and into a text file. Bytes that are
    not valid UTF-8 — a Latin-1 accent, a Windows-1252 quote, anything hashcat
    emitted raw — cannot be decoded without loss, so they are hex-wrapped
    exactly as hashcat itself would. Decoding such a plaintext with
    ``errors="ignore"`` instead yields a *different* password with no error.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return "$HEX[" + raw.hex() + "]"


def usable_plaintext(raw, *, keep_whitespace=False):
    """Return the password from a raw corpus line, or "" if there is none.

    Blank and whitespace-only lines are discarded. Leading hash fields are
    dropped and a ``$HEX[...]`` wrapper is decoded, both only when clearly
    present.

    ``keep_whitespace`` keeps a leading or trailing space that is part of the
    password, stripping only the line's own ``\\r``/``\\n`` terminator. The
    default is False, and stays False, because most callers only want a token
    to count or to feed a model, where a stray space is noise; a caller that
    has to reproduce the password *exactly* — :func:`hate_crack.rulegen.generate`,
    whose whole output is a baseword plus a rule that must rebuild it byte for
    byte — opts in. Left on by default, the space is discarded silently and
    even the reconstruction self-check passes, because it compares against the
    already-stripped password.

    Blank detection uses the un-stripped line either way, so a whitespace-only
    line is still discarded rather than becoming a password made of spaces.

    Leading whitespace is decided rather than kept blindly, because keeping it
    blindly would defeat the two undo steps above: an indented line puts the
    space *in front of* the hash field and the ``$HEX[`` marker, so neither
    detector matches and the whole line becomes the password. Both detectors
    therefore run against the un-indented form, and the indent is re-attached
    only when neither of them matched — that is, only when nothing about the
    line suggests the indent is formatting rather than password. A space
    *after* the separator is a different question and is always kept: it is
    inside the plaintext field, which is exactly where a password's own
    leading space appears.
    """
    if not raw.strip():
        return ""
    if not keep_whitespace:
        text = strip_hash_prefix(raw.strip())
        if not text:
            return ""
        return decode_hex_wrapper(text)

    text = raw.rstrip("\r\n")
    body = text.lstrip()

    unprefixed = strip_hash_prefix(body)
    if unprefixed != body:
        # A leading hash field was consumed, so the indent sat in front of a
        # hash and is line formatting. Everything after the separator is the
        # password, a leading space included.
        if not unprefixed:
            return ""
        return decode_hex_wrapper(unprefixed)

    decoded = decode_hex_wrapper(body)
    if decoded != body:
        # A wrapper encodes any whitespace of its own *inside* the hex, so an
        # indent outside it cannot be part of the password either.
        return decoded

    # Neither matched: nothing here says the leading whitespace is anything but
    # part of the password, so keep the line as it came in.
    return text
