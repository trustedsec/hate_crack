"""Unit tests for hate_crack.plaintext — recovering the password from a line."""

import os

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import plaintext  # noqa: E402

NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"  # 32
SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40
LM = "aad3b435b51404ee"  # 16
# The empty-LM constant present on every account in an NTDS dump.
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
BCRYPT = "$2y$10$abcdefghijklmnopqrstuv"


# --------------------------------------------------------------------------
# is_hash_token
# --------------------------------------------------------------------------


@pytest.mark.parametrize("token", [NTLM, SHA1, LM, BCRYPT, NTLM.upper()])
def test_recognizes_hash_shaped_tokens(token):
    assert plaintext.is_hash_token(token)


@pytest.mark.parametrize(
    "token",
    [
        "",
        "aabbcc",  # hex, but no digest is 6 characters
        "deadbeef",  # ditto, 8
        "abcdefghijklmnopqrstuvwxyzabcdef",  # 32 chars but not hex
        "31d6cfe0d16ae931b73c59d7e0c089c",  # 31 — one short of NTLM
        "$HEX[68656c6c6f]",  # a wrapped plaintext, not a hash
        "alpha",
    ],
)
def test_rejects_non_hash_tokens(token):
    assert not plaintext.is_hash_token(token)


# --------------------------------------------------------------------------
# strip_hash_prefix
# --------------------------------------------------------------------------


def test_strips_a_single_hash_field():
    assert plaintext.strip_hash_prefix(f"{NTLM}:token1") == "token1"


def test_strips_multiple_leading_hash_fields():
    """hashcat writes hash:salt:plain for salted algorithms."""
    assert plaintext.strip_hash_prefix(f"{LM}:{NTLM}:token1") == "token1"


def test_keeps_colons_inside_the_plaintext():
    assert plaintext.strip_hash_prefix(f"{NTLM}:frag:ment") == "frag:ment"


def test_leaves_a_line_with_no_hash_field_intact():
    """A wordlist entry may hold a colon — a URL, a ratio, a time of day."""
    for line in ("aabbcc:token1", "12:30", "ratio:1:2", "scheme://host/path"):
        assert plaintext.strip_hash_prefix(line) == line


def test_line_without_a_colon_is_returned_as_is():
    assert plaintext.strip_hash_prefix("token1") == "token1"


def test_trailing_colon_after_a_hash_yields_nothing():
    assert plaintext.strip_hash_prefix(f"{NTLM}:") == ""


def test_never_consumes_the_final_field():
    """Even if the plaintext itself looks like a digest, something must remain."""
    assert plaintext.strip_hash_prefix(f"{NTLM}:{SHA1}") == SHA1


# --------------------------------------------------------------------------
# decode_hex_wrapper
# --------------------------------------------------------------------------


def test_decodes_a_hex_wrapper():
    assert plaintext.decode_hex_wrapper("$HEX[68656c6c6f]") == "hello"


def test_decodes_high_bytes_one_byte_per_character():
    """Byte-per-character, because hashcat rules address bytes, not codepoints."""
    decoded = plaintext.decode_hex_wrapper("$HEX[76c3a477]")
    assert decoded == "v\xc3\xa4w"
    assert len(decoded) == 4


@pytest.mark.parametrize(
    "value",
    [
        "$HEX[nothex]",
        "$HEX[abc]",  # odd length
        "$HEX[6865",  # unterminated
        "$HEXX[6865]",
        "notawrapper",
    ],
)
def test_malformed_wrapper_passes_through(value):
    assert plaintext.decode_hex_wrapper(value) == value


# --------------------------------------------------------------------------
# usable_plaintext
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("token1\n", "token1"),
        ("  token1  \n", "token1"),
        ("", ""),
        ("   \t ", ""),
        (f"{NTLM}:token1", "token1"),
        (f"{NTLM}:", ""),
        (f"{NTLM}:$HEX[68656c6c6f]", "hello"),
        ("$HEX[68656c6c6f]", "hello"),
        ("aabbcc:token1", "aabbcc:token1"),
    ],
)
def test_usable_plaintext(raw, expected):
    assert plaintext.usable_plaintext(raw) == expected


# --------------------------------------------------------------------------
# looks_like_hash_line
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "line",
    [
        f"user:1103:{EMPTY_LM}:{NTLM}:::",
        f"{NTLM}",  # a bare digest with no plaintext after it
        f"{EMPTY_LM}:x",
    ],
)
def test_flags_uncracked_dump_lines(line):
    assert plaintext.looks_like_hash_line(line)


@pytest.mark.parametrize(
    "line",
    [
        "Alpha2024!",
        f"{NTLM}:Alpha2024!",  # cracked: has a plaintext
        "correct horse battery staple",
        "deadbeef",
        "aabbcc:token1",
    ],
)
def test_does_not_flag_cracked_or_plain_lines(line):
    assert not plaintext.looks_like_hash_line(line)


# --------------------------------------------------------------------------
# encode_hex_wrapper
# --------------------------------------------------------------------------


def test_encode_hex_wrapper_passes_through_valid_utf8():
    assert plaintext.encode_hex_wrapper(b"Alpha2024!") == "Alpha2024!"
    assert plaintext.encode_hex_wrapper("café".encode("utf-8")) == "café"


def test_encode_hex_wrapper_wraps_undecodable_bytes():
    raw = b"abc\xffdef"
    assert plaintext.encode_hex_wrapper(raw) == "$HEX[616263ff646566]"
    # Round trip: the wrapper decodes back to the same bytes.
    assert (
        plaintext.decode_hex_wrapper(plaintext.encode_hex_wrapper(raw)).encode(
            "latin-1"
        )
        == raw
    )
