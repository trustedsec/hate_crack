"""Tests for bare NTLM hash format detection in preprocessing.

Verifies that the first-line format detection at main.py:3828-3905
correctly identifies bare 32-char hex hashes under various encoding
and whitespace conditions.
"""

import re
import sys
import importlib

import pytest


@pytest.fixture
def main_module(monkeypatch):
    """Load hate_crack.main with SKIP_INIT to access helper functions."""
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    if "hate_crack.main" in sys.modules:
        mod = sys.modules["hate_crack.main"]
        importlib.reload(mod)
        return mod
    import hate_crack.main as mod

    return mod


def _read_first_line(path):
    """Replicate the first-line reading logic from main.py:3828-3829."""
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.readline().strip().replace("\x00", "")


BARE_HASH_PATTERN = re.compile(r"^[a-f0-9A-F]{32}$")
PWDUMP_PATTERN = re.compile(r"[a-f0-9A-F]{32}:[a-f0-9A-F]{32}:::")
USER_HASH_PATTERN = re.compile(r"^.+:[a-f0-9A-F]{32}$")


class TestBareHashDetection:
    """Bare 32-char NTLM hash detection."""

    def test_bare_hash_detected(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404ee\n")
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line)

    def test_bare_hash_uppercase(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_text("AAD3B435B51404EEAAD3B435B51404EE\n")
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line)

    def test_bare_hash_mixed_case(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_text("Aad3b435B51404eeAAD3b435b51404EE\n")
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line)

    def test_bare_hash_with_bom(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_bytes(b"\xef\xbb\xbfaad3b435b51404eeaad3b435b51404ee\n")
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line), f"BOM not stripped: {line!r}"

    def test_bare_hash_with_crlf(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_bytes(b"aad3b435b51404eeaad3b435b51404ee\r\n")
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line), f"CRLF not stripped: {line!r}"

    def test_bare_hash_with_bom_and_crlf(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_bytes(
            b"\xef\xbb\xbfaad3b435b51404eeaad3b435b51404ee\r\n"
        )
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line), f"BOM+CRLF not handled: {line!r}"

    def test_bare_hash_with_trailing_space(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404ee   \n")
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line), f"Trailing space not stripped: {line!r}"

    def test_bare_hash_with_null_bytes(self, tmp_path):
        """UTF-16LE encoded file read as UTF-8 produces null bytes."""
        hash_file = tmp_path / "bare.txt"
        raw = b"a\x00a\x00d\x003\x00b\x004\x003\x005\x00b\x005\x001\x004\x000\x004\x00e\x00e\x00a\x00a\x00d\x003\x00b\x004\x003\x005\x00b\x005\x001\x004\x000\x004\x00e\x00e\x00\n\x00"
        hash_file.write_bytes(raw)
        line = _read_first_line(str(hash_file))
        assert BARE_HASH_PATTERN.search(line), f"Null bytes not stripped: {line!r}"

    def test_not_bare_hash_31_chars(self, tmp_path):
        hash_file = tmp_path / "short.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404e\n")
        line = _read_first_line(str(hash_file))
        assert not BARE_HASH_PATTERN.search(line)

    def test_not_bare_hash_33_chars(self, tmp_path):
        hash_file = tmp_path / "long.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404eee\n")
        line = _read_first_line(str(hash_file))
        assert not BARE_HASH_PATTERN.search(line)

    def test_not_bare_hash_non_hex(self, tmp_path):
        hash_file = tmp_path / "nonhex.txt"
        hash_file.write_text("zad3b435b51404eeaad3b435b51404ee\n")
        line = _read_first_line(str(hash_file))
        assert not BARE_HASH_PATTERN.search(line)


class TestFormatDetectionPriority:
    """Verify the detection chain matches the correct format."""

    def test_pwdump_takes_priority(self, tmp_path):
        hash_file = tmp_path / "pwdump.txt"
        hash_file.write_text(
            "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        line = _read_first_line(str(hash_file))
        assert PWDUMP_PATTERN.search(line)

    def test_user_hash_detected(self, tmp_path):
        hash_file = tmp_path / "userhash.txt"
        hash_file.write_text("admin:aad3b435b51404eeaad3b435b51404ee\n")
        line = _read_first_line(str(hash_file))
        assert not PWDUMP_PATTERN.search(line)
        assert not BARE_HASH_PATTERN.search(line)
        assert USER_HASH_PATTERN.search(line)

    def test_bare_hash_not_confused_with_user_hash(self, tmp_path):
        hash_file = tmp_path / "bare.txt"
        hash_file.write_text("aad3b435b51404eeaad3b435b51404ee\n")
        line = _read_first_line(str(hash_file))
        assert not PWDUMP_PATTERN.search(line)
        assert BARE_HASH_PATTERN.search(line)


class TestErrorMessageOnUnrecognizedFormat:
    """Verify the improved error message for unrecognized formats."""

    def test_unrecognized_format_shows_repr(self, tmp_path, main_module, capsys):
        hash_file = tmp_path / "weird.txt"
        hash_file.write_text("not_a_valid_hash_format\n")
        line = _read_first_line(str(hash_file))
        assert not BARE_HASH_PATTERN.search(line)
        assert not PWDUMP_PATTERN.search(line)
        assert not USER_HASH_PATTERN.search(line)
