"""Tests for the ``username:hash`` format detection and ``--username`` injection.

Covers both the pure-logic ``detect_username_hash_format`` function and the
command-building integration point in ``_append_potfile_arg`` /
``_maybe_append_username_flag``.
"""

from __future__ import annotations

import sys
import importlib
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def main_module(monkeypatch):
    """Load hate_crack.main with SKIP_INIT to access helpers directly."""
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    if "hate_crack.main" in sys.modules:
        mod = sys.modules["hate_crack.main"]
        importlib.reload(mod)
        return mod
    import hate_crack.main as mod

    return mod


@pytest.fixture
def detect():
    """Return the pure-logic detection function."""
    from hate_crack.username_detect import detect_username_hash_format

    return detect_username_hash_format


def _make_mock_proc():
    proc = MagicMock()
    proc.wait.return_value = None
    proc.pid = 12345
    return proc


# ---------------------------------------------------------------------------
# Unit tests: detect_username_hash_format
# ---------------------------------------------------------------------------


class TestDetectPositiveCases:
    """Per-mode positive cases: sample matches ``user:<hex>`` with correct length."""

    def test_md5_user_hash(self, tmp_path, detect):
        f = tmp_path / "md5.txt"
        f.write_text("alice:5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert detect(str(f), "0") is True

    def test_sha1_user_hash(self, tmp_path, detect):
        f = tmp_path / "sha1.txt"
        f.write_text("alice:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n")
        assert detect(str(f), "100") is True

    def test_sha256_user_hash(self, tmp_path, detect):
        f = tmp_path / "sha256.txt"
        f.write_text(
            "bob:5e884898da28047151d0e56f8dc6292773603d0d"
            "6aabbdd62a11ef721d1542d8\n"
        )
        assert detect(str(f), "1400") is True

    def test_sha512_user_hash(self, tmp_path, detect):
        f = tmp_path / "sha512.txt"
        f.write_text(
            "carol:b109f3bbbc244eb82441917ed06d618b9008dd09b"
            "3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df"
            "5f1326af5a2ea6d103fd07c95385ffab0cacbc86\n"
        )
        assert detect(str(f), "1700") is True

    def test_ntlm_user_hash(self, tmp_path, detect):
        f = tmp_path / "ntlm.txt"
        # Mode 1000 with user:hash shape is a legitimate hashcat input.
        f.write_text("alice:aad3b435b51404eeaad3b435b51404ee\n")
        assert detect(str(f), "1000") is True

    def test_lm_user_hash(self, tmp_path, detect):
        f = tmp_path / "lm.txt"
        f.write_text("alice:aad3b435b51404ee\n")
        assert detect(str(f), "3000") is True

    def test_multiple_lines_all_match(self, tmp_path, detect):
        f = tmp_path / "md5.txt"
        f.write_text(
            "alice:5f4dcc3b5aa765d61d8327deb882cf99\n"
            "bob:e10adc3949ba59abbe56e057f20f883e\n"
            "carol:25f9e794323b453885f5181f1b624d0b\n"
        )
        assert detect(str(f), "0") is True


class TestDetectNegativeCases:
    """Detection must return False on non-matching content."""

    def test_bare_hashes_no_colon(self, tmp_path, detect):
        f = tmp_path / "bare.txt"
        f.write_text("5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert detect(str(f), "0") is False

    def test_wrong_hex_length(self, tmp_path, detect):
        """SHA1-length hex with MD5 hash type must not match."""
        f = tmp_path / "wrong.txt"
        f.write_text("alice:5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8\n")
        assert detect(str(f), "0") is False

    def test_non_hex_field2(self, tmp_path, detect):
        f = tmp_path / "nonhex.txt"
        f.write_text("alice:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ\n")
        assert detect(str(f), "0") is False

    def test_mixed_valid_and_invalid(self, tmp_path, detect):
        """All sampled lines must match; one bad line fails detection."""
        f = tmp_path / "mixed.txt"
        f.write_text(
            "alice:5f4dcc3b5aa765d61d8327deb882cf99\n"
            "bob:not_a_hash_at_all\n"
        )
        assert detect(str(f), "0") is False

    def test_pwdump_format_mode_1000(self, tmp_path, detect):
        """pwdump (user:RID:LM:NT:::) has a numeric field 2, not hex."""
        f = tmp_path / "pwdump.txt"
        f.write_text(
            "user1:1001:aad3b435b51404eeaad3b435b51404ee"
            ":31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        assert detect(str(f), "1000") is False

    def test_trailing_garbage_after_hash(self, tmp_path, detect):
        """Anchored regex must reject lines with extra trailing fields."""
        f = tmp_path / "trailing.txt"
        f.write_text("alice:5f4dcc3b5aa765d61d8327deb882cf99:extra\n")
        assert detect(str(f), "0") is False


class TestDetectBlocklist:
    """Blocklisted modes must return False regardless of content."""

    @pytest.mark.parametrize(
        "mode", ["2500", "22000", "5300", "5400", "5500", "5600", "1800", "3200"]
    )
    def test_blocklist_modes(self, tmp_path, detect, mode):
        f = tmp_path / "any.txt"
        # Content that *looks* like a user:md5-hash, still blocked.
        f.write_text("alice:5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert detect(str(f), mode) is False


class TestDetectUnknownMode:
    def test_unknown_mode_returns_false(self, tmp_path, detect):
        f = tmp_path / "x.txt"
        f.write_text("alice:5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert detect(str(f), "99999") is False


class TestDetectFileHandling:
    def test_missing_file(self, tmp_path, detect):
        assert detect(str(tmp_path / "does_not_exist.txt"), "0") is False

    def test_empty_file(self, tmp_path, detect):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert detect(str(f), "0") is False

    def test_only_blank_lines(self, tmp_path, detect):
        f = tmp_path / "blank.txt"
        f.write_text("\n\n\n")
        assert detect(str(f), "0") is False

    def test_only_comments(self, tmp_path, detect):
        f = tmp_path / "comments.txt"
        f.write_text("# just a comment\n# another\n")
        assert detect(str(f), "0") is False

    def test_blank_leading_lines_skipped(self, tmp_path, detect):
        f = tmp_path / "b.txt"
        f.write_text("\n\nalice:5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert detect(str(f), "0") is True

    def test_comment_lines_skipped(self, tmp_path, detect):
        f = tmp_path / "c.txt"
        f.write_text(
            "# sample file\nalice:5f4dcc3b5aa765d61d8327deb882cf99\n"
            "bob:e10adc3949ba59abbe56e057f20f883e\n"
        )
        assert detect(str(f), "0") is True

    def test_bom_handled(self, tmp_path, detect):
        f = tmp_path / "bom.txt"
        f.write_bytes(
            b"\xef\xbb\xbfalice:5f4dcc3b5aa765d61d8327deb882cf99\n"
        )
        assert detect(str(f), "0") is True

    def test_crlf_handled(self, tmp_path, detect):
        f = tmp_path / "crlf.txt"
        f.write_bytes(b"alice:5f4dcc3b5aa765d61d8327deb882cf99\r\n")
        assert detect(str(f), "0") is True

    def test_null_bytes_stripped(self, tmp_path, detect):
        f = tmp_path / "null.txt"
        f.write_bytes(b"alice\x00:5f4dcc3b5aa765d61d8327deb882cf99\n")
        assert detect(str(f), "0") is True

    def test_unicode_username(self, tmp_path, detect):
        f = tmp_path / "u.txt"
        f.write_text(
            "alicé:5f4dcc3b5aa765d61d8327deb882cf99\n", encoding="utf-8"
        )
        assert detect(str(f), "0") is True


class TestDetectSampleSize:
    def test_sample_size_honored(self, tmp_path, detect):
        """With sample_size=3, a later bad line is not read and detection passes."""
        lines = ["alice:5f4dcc3b5aa765d61d8327deb882cf99\n"] * 3
        lines += ["bob:not_a_valid_hash\n"] * 47
        f = tmp_path / "big.txt"
        f.write_text("".join(lines))
        assert detect(str(f), "0", sample_size=3) is True
        # With sample_size large enough to read the bad lines, it fails.
        assert detect(str(f), "0", sample_size=10) is False


# ---------------------------------------------------------------------------
# Integration tests: --username injection via _append_potfile_arg
# ---------------------------------------------------------------------------


class TestAppendUsernameFlag:
    """_append_potfile_arg should append --username when hcatUsernamePrefix."""

    def test_append_when_flag_true(self, main_module):
        cmd = ["hashcat", "-m", "0", "hashes.txt"]
        with patch.object(main_module, "hcatUsernamePrefix", True), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "_debug_cmd"):
            main_module._append_potfile_arg(cmd)
        assert "--username" in cmd

    def test_no_append_when_flag_false(self, main_module):
        cmd = ["hashcat", "-m", "0", "hashes.txt"]
        with patch.object(main_module, "hcatUsernamePrefix", False), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "_debug_cmd"):
            main_module._append_potfile_arg(cmd)
        assert "--username" not in cmd

    def test_no_duplicate_when_tuning_adds_username(self, main_module):
        """If --username is already in cmd (e.g. from hcatTuning), don't add a second."""
        cmd = ["hashcat", "-m", "0", "hashes.txt", "--username"]
        with patch.object(main_module, "hcatUsernamePrefix", True), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "_debug_cmd"):
            main_module._append_potfile_arg(cmd)
        assert cmd.count("--username") == 1

    def test_append_with_use_potfile_path_false(self, main_module):
        """When potfile handling is disabled, --username must still be injected."""
        cmd = ["hashcat", "-m", "0", "hashes.txt"]
        with patch.object(main_module, "hcatUsernamePrefix", True), \
             patch.object(main_module, "_debug_cmd"):
            main_module._append_potfile_arg(cmd, use_potfile_path=False)
        assert "--username" in cmd


class TestUsernameInjectionIntoBruteForce:
    """End-to-end: hcatBruteForce cmd contains --username when flag is set."""

    def test_brute_force_contains_username_when_flag_set(
        self, main_module, tmp_path
    ):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatUsernamePrefix", True), \
             patch.object(main_module, "generate_session_id", return_value="sess"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mp, \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("0", hash_file, 1, 7)
        cmd = mp.call_args[0][0]
        assert "--username" in cmd

    def test_brute_force_no_username_when_flag_unset(
        self, main_module, tmp_path
    ):
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatUsernamePrefix", False), \
             patch.object(main_module, "generate_session_id", return_value="sess"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mp, \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("0", hash_file, 1, 7)
        cmd = mp.call_args[0][0]
        assert "--username" not in cmd

    def test_brute_force_duplicate_guard_via_tuning(
        self, main_module, tmp_path
    ):
        """hcatTuning='--username' with the flag set must not duplicate."""
        hash_file = str(tmp_path / "hashes.txt")
        mock_proc = _make_mock_proc()

        with patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", "--username"), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatUsernamePrefix", True), \
             patch.object(main_module, "generate_session_id", return_value="sess"), \
             patch("hate_crack.main.subprocess.Popen", return_value=mock_proc) as mp, \
             patch.object(main_module, "lineCount", return_value=0):
            main_module.hcatBruteForce("0", hash_file, 1, 7)
        cmd = mp.call_args[0][0]
        assert cmd.count("--username") == 1
