"""Tests for NTLM/NetNTLM hash preprocessing helpers (issues #27 and #28)."""

import os
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


class TestFilterComputerAccounts:
    """Issue #27 - filter accounts ending with $."""

    def test_removes_computer_accounts(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "COMPUTER1$:1002:aad3b435b51404ee:hash2:::\n"
            "user2:1003:aad3b435b51404ee:hash3:::\n"
            "WORKSTATION$:1004:aad3b435b51404ee:hash4:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 2
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2
        assert all("$" not in line.split(":", 1)[0] for line in lines)

    def test_no_computer_accounts(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "user2:1002:aad3b435b51404ee:hash2:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 0
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_all_computer_accounts(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "COMP1$:1001:aad3b435b51404ee:hash1:::\n"
            "COMP2$:1002:aad3b435b51404ee:hash2:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 2
        content = output_file.read_text().strip()
        assert content == ""

    def test_missing_file(self, tmp_path, main_module):
        removed = main_module._filter_computer_accounts(
            str(tmp_path / "nonexistent.txt"),
            str(tmp_path / "output.txt"),
        )
        assert removed == 0

    def test_empty_file(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("")
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 0


class TestDedupNetntlmByUsername:
    """Issue #28 - deduplicate NetNTLM hashes by username."""

    def test_removes_duplicates(self, tmp_path, main_module):
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user1::DOMAIN:challenge1:response1:blob1\n"
            "user2::DOMAIN:challenge2:response2:blob2\n"
            "user1::DOMAIN:challenge3:response3:blob3\n"
            "user3::DOMAIN:challenge4:response4:blob4\n"
            "user2::DOMAIN:challenge5:response5:blob5\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 5
        assert duplicates == 2
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 3
        # First occurrences should be kept
        assert "challenge1" in lines[0]
        assert "challenge2" in lines[1]
        assert "challenge4" in lines[2]

    def test_case_insensitive_dedup(self, tmp_path, main_module):
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "User1::DOMAIN:challenge1:response1:blob1\n"
            "USER1::DOMAIN:challenge2:response2:blob2\n"
            "user1::DOMAIN:challenge3:response3:blob3\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 3
        assert duplicates == 2
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_no_duplicates(self, tmp_path, main_module):
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user1::DOMAIN:challenge1:response1:blob1\n"
            "user2::DOMAIN:challenge2:response2:blob2\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 2
        assert duplicates == 0

    def test_missing_file(self, tmp_path, main_module):
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(tmp_path / "nonexistent.txt"),
            str(tmp_path / "output.txt"),
        )
        assert total == 0
        assert duplicates == 0

    def test_empty_file(self, tmp_path, main_module):
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text("")
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 0
        assert duplicates == 0
