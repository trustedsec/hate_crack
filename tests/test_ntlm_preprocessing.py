"""Tests for NTLM/NetNTLM hash preprocessing helpers (issues #27 and #28)."""

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


class TestCountComputerAccounts:
    """Issue #27 - count computer accounts (helper for detection)."""

    def test_counts_computer_accounts(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "COMPUTER1$:1002:aad3b435b51404ee:hash2:::\n"
            "user2:1003:aad3b435b51404ee:hash3:::\n"
            "WORKSTATION$:1004:aad3b435b51404ee:hash4:::\n"
        )
        assert main_module._count_computer_accounts(str(hash_file)) == 2

    def test_no_computer_accounts(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "user2:1002:aad3b435b51404ee:hash2:::\n"
        )
        assert main_module._count_computer_accounts(str(hash_file)) == 0

    def test_missing_file(self, tmp_path, main_module):
        assert main_module._count_computer_accounts(str(tmp_path / "nope.txt")) == 0

    def test_empty_file(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("")
        assert main_module._count_computer_accounts(str(hash_file)) == 0


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

    def test_malformed_lines(self, tmp_path, main_module):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "malformed_line_without_dollar\n"
            "COMP$:1002:aad3b435b51404ee:hash2:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_crlf_line_endings(self, tmp_path, main_module):
        """Test that CRLF (Windows) line endings are handled correctly."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_bytes(
            b"user1:1001:aad3b435b51404ee:hash1:::\r\n"
            b"COMPUTER1$:1002:aad3b435b51404ee:hash2:::\r\n"
            b"user2:1003:aad3b435b51404ee:hash3:::\r\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2
        # Verify no stray \r in output
        for line in lines:
            assert "\r" not in line


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
        # Output file should NOT be created when no duplicates exist
        assert not output_file.exists()

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
        assert not output_file.exists()

    def test_malformed_lines(self, tmp_path, main_module):
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user1::DOMAIN:challenge1:response1:blob1\n"
            "malformed_line_without_colons\n"
            "user2::DOMAIN:challenge2:response2:blob2\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 3
        assert duplicates == 0
        assert not output_file.exists()

    def test_crlf_line_endings(self, tmp_path, main_module):
        """Test that CRLF (Windows) line endings are handled correctly."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_bytes(
            b"user1::DOMAIN:challenge1:response1:blob1\r\n"
            b"user2::DOMAIN:challenge2:response2:blob2\r\n"
            b"user1::DOMAIN:challenge3:response3:blob3\r\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 3
        assert duplicates == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2
        # Verify no stray \r in output
        for line in lines:
            assert "\r" not in line


class TestWriteFieldSortedUnique:
    """Test _write_field_sorted_unique helper for extracting hash fields."""

    def test_extracts_nt_hashes_field_4(self, tmp_path, main_module):
        """Extract NT hashes (field 4) from pwdump format."""
        hash_file = tmp_path / "pwdump.txt"
        hash_file.write_text(
            "user1:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "user2:501:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "user3:502:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        )
        output_file = tmp_path / "nt.txt"
        result = main_module._write_field_sorted_unique(
            str(hash_file), str(output_file), 4, ":"
        )
        assert result is True
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2  # Two unique NT hashes
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" in lines
        assert "8846f7eaee8fb117ad06bdd830b7586c" in lines

    def test_extracts_lm_hashes_field_3(self, tmp_path, main_module):
        """Extract LM hashes (field 3) from pwdump format."""
        hash_file = tmp_path / "pwdump.txt"
        hash_file.write_text(
            "user1:500:e52cac67419a9a224a3b108f3fa6cb6d:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "user2:501:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "user3:502:e52cac67419a9a224a3b108f3fa6cb6d:abc123def456:::\n"
        )
        output_file = tmp_path / "lm.txt"
        result = main_module._write_field_sorted_unique(
            str(hash_file), str(output_file), 3, ":"
        )
        assert result is True
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2  # Two unique LM hashes
        assert "aad3b435b51404eeaad3b435b51404ee" in lines
        assert "e52cac67419a9a224a3b108f3fa6cb6d" in lines

    def test_sorts_and_deduplicates(self, tmp_path, main_module):
        """Verify sorting and deduplication."""
        hash_file = tmp_path / "pwdump.txt"
        hash_file.write_text(
            "user1:500:lm1:zzz:::\n"
            "user2:501:lm2:aaa:::\n"
            "user3:502:lm3:mmm:::\n"
            "user4:503:lm4:aaa:::\n"  # Duplicate NT hash
        )
        output_file = tmp_path / "nt.txt"
        main_module._write_field_sorted_unique(str(hash_file), str(output_file), 4, ":")
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 3
        assert lines == ["aaa", "mmm", "zzz"]  # Sorted alphabetically

    def test_handles_missing_fields(self, tmp_path, main_module):
        """Lines with fewer fields than requested should be skipped."""
        hash_file = tmp_path / "pwdump.txt"
        hash_file.write_text(
            "user1:500:lm1:nt1:::\n"
            "malformed:500\n"  # Only 2 fields
            "user2:501:lm2:nt2:::\n"
        )
        output_file = tmp_path / "nt.txt"
        main_module._write_field_sorted_unique(str(hash_file), str(output_file), 4, ":")
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2
        assert "nt1" in lines
        assert "nt2" in lines

    def test_missing_input_file(self, tmp_path, main_module):
        """Should return False when input file doesn't exist."""
        result = main_module._write_field_sorted_unique(
            str(tmp_path / "nonexistent.txt"), str(tmp_path / "output.txt"), 4, ":"
        )
        assert result is False

    def test_empty_file(self, tmp_path, main_module):
        """Empty input should create empty output."""
        hash_file = tmp_path / "empty.txt"
        hash_file.write_text("")
        output_file = tmp_path / "out.txt"
        result = main_module._write_field_sorted_unique(
            str(hash_file), str(output_file), 4, ":"
        )
        assert result is True
        assert output_file.read_text().strip() == ""


class TestPwdumpFilterPipeline:
    """Full pipeline tests: filter -> extract NT/LM -> verify output."""

    def test_full_pipeline_with_filtering(self, tmp_path, main_module):
        """Test complete flow: filter computer accounts, extract NT/LM hashes."""
        # Step 1: Create pwdump file with mixed accounts
        pwdump_file = tmp_path / "dump.txt"
        pwdump_file.write_text(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "DESKTOP-ABC$:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "john:1002:e52cac67419a9a224a3b108f3fa6cb6d:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
            "WORKSTATION$:1003:aad3b435b51404eeaad3b435b51404ee:deadbeefcafebabe1234567890abcdef:::\n"
            "alice:1004:aad3b435b51404eeaad3b435b51404ee:6cb75f652a9b52798eb6cf2201057c73:::\n"
        )

        # Step 2: Count computer accounts
        count = main_module._count_computer_accounts(str(pwdump_file))
        assert count == 2

        # Step 3: Filter computer accounts
        filtered_file = tmp_path / "dump.txt.filtered"
        removed = main_module._filter_computer_accounts(
            str(pwdump_file), str(filtered_file)
        )
        assert removed == 2

        # Step 4: Verify filtered file preserves complete pwdump format
        filtered_lines = filtered_file.read_text().strip().split("\n")
        assert len(filtered_lines) == 4
        for line in filtered_lines:
            # Each line should have pwdump format: user:uid:LM:NT:::
            parts = line.split(":")
            assert len(parts) == 7  # 7 fields total (6 colons)
            assert not parts[0].endswith("$")  # No computer accounts

        # Step 5: Extract NT hashes from filtered file
        nt_file = tmp_path / "dump.txt.filtered.nt"
        result = main_module._write_field_sorted_unique(
            str(filtered_file), str(nt_file), 4, ":"
        )
        assert result is True

        # Step 6: Verify NT hashes are correct and don't include computer account hashes
        nt_hashes = nt_file.read_text().strip().split("\n")
        assert len(nt_hashes) == 3  # Three unique NT hashes from non-computer accounts
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" in nt_hashes  # Admin/Guest empty hash
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in nt_hashes  # john's hash
        assert "6cb75f652a9b52798eb6cf2201057c73" in nt_hashes  # alice's hash
        # Computer account hashes should NOT be present
        assert "8846f7eaee8fb117ad06bdd830b7586c" not in nt_hashes
        assert "deadbeefcafebabe1234567890abcdef" not in nt_hashes

        # Step 7: Extract LM hashes from filtered file
        lm_file = tmp_path / "dump.txt.filtered.lm"
        result = main_module._write_field_sorted_unique(
            str(filtered_file), str(lm_file), 3, ":"
        )
        assert result is True

        # Step 8: Verify LM hashes are correct
        lm_hashes = lm_file.read_text().strip().split("\n")
        assert len(lm_hashes) == 2  # Two unique LM hashes
        assert (
            "aad3b435b51404eeaad3b435b51404ee" in lm_hashes
        )  # Empty LM (Admin/Guest/alice)
        assert "e52cac67419a9a224a3b108f3fa6cb6d" in lm_hashes  # john's LM

    def test_pipeline_without_filtering(self, tmp_path, main_module):
        """Test pipeline when no computer accounts exist."""
        pwdump_file = tmp_path / "dump.txt"
        pwdump_file.write_text(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "john:1002:e52cac67419a9a224a3b108f3fa6cb6d:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
            "alice:1004:aad3b435b51404eeaad3b435b51404ee:6cb75f652a9b52798eb6cf2201057c73:::\n"
        )

        # Count should be zero
        count = main_module._count_computer_accounts(str(pwdump_file))
        assert count == 0

        # Extract NT directly from original file (simulate no filtering step)
        nt_file = tmp_path / "dump.txt.nt"
        main_module._write_field_sorted_unique(str(pwdump_file), str(nt_file), 4, ":")

        nt_hashes = nt_file.read_text().strip().split("\n")
        assert len(nt_hashes) == 3
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" in nt_hashes
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in nt_hashes
        assert "6cb75f652a9b52798eb6cf2201057c73" in nt_hashes

    def test_pipeline_with_realistic_hashes(self, tmp_path, main_module):
        """Test with realistic Active Directory pwdump data."""
        pwdump_file = tmp_path / "ad_dump.txt"
        pwdump_file.write_text(
            # Real format examples
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:d3c02561bba6ee4ad6cfd024ec8fda5d:::\n"
            "CORP-DC01$:1000:aad3b435b51404eeaad3b435b51404ee:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6:::\n"
            "CORP-WKS01$:1001:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::\n"
            "jdoe:1102:e52cac67419a9a224a3b108f3fa6cb6d:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "CORP-SRV01$:1003:aad3b435b51404eeaad3b435b51404ee:fedcba0987654321fedcba0987654321:::\n"
            "asmith:1103:aad3b435b51404eeaad3b435b51404ee:2b2ac52d43a3d5c5c5b5b5f5e5d5c5a5:::\n"
        )

        # Count computer accounts (domain controllers, workstations, servers)
        count = main_module._count_computer_accounts(str(pwdump_file))
        assert count == 3

        # Filter them out
        filtered_file = tmp_path / "ad_dump.txt.filtered"
        removed = main_module._filter_computer_accounts(
            str(pwdump_file), str(filtered_file)
        )
        assert removed == 3

        # Extract NT hashes
        nt_file = tmp_path / "ad_dump.txt.filtered.nt"
        main_module._write_field_sorted_unique(str(filtered_file), str(nt_file), 4, ":")

        nt_hashes = nt_file.read_text().strip().split("\n")
        assert len(nt_hashes) == 4  # Four unique NT hashes from user accounts
        # Verify no computer account hashes leaked through
        assert "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" not in nt_hashes
        assert "1234567890abcdef1234567890abcdef" not in nt_hashes
        assert "fedcba0987654321fedcba0987654321" not in nt_hashes

    def test_pipeline_with_bom(self, tmp_path, main_module):
        """Test that BOM character doesn't break filtering."""
        pwdump_file = tmp_path / "bom_dump.txt"
        # Note: The main.py code strips BOM at line 3672 but _filter_computer_accounts
        # doesn't handle it. This tests if that causes issues.
        pwdump_file.write_text(
            "\ufeffAdministrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "COMPUTER$:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "john:1002:e52cac67419a9a224a3b108f3fa6cb6d:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
        )

        filtered_file = tmp_path / "bom_dump.txt.filtered"
        removed = main_module._filter_computer_accounts(
            str(pwdump_file), str(filtered_file)
        )
        assert removed == 1

        filtered_lines = filtered_file.read_text().strip().split("\n")
        # BOM should be preserved in first line since filter doesn't strip it
        assert len(filtered_lines) == 2
        # First username might have BOM attached
        first_username = filtered_lines[0].split(":", 1)[0]
        # BOM gets written through, so we check it's either with or without
        assert "Administrator" in first_username

    def test_pipeline_preserves_all_fields(self, tmp_path, main_module):
        """Verify filtered file maintains exact pwdump structure."""
        pwdump_file = tmp_path / "structure.txt"
        pwdump_file.write_text(
            "user1:500:LM1:NT1:extra1:extra2:extra3\n"
            "COMP$:501:LM2:NT2:extra4:extra5:extra6\n"
            "user2:502:LM3:NT3:extra7:extra8:extra9\n"
        )

        filtered_file = tmp_path / "structure.txt.filtered"
        main_module._filter_computer_accounts(str(pwdump_file), str(filtered_file))

        filtered_lines = filtered_file.read_text().strip().split("\n")
        assert len(filtered_lines) == 2

        # Each line should have exactly 7 fields
        for line in filtered_lines:
            assert line.count(":") == 6
            parts = line.split(":")
            assert len(parts) == 7

    def test_pipeline_empty_username_edge_case(self, tmp_path, main_module):
        """Test handling of lines with empty username field."""
        pwdump_file = tmp_path / "empty_user.txt"
        pwdump_file.write_text(
            "user1:500:lm1:nt1:::\n"
            ":501:lm2:nt2:::\n"  # Empty username
            "COMP$:502:lm3:nt3:::\n"
            "user2:503:lm4:nt4:::\n"
        )

        count = main_module._count_computer_accounts(str(pwdump_file))
        assert count == 1  # Only COMP$ should count

        filtered_file = tmp_path / "empty_user.txt.filtered"
        removed = main_module._filter_computer_accounts(
            str(pwdump_file), str(filtered_file)
        )
        assert removed == 1

        filtered_lines = filtered_file.read_text().strip().split("\n")
        assert len(filtered_lines) == 3  # Empty username line should be kept

    def test_pipeline_with_duplicate_hashes_across_accounts(
        self, tmp_path, main_module
    ):
        """Verify deduplication works correctly when multiple users share hashes."""
        pwdump_file = tmp_path / "dup_hashes.txt"
        pwdump_file.write_text(
            "user1:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "user2:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"  # Same hash
            "COMP$:502:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "user3:503:e52cac67419a9a224a3b108f3fa6cb6d:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"  # Same NT, different LM
        )

        filtered_file = tmp_path / "dup_hashes.txt.filtered"
        main_module._filter_computer_accounts(str(pwdump_file), str(filtered_file))

        nt_file = tmp_path / "dup_hashes.txt.filtered.nt"
        main_module._write_field_sorted_unique(str(filtered_file), str(nt_file), 4, ":")

        nt_hashes = nt_file.read_text().strip().split("\n")
        # Should have only 1 unique NT hash (31d6cfe0d16ae931b73c59d7e0c089c0)
        assert len(nt_hashes) == 1
        assert nt_hashes[0] == "31d6cfe0d16ae931b73c59d7e0c089c0"

        lm_file = tmp_path / "dup_hashes.txt.filtered.lm"
        main_module._write_field_sorted_unique(str(filtered_file), str(lm_file), 3, ":")

        lm_hashes = lm_file.read_text().strip().split("\n")
        # Should have 2 unique LM hashes
        assert len(lm_hashes) == 2
        assert "aad3b435b51404eeaad3b435b51404ee" in lm_hashes
        assert "e52cac67419a9a224a3b108f3fa6cb6d" in lm_hashes
