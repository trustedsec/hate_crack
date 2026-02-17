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


class TestE2EPreprocessingFlow:
    """End-to-end tests that simulate the actual main() preprocessing flow.

    These tests replicate the exact logic from main.py lines 3698-3747,
    exercising the full chain: format detection -> computer account filtering
    -> NT/LM hash extraction -> final hcatHashFile assignment.
    """

    @staticmethod
    def _run_preprocessing(main_module, hash_file_path, input_responses):
        """Simulate the main() preprocessing block for hash type 1000.

        Replicates the exact flow from main.py:
        1. Read first line, detect pwdump format
        2. Count computer accounts, prompt to filter
        3. Extract NT and LM hashes via _write_field_sorted_unique
        4. Return the final hcatHashFile path and metadata

        Args:
            main_module: The hate_crack.main module
            hash_file_path: Path to the pwdump hash file
            input_responses: List of responses for input() calls
                (e.g., ["Y"] to accept filtering, ["N"] to decline)

        Returns:
            dict with keys: hcatHashFile, hcatHashFileOrig, pwdump_format,
                lmHashesFound, filtered_path, nt_file, lm_file
        """
        import re

        input_iter = iter(input_responses)

        hcatHashFile = str(hash_file_path)
        hcatHashFileOrig = None
        pwdump_format = False
        lmHashesFound = False
        filtered_path = None

        # Read first line (same as main.py line 3702-3703)
        with open(hcatHashFile, "r") as f:
            hcatHashFileLine = f.readline().strip().lstrip("\ufeff")

        # Detect pwdump format (same regex as main.py line 3704)
        if re.search(r"[a-f0-9A-F]{32}:[a-f0-9A-F]{32}:::", hcatHashFileLine):
            pwdump_format = True

            # Count and optionally filter computer accounts
            computer_count = main_module._count_computer_accounts(hcatHashFile)
            if computer_count > 0:
                filter_choice = next(input_iter, "Y")
                if filter_choice.upper() == "Y":
                    filtered_path = f"{hcatHashFile}.filtered"
                    main_module._filter_computer_accounts(hcatHashFile, filtered_path)
                    hcatHashFile = filtered_path

            # Extract NT hashes (field 4) - same as main.py line 3726
            main_module._write_field_sorted_unique(
                hcatHashFile, f"{hcatHashFile}.nt", 4
            )
            # Extract LM hashes (field 3) - same as main.py line 3728
            main_module._write_field_sorted_unique(
                hcatHashFile, f"{hcatHashFile}.lm", 3
            )

            # Check for LM hashes (same logic as main.py lines 3729-3735)
            lm_count = main_module.lineCount(hcatHashFile + ".lm")
            if (
                lm_count == 1
                and hcatHashFileLine.split(":")[2].lower()
                != "aad3b435b51404eeaad3b435b51404ee"
            ) or lm_count > 1:
                lmHashesFound = True
                # Decline LM brute force to keep test simple
                next(input_iter, "N")

            hcatHashFileOrig = hcatHashFile
            hcatHashFile = hcatHashFile + ".nt"

        return {
            "hcatHashFile": hcatHashFile,
            "hcatHashFileOrig": hcatHashFileOrig,
            "pwdump_format": pwdump_format,
            "lmHashesFound": lmHashesFound,
            "filtered_path": filtered_path,
        }

    def test_e2e_filter_computers_and_extract_nt(self, tmp_path, main_module):
        """Full flow: secretsdump.py output -> filter computers -> extract NT hashes."""
        pwdump = tmp_path / "secretsdump.txt"
        pwdump.write_text(
            "Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "CORP-DC01$:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "john.doe:1002:e52cac67419a9a224a3b108f3fa6cb6d:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
            "CORP-WKS01$:1003:aad3b435b51404eeaad3b435b51404ee:deadbeefcafebabe1234567890abcdef:::\n"
            "jane.smith:1004:aad3b435b51404eeaad3b435b51404ee:6cb75f652a9b52798eb6cf2201057c73:::\n"
            "CORP-SRV01$:1005:aad3b435b51404eeaad3b435b51404ee:1234567890abcdef1234567890abcdef:::\n"
        )

        result = self._run_preprocessing(main_module, pwdump, ["Y", "N"])

        # Verify pwdump detected
        assert result["pwdump_format"] is True

        # Verify filtering happened
        assert result["filtered_path"] is not None
        filtered = open(result["filtered_path"]).read()
        filtered_lines = filtered.strip().split("\n")
        assert len(filtered_lines) == 4, (
            f"Expected 4 non-computer lines, got {len(filtered_lines)}"
        )
        for line in filtered_lines:
            username = line.split(":")[0]
            assert not username.endswith("$"), (
                f"Computer account leaked through: {username}"
            )

        # Verify final hcatHashFile points to .nt file
        assert result["hcatHashFile"].endswith(".nt")

        # Verify NT hashes are correct (no computer account hashes)
        nt_content = open(result["hcatHashFile"]).read()
        nt_hashes = nt_content.strip().split("\n")
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" in nt_hashes  # Admin/Guest
        assert "5f4dcc3b5aa765d61d8327deb882cf99" in nt_hashes  # john.doe
        assert "6cb75f652a9b52798eb6cf2201057c73" in nt_hashes  # jane.smith
        # Computer hashes must NOT be present
        assert "8846f7eaee8fb117ad06bdd830b7586c" not in nt_hashes
        assert "deadbeefcafebabe1234567890abcdef" not in nt_hashes
        assert "1234567890abcdef1234567890abcdef" not in nt_hashes

    def test_e2e_decline_filter(self, tmp_path, main_module):
        """Full flow when user declines filtering - all hashes including computers."""
        pwdump = tmp_path / "dump.txt"
        pwdump.write_text(
            "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "COMP$:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        )

        result = self._run_preprocessing(main_module, pwdump, ["N", "N"])

        assert result["pwdump_format"] is True
        assert result["filtered_path"] is None  # No filtering

        # NT file should contain BOTH hashes (computer included)
        nt_hashes = open(result["hcatHashFile"]).read().strip().split("\n")
        assert "31d6cfe0d16ae931b73c59d7e0c089c0" in nt_hashes
        assert "8846f7eaee8fb117ad06bdd830b7586c" in nt_hashes

    def test_e2e_no_computers_in_dump(self, tmp_path, main_module):
        """Full flow with no computer accounts - no prompt shown."""
        pwdump = tmp_path / "clean.txt"
        pwdump.write_text(
            "admin:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "john:501:e52cac67419a9a224a3b108f3fa6cb6d:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
        )

        # No input responses needed since no computer accounts -> no prompt
        result = self._run_preprocessing(main_module, pwdump, ["N"])

        assert result["pwdump_format"] is True
        assert result["filtered_path"] is None
        nt_hashes = open(result["hcatHashFile"]).read().strip().split("\n")
        assert len(nt_hashes) == 2

    def test_e2e_all_computers(self, tmp_path, main_module):
        """Full flow where ALL accounts are computer accounts."""
        pwdump = tmp_path / "computers_only.txt"
        pwdump.write_text(
            "DC01$:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "WKS01$:501:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
        )

        result = self._run_preprocessing(main_module, pwdump, ["Y", "N"])

        assert result["filtered_path"] is not None
        filtered = open(result["filtered_path"]).read()
        assert filtered.strip() == ""  # All lines removed

        # NT file should be empty too
        nt_content = open(result["hcatHashFile"]).read()
        assert nt_content.strip() == ""

    def test_e2e_lm_hashes_detected(self, tmp_path, main_module):
        """Full flow with non-empty LM hashes triggers LM detection."""
        pwdump = tmp_path / "lm_hashes.txt"
        pwdump.write_text(
            "admin:500:e52cac67419a9a224a3b108f3fa6cb6d:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "COMP$:501:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "john:502:a4f49c406510bdca00000000000000000:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
        )

        result = self._run_preprocessing(main_module, pwdump, ["Y", "N"])

        assert result["lmHashesFound"] is True

        # LM file should only have non-computer LM hashes
        lm_path = result["hcatHashFileOrig"] + ".lm"
        lm_hashes = open(lm_path).read().strip().split("\n")
        # Computer LM hash should not be present
        for lm in lm_hashes:
            # These are from the filtered file (no COMP$)
            assert lm in [
                "a4f49c406510bdca00000000000000000",
                "e52cac67419a9a224a3b108f3fa6cb6d",
            ]

    def test_e2e_domain_prefix_computers(self, tmp_path, main_module):
        """Full flow with domain\\computer$ format from secretsdump."""
        pwdump = tmp_path / "domain_dump.txt"
        pwdump.write_text(
            "CORP\\Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
            "CORP\\DESKTOP-PC$:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n"
            "CORP\\john.doe:1002:aad3b435b51404eeaad3b435b51404ee:5f4dcc3b5aa765d61d8327deb882cf99:::\n"
        )

        result = self._run_preprocessing(main_module, pwdump, ["Y", "N"])

        # Verify format detection still works (regex matches the LM:NT::: part)
        assert result["pwdump_format"] is True

        # The username field is "CORP\DESKTOP-PC$" - split on ":" gets that
        # But wait: "CORP\DESKTOP-PC$" doesn't end with $ in the first :-delimited field?
        # Actually it does: split(":", 1)[0] = "CORP\\DESKTOP-PC$" which ends with "$"
        assert result["filtered_path"] is not None
        filtered_lines = open(result["filtered_path"]).read().strip().split("\n")
        assert len(filtered_lines) == 2
        for line in filtered_lines:
            username = line.split(":")[0]
            assert not username.endswith("$")
