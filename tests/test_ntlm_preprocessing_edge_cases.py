"""Additional edge case tests for NTLM preprocessing (issues #27 and #28)."""

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


class TestFilterComputerAccountsEdgeCases:
    """Additional edge cases for computer account filtering."""

    def test_unicode_in_usernames(self, tmp_path, main_module):
        """Test handling of Unicode characters in usernames."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "Müller$:1002:aad3b435b51404ee:hash2:::\n"
            "用户:1003:aad3b435b51404ee:hash3:::\n",
            encoding="utf-8",
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 1
        lines = output_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2
        assert "Müller$" not in output_file.read_text(encoding="utf-8")

    def test_dollar_in_middle_of_username(self, tmp_path, main_module):
        """Test that $ only at end triggers filtering."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user$name:1001:aad3b435b51404ee:hash1:::\n"
            "COMP1$:1002:aad3b435b51404ee:hash2:::\n"
            "$startdollar:1003:aad3b435b51404ee:hash3:::\n",
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        # Only COMP1$ should be removed (ends with $)
        assert removed == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2
        assert "user$name" in lines[0]
        assert "$startdollar" in lines[1]

    def test_empty_username(self, tmp_path, main_module):
        """Test handling of lines with empty username field."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            ":1001:aad3b435b51404ee:hash1:::\nuser1:1002:aad3b435b51404ee:hash2:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 0
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_very_long_lines(self, tmp_path, main_module):
        """Test handling of very long hash lines."""
        hash_file = tmp_path / "hashes.txt"
        long_hash = "a" * 10000
        hash_file.write_text(
            f"user1:1001:{long_hash}:hash1:::\nCOMP1$:1002:{long_hash}:hash2:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 1
        assert "user1" in lines[0]

    def test_output_file_exists_overwrites(self, tmp_path, main_module):
        """Test that output file is overwritten if it exists."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "COMP1$:1002:aad3b435b51404ee:hash2:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        output_file.write_text("OLD CONTENT THAT SHOULD BE REPLACED\n")

        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 1
        content = output_file.read_text()
        assert "OLD CONTENT" not in content
        assert "user1" in content

    def test_permission_denied_output(self, tmp_path, main_module):
        """Test handling when output file cannot be written."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "COMP1$:1002:aad3b435b51404ee:hash2:::\n"
        )
        # Create a read-only directory for output
        readonly_dir = tmp_path / "readonly"
        readonly_dir.mkdir()
        os.chmod(readonly_dir, 0o444)

        output_file = readonly_dir / "filtered.txt"

        # Should handle PermissionError gracefully
        try:
            removed = main_module._filter_computer_accounts(
                str(hash_file), str(output_file)
            )
            # If it doesn't raise, should return 0
            assert removed == 0
        except PermissionError:
            # This is also acceptable behavior
            pass
        finally:
            # Cleanup - restore permissions
            os.chmod(readonly_dir, 0o755)

    def test_blank_lines_preserved_count(self, tmp_path, main_module):
        """Test that blank lines don't affect removed count."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "\n"
            "COMP1$:1002:aad3b435b51404ee:hash2:::\n"
            "\n\n"
            "user2:1003:aad3b435b51404ee:hash3:::\n"
        )
        output_file = tmp_path / "filtered.txt"
        removed = main_module._filter_computer_accounts(
            str(hash_file), str(output_file)
        )
        assert removed == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2


class TestDedupNetntlmEdgeCases:
    """Additional edge cases for NetNTLM deduplication."""

    def test_unicode_usernames(self, tmp_path, main_module):
        """Test deduplication with Unicode usernames."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "用户1::DOMAIN:challenge1:response1:blob1\n"
            "用户1::DOMAIN:challenge2:response2:blob2\n"
            "Müller::DOMAIN:challenge3:response3:blob3\n",
            encoding="utf-8",
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 3
        assert duplicates == 1
        lines = output_file.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 2

    def test_whitespace_in_usernames(self, tmp_path, main_module):
        """Test handling of usernames with leading/trailing spaces."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user1::DOMAIN:challenge1:response1:blob1\n"
            " user1::DOMAIN:challenge2:response2:blob2\n"
            "user1 ::DOMAIN:challenge3:response3:blob3\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        # These are NOT duplicates because split() doesn't strip whitespace
        # This is actually correct behavior - the usernames differ
        assert total == 3
        assert duplicates == 0

    def test_case_variations(self, tmp_path, main_module):
        """Test various case combinations are deduplicated."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "User1::DOMAIN:challenge1:response1:blob1\n"
            "user1::DOMAIN:challenge2:response2:blob2\n"
            "USER1::DOMAIN:challenge3:response3:blob3\n"
            "uSeR1::DOMAIN:challenge4:response4:blob4\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 4
        assert duplicates == 3
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_very_long_username(self, tmp_path, main_module):
        """Test handling of very long usernames."""
        hash_file = tmp_path / "netntlm.txt"
        long_user = "a" * 10000
        hash_file.write_text(
            f"{long_user}::DOMAIN:challenge1:response1:blob1\n"
            f"{long_user}::DOMAIN:challenge2:response2:blob2\n"
            "user2::DOMAIN:challenge3:response3:blob3\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 3
        assert duplicates == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 2

    def test_memory_efficiency_many_duplicates(self, tmp_path, main_module):
        """Test memory handling with many duplicates."""
        hash_file = tmp_path / "netntlm.txt"
        # Create 1000 lines, all duplicates of the same user
        content = ""
        for i in range(1000):
            content += f"user1::DOMAIN:challenge{i}:response{i}:blob{i}\n"
        hash_file.write_text(content)

        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 1000
        assert duplicates == 999
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 1

    def test_special_characters_in_username(self, tmp_path, main_module):
        """Test usernames with special characters."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user@domain::DOMAIN:challenge1:response1:blob1\n"
            "user-name::DOMAIN:challenge2:response2:blob2\n"
            "user.name::DOMAIN:challenge3:response3:blob3\n"
            "user@domain::DOMAIN:challenge4:response4:blob4\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 4
        assert duplicates == 1
        lines = output_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_only_colons(self, tmp_path, main_module):
        """Test handling of malformed lines with only colons."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user1::DOMAIN:challenge1:response1:blob1\n"
            ":::::\n"
            "user2::DOMAIN:challenge2:response2:blob2\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        # Empty username from ::::: should be counted but not cause errors
        assert total == 3

    def test_preserved_line_order(self, tmp_path, main_module):
        """Test that first occurrence is preserved, not last."""
        hash_file = tmp_path / "netntlm.txt"
        hash_file.write_text(
            "user1::DOMAIN:FIRST:response1:blob1\n"
            "user2::DOMAIN:challenge2:response2:blob2\n"
            "user1::DOMAIN:SECOND:response3:blob3\n"
            "user3::DOMAIN:challenge4:response4:blob4\n"
            "user1::DOMAIN:THIRD:response5:blob5\n"
        )
        output_file = tmp_path / "dedup.txt"
        total, duplicates = main_module._dedup_netntlm_by_username(
            str(hash_file), str(output_file)
        )
        assert total == 5
        assert duplicates == 2
        content = output_file.read_text()
        # First occurrence should be kept
        assert "FIRST" in content
        assert "SECOND" not in content
        assert "THIRD" not in content


class TestCountComputerAccountsEdgeCases:
    """Additional edge cases for computer account counting."""

    def test_mixed_delimiters(self, tmp_path, main_module):
        """Test that only the specified delimiter is used."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text(
            "user1:1001:aad3b435b51404ee:hash1:::\n"
            "COMP$;1002;aad3b435b51404ee;hash2\n"  # Different delimiter
        )
        # Default delimiter is ":"
        assert main_module._count_computer_accounts(str(hash_file)) == 0
        # Custom delimiter ";" - COMP$ is first field with ";" delimiter
        assert main_module._count_computer_accounts(str(hash_file), ";") == 1

    def test_single_field_line(self, tmp_path, main_module):
        """Test lines with only one field (no delimiter)."""
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("COMP1$\nuser1:1001:aad3b435b51404ee:hash1:::\n")
        # COMP1$ should still be counted (split returns single element)
        assert main_module._count_computer_accounts(str(hash_file)) == 1
