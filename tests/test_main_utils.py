"""Tests for utility functions in hate_crack/main.py."""

import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack.main import _dedup_netntlm_by_username


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


class TestAppendPotfileArg:
    def test_appends_potfile_path(self, main_module):
        with patch.object(main_module, "hcatPotfilePath", "/some/path"):
            cmd = []
            main_module._append_potfile_arg(cmd)
        assert "--potfile-path=/some/path" in cmd

    def test_no_append_empty_potfile(self, main_module):
        with patch.object(main_module, "hcatPotfilePath", ""):
            cmd = []
            main_module._append_potfile_arg(cmd)
        assert cmd == []

    def test_disabled_by_flag(self, main_module):
        with patch.object(main_module, "hcatPotfilePath", "/some/path"):
            cmd = []
            main_module._append_potfile_arg(cmd, use_potfile_path=False)
        assert cmd == []

    def test_explicit_potfile_overrides_global(self, main_module):
        with patch.object(main_module, "hcatPotfilePath", "/global/path"):
            cmd = []
            main_module._append_potfile_arg(cmd, potfile_path="/custom/path")
        assert "--potfile-path=/custom/path" in cmd
        assert "--potfile-path=/global/path" not in cmd

    def test_explicit_potfile_when_global_empty(self, main_module):
        with patch.object(main_module, "hcatPotfilePath", ""):
            cmd = []
            main_module._append_potfile_arg(cmd, potfile_path="/explicit/path")
        assert "--potfile-path=/explicit/path" in cmd


class TestGenerateSessionId:
    def test_basic_filename(self, main_module):
        with patch("hate_crack.main.hcatHashFile", "/tmp/myfile.txt", create=True):
            result = main_module.generate_session_id()
        assert result == "myfile"

    def test_with_hyphens_and_underscores(self, main_module):
        with patch("hate_crack.main.hcatHashFile", "/path/to/my-file_v2.txt", create=True):
            result = main_module.generate_session_id()
        assert result == "my-file_v2"

    def test_dots_replaced(self, main_module):
        with patch("hate_crack.main.hcatHashFile", "/tmp/file.with.dots.txt", create=True):
            result = main_module.generate_session_id()
        assert result == "file_with_dots"

    def test_spaces_replaced(self, main_module):
        with patch("hate_crack.main.hcatHashFile", "/tmp/file with spaces.txt", create=True):
            result = main_module.generate_session_id()
        assert result == "file_with_spaces"

    def test_returns_nonempty_string(self, main_module):
        with patch("hate_crack.main.hcatHashFile", "/tmp/somefile.txt", create=True):
            result = main_module.generate_session_id()
        assert isinstance(result, str)
        assert len(result) > 0

    def test_only_safe_chars(self, main_module):
        with patch("hate_crack.main.hcatHashFile", "/tmp/f!le@na#me.txt", create=True):
            result = main_module.generate_session_id()
        import re
        assert re.fullmatch(r"[a-zA-Z0-9_-]+", result) is not None


class TestEnsureHashfileInCwd:
    def test_none_returns_none(self, main_module):
        result = main_module._ensure_hashfile_in_cwd(None)
        assert result is None

    def test_empty_string_returns_empty(self, main_module):
        result = main_module._ensure_hashfile_in_cwd("")
        assert result == ""

    def test_relative_path_unchanged(self, main_module):
        result = main_module._ensure_hashfile_in_cwd("relative/path.txt")
        assert result == "relative/path.txt"

    def test_already_in_cwd(self, main_module, tmp_path):
        target = tmp_path / "hashfile.txt"
        target.write_text("hashes")
        with patch("os.getcwd", return_value=str(tmp_path)):
            result = main_module._ensure_hashfile_in_cwd(str(target))
        assert result == str(target)

    def test_different_dir_existing_file_in_cwd(self, main_module, tmp_path):
        # File exists in a different directory
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        source_file = other_dir / "hashes.txt"
        source_file.write_text("hashes")

        # A file with the same name already exists in cwd
        cwd_dir = tmp_path / "cwd"
        cwd_dir.mkdir()
        cwd_copy = cwd_dir / "hashes.txt"
        cwd_copy.write_text("cwd version")

        with patch("os.getcwd", return_value=str(cwd_dir)):
            result = main_module._ensure_hashfile_in_cwd(str(source_file))
        assert result == str(cwd_copy)

    def test_different_dir_creates_symlink(self, main_module, tmp_path):
        # Source file in a different directory, nothing in cwd
        other_dir = tmp_path / "other"
        other_dir.mkdir()
        source_file = other_dir / "hashes.txt"
        source_file.write_text("hashes")

        cwd_dir = tmp_path / "cwd"
        cwd_dir.mkdir()

        with patch("os.getcwd", return_value=str(cwd_dir)):
            result = main_module._ensure_hashfile_in_cwd(str(source_file))

        expected = str(cwd_dir / "hashes.txt")
        assert result == expected
        assert os.path.exists(expected)


class TestRunHashcatShow:
    def _make_mock_result(self, stdout_bytes):
        mock_result = MagicMock()
        mock_result.stdout = stdout_bytes
        return mock_result

    def test_show_flag_present(self, main_module, tmp_path):
        mock_result = self._make_mock_result(b"")
        output = tmp_path / "out.txt"
        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return mock_result

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatPotfilePath", ""),
        ):
            main_module._run_hashcat_show("1000", "/tmp/h.txt", str(output))

        assert "--show" in captured_cmd

    def test_valid_lines_written(self, main_module, tmp_path):
        stdout = b"abc123:password\ndeadbeef:hunter2\n"
        mock_result = self._make_mock_result(stdout)
        output = tmp_path / "out.txt"

        with (
            patch("hate_crack.main.subprocess.run", return_value=mock_result),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatPotfilePath", ""),
        ):
            main_module._run_hashcat_show("1000", "/tmp/h.txt", str(output))

        lines = output.read_text().splitlines()
        assert "abc123:password" in lines
        assert "deadbeef:hunter2" in lines

    def test_hash_parsing_error_excluded(self, main_module, tmp_path):
        stdout = b"abc123:password\nHash parsing error: bad line\n"
        mock_result = self._make_mock_result(stdout)
        output = tmp_path / "out.txt"

        with (
            patch("hate_crack.main.subprocess.run", return_value=mock_result),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatPotfilePath", ""),
        ):
            main_module._run_hashcat_show("1000", "/tmp/h.txt", str(output))

        content = output.read_text()
        assert "Hash parsing error" not in content
        assert "abc123:password" in content

    def test_star_prefix_excluded(self, main_module, tmp_path):
        stdout = b"abc123:password\n* Device #1: ...\n"
        mock_result = self._make_mock_result(stdout)
        output = tmp_path / "out.txt"

        with (
            patch("hate_crack.main.subprocess.run", return_value=mock_result),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatPotfilePath", ""),
        ):
            main_module._run_hashcat_show("1000", "/tmp/h.txt", str(output))

        content = output.read_text()
        assert "* Device" not in content

    def test_lines_without_colon_excluded(self, main_module, tmp_path):
        stdout = b"abc123:password\nlinewithoutseparator\n"
        mock_result = self._make_mock_result(stdout)
        output = tmp_path / "out.txt"

        with (
            patch("hate_crack.main.subprocess.run", return_value=mock_result),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatPotfilePath", ""),
        ):
            main_module._run_hashcat_show("1000", "/tmp/h.txt", str(output))

        content = output.read_text()
        assert "linewithoutseparator" not in content
        assert "abc123:password" in content

    def test_potfile_path_included_when_set(self, main_module, tmp_path):
        mock_result = self._make_mock_result(b"")
        output = tmp_path / "out.txt"
        captured_cmd = []

        def fake_run(cmd, **kwargs):
            captured_cmd.extend(cmd)
            return mock_result

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatPotfilePath", "/my/potfile"),
        ):
            main_module._run_hashcat_show("1000", "/tmp/h.txt", str(output))

        assert any("--potfile-path=/my/potfile" in arg for arg in captured_cmd)


class TestDedupNetntlmByUsername:
    def test_no_duplicates_no_output_file(self, tmp_path):
        input_file = tmp_path / "hashes.txt"
        input_file.write_text("user1::domain:challenge:response:blob\nuser2::domain:challenge:response:blob\n")
        output_file = tmp_path / "deduped.txt"

        total, dupes = _dedup_netntlm_by_username(str(input_file), str(output_file))

        assert total == 2
        assert dupes == 0
        assert not output_file.exists()

    def test_duplicates_removed(self, tmp_path):
        input_file = tmp_path / "hashes.txt"
        input_file.write_text(
            "alice::domain:aaa:bbb:ccc\n"
            "bob::domain:ddd:eee:fff\n"
            "alice::domain:111:222:333\n"
        )
        output_file = tmp_path / "deduped.txt"

        total, dupes = _dedup_netntlm_by_username(str(input_file), str(output_file))

        assert total == 3
        assert dupes == 1
        assert output_file.exists()
        lines = output_file.read_text().splitlines()
        assert len(lines) == 2
        assert any("alice" in line for line in lines)
        assert any("bob" in line for line in lines)

    def test_only_first_occurrence_kept(self, tmp_path):
        input_file = tmp_path / "hashes.txt"
        input_file.write_text(
            "alice::domain:first:aaa:bbb\n"
            "alice::domain:second:ccc:ddd\n"
        )
        output_file = tmp_path / "deduped.txt"

        _dedup_netntlm_by_username(str(input_file), str(output_file))

        content = output_file.read_text()
        assert "first" in content
        assert "second" not in content

    def test_empty_file(self, tmp_path):
        input_file = tmp_path / "empty.txt"
        input_file.write_text("")
        output_file = tmp_path / "deduped.txt"

        total, dupes = _dedup_netntlm_by_username(str(input_file), str(output_file))

        assert total == 0
        assert dupes == 0
        assert not output_file.exists()

    def test_missing_input_file(self, tmp_path):
        input_file = tmp_path / "nonexistent.txt"
        output_file = tmp_path / "deduped.txt"

        total, dupes = _dedup_netntlm_by_username(str(input_file), str(output_file))

        assert total == 0
        assert dupes == 0

    def test_lines_without_delimiter(self, tmp_path):
        input_file = tmp_path / "hashes.txt"
        input_file.write_text("nodeilimiter\nnodeilimiter\n")
        output_file = tmp_path / "deduped.txt"

        # Should not raise; whole line treated as username
        total, dupes = _dedup_netntlm_by_username(str(input_file), str(output_file))

        assert total == 2
        assert dupes == 1

    def test_case_insensitive_username_dedup(self, tmp_path):
        input_file = tmp_path / "hashes.txt"
        input_file.write_text("Alice::domain:aaa:bbb:ccc\nalice::domain:ddd:eee:fff\n")
        output_file = tmp_path / "deduped.txt"

        total, dupes = _dedup_netntlm_by_username(str(input_file), str(output_file))

        assert total == 2
        assert dupes == 1


class TestResolveWordlistPath:
    def test_absolute_existing_file(self, main_module, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("word1\nword2\n")

        result = main_module._resolve_wordlist_path(str(wordlist), str(tmp_path))

        assert result == str(wordlist)

    def test_relative_found_in_base_dir(self, main_module, tmp_path):
        wordlist = tmp_path / "words.txt"
        wordlist.write_text("word1\nword2\n")

        result = main_module._resolve_wordlist_path("words.txt", str(tmp_path))

        assert result == str(wordlist)

    def test_not_found_returns_path_anyway(self, main_module, tmp_path):
        # When file not found, returns abspath of first candidate - does not raise
        result = main_module._resolve_wordlist_path("missing.txt", str(tmp_path))

        assert isinstance(result, str)
        assert len(result) > 0

    def test_empty_string_returns_empty(self, main_module):
        result = main_module._resolve_wordlist_path("", "/some/dir")

        assert result == ""

    def test_none_returns_none(self, main_module):
        result = main_module._resolve_wordlist_path(None, "/some/dir")

        assert result is None


class TestGetRulePath:
    def test_found_in_rules_directory(self, main_module, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rule_file = rules_dir / "best64.rule"
        rule_file.write_text("rule content")

        with patch.object(main_module, "rulesDirectory", str(rules_dir)):
            result = main_module.get_rule_path("best64.rule")

        assert result == str(rule_file)

    def test_found_in_fallback_dir(self, main_module, tmp_path):
        # rulesDirectory has no such file, fallback does
        empty_rules_dir = tmp_path / "empty_rules"
        empty_rules_dir.mkdir()
        fallback_dir = tmp_path / "fallback"
        fallback_dir.mkdir()
        rule_file = fallback_dir / "custom.rule"
        rule_file.write_text("rule content")

        with patch.object(main_module, "rulesDirectory", str(empty_rules_dir)):
            result = main_module.get_rule_path("custom.rule", fallback_dir=str(fallback_dir))

        assert result == str(rule_file)

    def test_not_found_returns_first_candidate(self, main_module, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        with patch.object(main_module, "rulesDirectory", str(rules_dir)):
            result = main_module.get_rule_path("nonexistent.rule")

        assert result == str(rules_dir / "nonexistent.rule")

    def test_no_rules_directory_no_fallback_returns_rule_name(self, main_module):
        with patch.object(main_module, "rulesDirectory", ""):
            result = main_module.get_rule_path("some.rule")

        assert result == "some.rule"

    def test_fallback_checked_after_rules_directory(self, main_module, tmp_path):
        # Both directories have the rule; rules_directory takes priority
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        fallback_dir = tmp_path / "fallback"
        fallback_dir.mkdir()
        (rules_dir / "priority.rule").write_text("rules version")
        (fallback_dir / "priority.rule").write_text("fallback version")

        with patch.object(main_module, "rulesDirectory", str(rules_dir)):
            result = main_module.get_rule_path("priority.rule", fallback_dir=str(fallback_dir))

        assert result == str(rules_dir / "priority.rule")


class TestCleanupWordlistArtifacts:
    def test_removes_out_files_from_cwd(self, main_module, tmp_path):
        artifact = tmp_path / "cracked.out"
        artifact.write_text("cracked passwords")

        with (
            patch("os.getcwd", return_value=str(tmp_path)),
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatWordlists", str(tmp_path / "wordlists")),
        ):
            main_module.cleanup_wordlist_artifacts()

        assert not artifact.exists()

    def test_preserves_non_artifact_files(self, main_module, tmp_path):
        keeper = tmp_path / "important.txt"
        keeper.write_text("keep me")
        artifact = tmp_path / "remove.out"
        artifact.write_text("remove me")

        with (
            patch("os.getcwd", return_value=str(tmp_path)),
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatWordlists", str(tmp_path / "wordlists")),
        ):
            main_module.cleanup_wordlist_artifacts()

        assert keeper.exists()
        assert not artifact.exists()

    def test_removes_out_files_from_hate_path(self, main_module, tmp_path):
        hate_dir = tmp_path / "hate_crack"
        hate_dir.mkdir()
        cwd_dir = tmp_path / "cwd"
        cwd_dir.mkdir()
        artifact = hate_dir / "session.out"
        artifact.write_text("output")

        with (
            patch("os.getcwd", return_value=str(cwd_dir)),
            patch.object(main_module, "hate_path", str(hate_dir)),
            patch.object(main_module, "hcatWordlists", str(tmp_path / "wordlists")),
        ):
            main_module.cleanup_wordlist_artifacts()

        assert not artifact.exists()

    def test_missing_directory_does_not_raise(self, main_module, tmp_path):
        nonexistent = tmp_path / "nonexistent"
        cwd_dir = tmp_path / "cwd"
        cwd_dir.mkdir()

        with (
            patch("os.getcwd", return_value=str(cwd_dir)),
            patch.object(main_module, "hate_path", str(nonexistent)),
            patch.object(main_module, "hcatWordlists", str(tmp_path / "wordlists")),
        ):
            # Should not raise even when directories don't exist
            main_module.cleanup_wordlist_artifacts()
