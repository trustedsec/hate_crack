import json
import os

import pytest
from unittest.mock import MagicMock, patch

from hate_crack.api import (
    check_7z,
    check_transmission_cli,
    download_hashmob_wordlist,
    extract_with_7z,
    get_hashmob_api_key,
    get_hcat_potfile_args,
    get_hcat_potfile_path,
    list_and_download_hashmob_rules,
    sanitize_filename,
    _Hashmob429,
    _streamed_download,
    _with_hashmob_backoff,
    list_and_download_official_wordlists,
)
import requests as req_lib


class TestSanitizeFilename:
    def test_normal_filename_unchanged(self):
        assert sanitize_filename("rockyou.txt") == "rockyou.txt"

    def test_spaces_become_underscores(self):
        assert sanitize_filename("my file.txt") == "my_file.txt"

    def test_path_separators_removed(self):
        # Dots are kept; slashes are removed. "../../etc/passwd" has 4 dots, 2 slashes.
        assert sanitize_filename("../../etc/passwd") == "....etcpasswd"

    def test_empty_string(self):
        assert sanitize_filename("") == ""

    def test_mixed_case_preserved(self):
        assert sanitize_filename("RockYou.txt") == "RockYou.txt"


class TestCheck7z:
    def test_returns_true_when_found(self, capsys):
        with patch("shutil.which", return_value="/usr/bin/7z"):
            result = check_7z()
        assert result is True

    def test_returns_false_when_missing(self, capsys):
        with patch("shutil.which", return_value=None):
            result = check_7z()
        assert result is False
        captured = capsys.readouterr()
        assert "7z" in captured.out


class TestCheckTransmissionCli:
    def test_returns_true_when_found(self):
        with patch("shutil.which", return_value="/usr/bin/transmission-cli"):
            result = check_transmission_cli()
        assert result is True

    def test_returns_false_when_missing(self, capsys):
        with patch("shutil.which", return_value=None):
            result = check_transmission_cli()
        assert result is False
        captured = capsys.readouterr()
        assert "transmission-cli" in captured.out


class TestGetHcatPotfilePath:
    def test_returns_config_value_when_set(self, tmp_path):
        config_data = {"hcatPotfilePath": "/custom/hashcat.potfile"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch("hate_crack.api._resolve_config_path", return_value=str(config_file)):
            result = get_hcat_potfile_path()
        assert result == "/custom/hashcat.potfile"

    def test_returns_default_when_key_missing(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({}))
        with patch("hate_crack.api._resolve_config_path", return_value=str(config_file)):
            result = get_hcat_potfile_path()
        assert result == os.path.expanduser("~/.hashcat/hashcat.potfile")

    def test_returns_empty_string_when_key_is_empty(self, tmp_path):
        config_data = {"hcatPotfilePath": ""}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch("hate_crack.api._resolve_config_path", return_value=str(config_file)):
            result = get_hcat_potfile_path()
        assert result == ""

    def test_resolves_relative_path_from_config_dir(self, tmp_path):
        config_data = {"hcatPotfilePath": "hashcat.potfile"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch("hate_crack.api._resolve_config_path", return_value=str(config_file)):
            result = get_hcat_potfile_path()
        assert result == str(tmp_path / "hashcat.potfile")

    def test_returns_default_when_no_config(self):
        with patch("hate_crack.api._resolve_config_path", return_value=None):
            result = get_hcat_potfile_path()
        assert result == os.path.expanduser("~/.hashcat/hashcat.potfile")

    def test_expands_tilde_in_config_value(self, tmp_path):
        config_data = {"hcatPotfilePath": "~/.custom/hashcat.potfile"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch("hate_crack.api._resolve_config_path", return_value=str(config_file)):
            result = get_hcat_potfile_path()
        assert result == os.path.expanduser("~/.custom/hashcat.potfile")
        assert "~" not in result


class TestGetHcatPotfileArgs:
    def test_returns_list_with_potfile_arg(self):
        with patch("hate_crack.api.get_hcat_potfile_path", return_value="/some/path/hashcat.potfile"):
            result = get_hcat_potfile_args()
        assert result == ["--potfile-path=/some/path/hashcat.potfile"]

    def test_returns_non_empty_list_by_default(self):
        # Default path always resolves to something (expanduser never returns empty)
        with patch("hate_crack.api._resolve_config_path", return_value=None):
            result = get_hcat_potfile_args()
        assert len(result) == 1
        assert result[0].startswith("--potfile-path=")


class TestGetHashmobApiKey:
    def test_returns_key_from_config(self, tmp_path):
        config_data = {"hashmob_api_key": "abc123secret"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        config_path = str(config_file)
        # Patch isfile so the function sees our config file as the pkg_dir config,
        # and patch open so reads come from it.
        with patch("hate_crack.api.os.path.isfile", side_effect=lambda p: p == config_path), \
             patch("hate_crack.api.os.path.dirname", return_value=str(tmp_path)), \
             patch("hate_crack.api.os.path.abspath", side_effect=lambda p: p):
            result = get_hashmob_api_key()
        assert result == "abc123secret"

    def test_returns_none_when_missing(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({}))
        config_path = str(config_file)
        with patch("hate_crack.api.os.path.isfile", side_effect=lambda p: p == config_path), \
             patch("hate_crack.api.os.path.dirname", return_value=str(tmp_path)), \
             patch("hate_crack.api.os.path.abspath", side_effect=lambda p: p):
            result = get_hashmob_api_key()
        assert result is None

    def test_returns_none_when_no_config(self):
        with patch("hate_crack.api.os.path.isfile", return_value=False):
            result = get_hashmob_api_key()
        assert result is None


class TestExtractWith7z:
    def _make_run_result(self, returncode=0):
        result = MagicMock()
        result.returncode = returncode
        result.stdout = ""
        result.stderr = ""
        return result

    def test_returns_false_when_not_installed(self, tmp_path, capsys):
        with patch("hate_crack.api.shutil.which", return_value=None):
            archive = tmp_path / "test.7z"
            archive.write_text("fake archive data")
            result = extract_with_7z(str(archive), str(tmp_path))
        assert result is False
        captured = capsys.readouterr()
        assert "7z" in captured.out

    def test_returns_true_on_success(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=0)
        with patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"), \
             patch("subprocess.run", return_value=mock_result):
            result = extract_with_7z(str(archive), str(tmp_path), remove_archive=False)
        assert result is True

    def test_returns_false_on_failure(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=1)
        with patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"), \
             patch("subprocess.run", return_value=mock_result):
            result = extract_with_7z(str(archive), str(tmp_path))
        assert result is False

    def test_removes_archive_on_success(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=0)
        with patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"), \
             patch("subprocess.run", return_value=mock_result):
            result = extract_with_7z(str(archive), str(tmp_path), remove_archive=True)
        assert result is True
        assert not archive.exists()

    def test_keeps_archive_when_remove_false(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=0)
        with patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"), \
             patch("subprocess.run", return_value=mock_result):
            result = extract_with_7z(str(archive), str(tmp_path), remove_archive=False)
        assert result is True
        assert archive.exists()


class TestDownloadHashmobWordlist:
    def _make_mock_response(self, status_code=200, content=b"wordlist data"):
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status_code = status_code
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.iter_content.return_value = [content]
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def test_successful_download(self, tmp_path):
        mock_response = self._make_mock_response(status_code=200, content=b"wordlist data")
        out = tmp_path / "test.txt"
        with patch("hate_crack.api.requests.get", return_value=mock_response), \
             patch("hate_crack.api.time.sleep"):
            result = download_hashmob_wordlist("test.txt", str(out))
        assert result is True
        assert out.exists()
        assert out.read_bytes() == b"wordlist data"

    def test_404_returns_false(self, tmp_path):
        import requests as req

        mock_response = self._make_mock_response(status_code=404)
        mock_response.raise_for_status.side_effect = req.exceptions.HTTPError(
            response=MagicMock(status_code=404)
        )
        out = tmp_path / "test.txt"
        with patch("hate_crack.api.requests.get", return_value=mock_response), \
             patch("hate_crack.api.time.sleep"):
            result = download_hashmob_wordlist("test.txt", str(out))
        assert result is False


class TestParallelRuleDownloads:
    def _make_rules(self, names):
        return [{"file_name": n} for n in names]

    def _patch_stdin_tty(self):
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True
        return patch("hate_crack.api.sys.stdin", mock_stdin)

    def test_submits_to_thread_pool(self, tmp_path):
        rules = self._make_rules(["rule1.rule", "rule2.rule", "rule3.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl, \
             self._patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)
        assert mock_dl.call_count == 3
        downloaded_names = {c.args[0] for c in mock_dl.call_args_list}
        assert downloaded_names == {"rule1.rule", "rule2.rule", "rule3.rule"}

    def test_failure_does_not_block_others(self, tmp_path, capsys):
        rules = self._make_rules(["good.rule", "bad.rule", "also_good.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        def side_effect(file_name, out_path):
            if file_name == "bad.rule":
                raise RuntimeError("download error")

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule", side_effect=side_effect), \
             self._patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        captured = capsys.readouterr()
        assert "2 succeeded" in captured.out
        assert "1 failed" in captured.out

    def test_skips_already_downloaded(self, tmp_path, capsys):
        rules = self._make_rules(["existing.rule", "new.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        (tmp_path / "rules" / "existing.rule").touch()
        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl, \
             self._patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)
        assert mock_dl.call_count == 1
        assert mock_dl.call_args.args[0] == "new.rule"
        captured = capsys.readouterr()
        assert "Skipping already downloaded" in captured.out


def _make_mock_response(
    status_code=200,
    content=b"file data",
    content_type="application/octet-stream",
    headers=None,
):
    mock_resp = MagicMock()
    mock_resp.__enter__ = lambda s: mock_resp
    mock_resp.__exit__ = MagicMock(return_value=False)
    mock_resp.status_code = status_code
    mock_resp.headers = {
        "Content-Type": content_type,
        "content-length": str(len(content)),
        **(headers or {}),
    }
    mock_resp.iter_content.return_value = [content]
    mock_resp.content = content
    mock_resp.raise_for_status = MagicMock()
    return mock_resp


class TestStreamedDownload:
    def test_happy_path(self, tmp_path):
        content = b"hello data"
        mock_resp = _make_mock_response(status_code=200, content=content)
        out = tmp_path / "out.txt"
        with patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get:
            result = _streamed_download("https://example.com/file.txt", str(out))
        assert result is True
        assert out.exists()
        assert out.read_bytes() == content
        assert not (tmp_path / "out.txt.part").exists()
        mock_get.assert_called_once()
        assert mock_get.call_args.args[0] == "https://example.com/file.txt"

    def test_partial_cleanup_on_error(self, tmp_path):
        mock_resp = _make_mock_response(status_code=200, content=b"some data")
        mock_resp.iter_content.side_effect = req_lib.exceptions.ChunkedEncodingError(
            "network error"
        )
        out = tmp_path / "out.txt"
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _streamed_download("https://example.com/file.txt", str(out))
        assert result is False
        assert not out.exists()
        assert not (tmp_path / "out.txt.part").exists()

    def test_keyboardinterrupt_cleanup(self, tmp_path):
        mock_resp = _make_mock_response(status_code=200, content=b"some data")
        mock_resp.iter_content.side_effect = KeyboardInterrupt
        out = tmp_path / "out.txt"
        ki_raised = False
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            try:
                _streamed_download("https://example.com/file.txt", str(out))
            except KeyboardInterrupt:
                ki_raised = True
        assert ki_raised
        assert not (tmp_path / "out.txt.part").exists()

    def test_skip_existing(self, tmp_path):
        out = tmp_path / "out.txt"
        out.write_bytes(b"already here")
        with patch("hate_crack.api.requests.get") as mock_get:
            result = _streamed_download(
                "https://example.com/file.txt", str(out), skip_existing=True
            )
        assert result is True
        mock_get.assert_not_called()


class TestHashmobBackoff:
    def test_gives_up_after_max_attempts(self, capsys):
        fn = MagicMock(side_effect=_Hashmob429)
        with patch("hate_crack.api.time.sleep") as mock_sleep, \
             patch("hate_crack.api._hashmob_limiter.wait"):
            result = _with_hashmob_backoff(fn, max_attempts=3, base_delay=1, step=1, max_delay=10)
        assert result is False
        assert fn.call_count == 3
        # sleep called between attempts, but NOT after the last attempt
        assert mock_sleep.call_count == 2
        captured = capsys.readouterr()
        assert "gave up after 3 attempts" in captured.out

    def test_succeeds_on_first_try(self):
        fn = MagicMock(return_value=True)
        with patch("time.sleep") as mock_sleep:
            result = _with_hashmob_backoff(fn)
        assert result is True
        mock_sleep.assert_not_called()

    def test_succeeds_after_retry(self):
        fn = MagicMock(side_effect=[_Hashmob429(), _Hashmob429(), True])
        with patch("hate_crack.api.time.sleep") as mock_sleep, \
             patch("hate_crack.api._hashmob_limiter.wait"):
            result = _with_hashmob_backoff(fn, max_attempts=6, base_delay=1, step=1, max_delay=10)
        assert result is True
        assert fn.call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_429_exception_reraises(self):
        fn = MagicMock(side_effect=ValueError("not a 429"))
        with pytest.raises(ValueError, match="not a 429"):
            _with_hashmob_backoff(fn)


class TestHashmobWordlistRedirectBugFix:
    def test_meta_refresh_redirect_uses_verbatim_url(self, tmp_path):
        real_url = "https://real-server.example.com/actual_file.txt"
        html_content = (
            "<html><head>"
            '<meta http-equiv="refresh" content="0;url=https://real-server.example.com/actual_file.txt">'
            "</head></html>"
        ).encode()
        mock_resp = _make_mock_response(
            status_code=200,
            content=html_content,
            content_type="text/plain",
        )
        with patch("hate_crack.api.requests.get", return_value=mock_resp), \
             patch("hate_crack.api.time.sleep"), \
             patch("hate_crack.api._hashmob_limiter.wait"), \
             patch("hate_crack.api._streamed_download", return_value=True) as mock_sd:
            download_hashmob_wordlist("some_file.txt", str(tmp_path / "out.txt"))

        mock_sd.assert_called_once()
        called_url = mock_sd.call_args.args[0]
        assert called_url == real_url, (
            f"Expected verbatim redirect URL '{real_url}', got '{called_url}'"
        )


class TestListAndDownloadOfficialWordlistsSkipExisting:
    def test_skips_already_downloaded_in_all_branch(self, tmp_path, capsys):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        # Pre-create existing.txt with content so it passes the size>0 check
        (wordlists_dir / "existing.txt").write_bytes(b"already downloaded")

        api_data = [{"file_name": "existing.txt"}, {"file_name": "new.txt"}]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = api_data

        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True

        with patch("hate_crack.api.requests.get", return_value=mock_resp), \
             patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)), \
             patch("hate_crack.api.download_official_wordlist") as mock_dl, \
             patch("hate_crack.api.sys.stdin", mock_stdin), \
             patch("builtins.input", return_value="a"):
            list_and_download_official_wordlists()

        assert mock_dl.call_count == 1
        called_filename = mock_dl.call_args.args[0]
        assert called_filename == "new.txt"
        captured = capsys.readouterr()
        assert "Skipping existing.txt" in captured.out
