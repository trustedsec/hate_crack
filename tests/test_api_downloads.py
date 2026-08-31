import json
import os

import pytest
from unittest.mock import MagicMock, call, patch
import hate_crack.api as _api_mod
from hate_crack import api
from hate_crack import hashcat_paths

from hate_crack.api import (
    check_7z,
    check_transmission_daemon,
    download_hashmob_archive,
    download_hashmob_combined_left,
    download_hashmob_mask,
    download_hashmob_mask_list,
    download_hashmob_rule,
    download_hashmob_rule_list,
    download_hashmob_wordlist,
    download_hashmob_wordlist_list,
    download_official_wordlist,
    extract_with_7z,
    get_hashmob_api_key,
    get_hcat_potfile_args,
    get_hcat_potfile_path,
    list_and_download_hashmob_rules,
    list_hashmob_archives,
    list_hashmob_combined_left,
    run_torrent_session,
    sanitize_filename,
    TransmissionSession,
    _Hashmob429,
    _pick_free_port,
    _streamed_download,
    _with_hashmob_backoff,
    list_and_download_official_wordlists,
)
import requests as req_lib

from hate_crack.config_writer import write_env


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


class TestCheckTransmissionDaemon:
    def test_returns_true_when_both_found(self):
        with patch("shutil.which", side_effect=lambda x: f"/usr/bin/{x}"):
            result = check_transmission_daemon()
        assert result is True

    def test_returns_false_when_daemon_missing(self, capsys):
        def which(x):
            return None if x == "transmission-daemon" else f"/usr/bin/{x}"

        with patch("shutil.which", side_effect=which):
            result = check_transmission_daemon()
        assert result is False
        assert "transmission-daemon" in capsys.readouterr().out

    def test_returns_false_when_remote_missing(self, capsys):
        def which(x):
            return None if x == "transmission-remote" else f"/usr/bin/{x}"

        with patch("shutil.which", side_effect=which):
            result = check_transmission_daemon()
        assert result is False


class TestPickFreePort:
    def test_returns_int_in_valid_range(self):
        port = _pick_free_port()
        assert isinstance(port, int)
        assert 1 <= port <= 65535


class TestTransmissionSession:
    def _patch_startup_success(self):
        """Helper: returns patches that simulate a successful daemon startup."""
        proc_mock = MagicMock()
        # transmission-remote -l probe returns rc 0 immediately.
        probe_result = MagicMock(returncode=0, stdout="", stderr="")
        return proc_mock, probe_result

    def test_daemon_starts_with_expected_args(self, tmp_path):
        proc_mock, probe_result = self._patch_startup_success()
        with (
            patch("hate_crack.api._pick_free_port", return_value=12345),
            patch("subprocess.Popen", return_value=proc_mock) as popen,
            patch("subprocess.run", return_value=probe_result) as run_mock,
            patch("atexit.register"),
        ):
            ts = TransmissionSession(str(tmp_path))
            ts.__enter__()
            try:
                # Popen called with transmission-daemon and key flags
                args = popen.call_args[0][0]
                assert args[0] == "transmission-daemon"
                assert "-f" in args
                assert "--port" in args
                assert "12345" in args
                assert "--no-auth" in args
                assert "--download-dir" in args
                assert str(tmp_path) in args
                # Probe used transmission-remote with -l
                probe_args = run_mock.call_args[0][0]
                assert probe_args[0] == "transmission-remote"
                assert probe_args[-1] == "-l"
            finally:
                ts._stopped = True  # avoid running real cleanup

    def test_startup_timeout_raises(self, tmp_path):
        proc_mock = MagicMock()
        probe_failure = MagicMock(returncode=1, stdout="", stderr="")
        with (
            patch("hate_crack.api._pick_free_port", return_value=12345),
            patch("subprocess.Popen", return_value=proc_mock),
            patch("subprocess.run", return_value=probe_failure),
            patch("time.sleep"),
            patch("time.monotonic", side_effect=[0.0, 0.1, 100.0, 200.0, 300.0]),
            patch("atexit.register"),
        ):
            ts = TransmissionSession(str(tmp_path), startup_timeout=1.0)
            with pytest.raises(RuntimeError, match="Transmission daemon failed"):
                ts.__enter__()

    def test_add_uses_transmission_remote_and_returns_new_id(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        # Before: IDs 3 and 5. After add: ID 7 appears.
        list_calls = iter(
            [
                [{"id": 3}, {"id": 5}],
                [{"id": 3}, {"id": 5}, {"id": 7}],
            ]
        )
        run_result = MagicMock(returncode=0, stdout="", stderr="")
        with (
            patch("subprocess.run", return_value=run_result),
            patch.object(ts, "list", side_effect=list_calls),
        ):
            tid = ts.add("/tmp/foo.torrent")
        assert tid == 7

    def test_add_parses_id_from_output(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        before_list = [{"id": 1}]
        run_result = MagicMock(
            returncode=0,
            stdout="torrent added (id 42)\n",
            stderr="",
        )
        with (
            patch("subprocess.run", return_value=run_result),
            patch.object(ts, "list", return_value=before_list),
        ):
            tid = ts.add("/tmp/foo.torrent")
        assert tid == 42

    def test_add_raises_when_torrent_not_added(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        # list returns the same IDs before and after; output has no ID.
        run_result = MagicMock(returncode=1, stdout="", stderr="error")
        with (
            patch("subprocess.run", return_value=run_result),
            patch.object(ts, "list", return_value=[{"id": 1}]),
        ):
            with pytest.raises(RuntimeError):
                ts.add("/tmp/foo.torrent")

    def test_list_parses_rows(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        stdout = (
            "ID     Done       Have  ETA           Up    Down  Ratio  Status       Name\n"
            "  1   100%  1.50 GB  Done           0.0     0.0   1.0  Idle         my-list.7z\n"
            "  2    45%  500 MB   3 hours        0.0   200.0   0.1  Downloading  another-list.7z\n"
            "Sum:        2.00 GB                  0.0   200.0\n"
        )
        result = MagicMock(returncode=0, stdout=stdout, stderr="")
        with patch("subprocess.run", return_value=result):
            entries = ts.list()
        assert len(entries) == 2
        assert entries[0]["id"] == 1
        assert entries[0]["percent_done"] == 100.0
        assert entries[1]["id"] == 2
        assert entries[1]["percent_done"] == 45.0

    def test_list_returns_empty_on_nonzero_rc(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        result = MagicMock(returncode=1, stdout="", stderr="boom")
        with patch("subprocess.run", return_value=result):
            assert ts.list() == []

    def test_info_file_parses_path(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        stdout = (
            "myname.torrent (1 files):\n"
            "  #  Done Priority Get      Size       Name\n"
            "  0: 100% Normal   Yes      1.50 GB    my-list.7z\n"
        )
        result = MagicMock(returncode=0, stdout=stdout, stderr="")
        with patch("subprocess.run", return_value=result):
            name = ts.info_file(1)
        assert name == "my-list.7z"

    def test_info_file_returns_empty_on_failure(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        result = MagicMock(returncode=1, stdout="", stderr="bad")
        with patch("subprocess.run", return_value=result):
            assert ts.info_file(1) == ""

    def test_wait_for_all_invokes_callback_and_remove(self, tmp_path):
        ts = TransmissionSession(str(tmp_path), poll_interval=0.0)
        ts._rpc = "127.0.0.1:9999"
        # First poll: torrent at 100%. Second poll: empty.
        list_results = [
            [{"id": 1, "percent_done": 100.0, "status": "Idle", "name": "x"}],
            [],
        ]
        info_calls = []
        remove_calls = []

        def fake_list():
            return list_results.pop(0)

        def fake_info(tid):
            info_calls.append(tid)
            return "my-list.7z"

        def fake_remove(tid):
            remove_calls.append(tid)

        callbacks = []

        def on_complete(tid, name):
            callbacks.append((tid, name))

        with (
            patch.object(ts, "list", side_effect=fake_list),
            patch.object(ts, "info_file", side_effect=fake_info),
            patch.object(ts, "remove", side_effect=fake_remove),
            patch("time.sleep"),
        ):
            ts.wait_for_all(on_complete=on_complete)
        assert callbacks == [(1, "my-list.7z")]
        assert remove_calls == [1]
        assert info_calls == [1]

    def test_wait_for_all_calls_on_complete_when_info_file_empty(self, tmp_path):
        """on_complete must be called even when info_file returns "" so the caller
        can account for the torrent (e.g. increment a failure counter)."""
        ts = TransmissionSession(str(tmp_path), poll_interval=0.0)
        ts._rpc = "127.0.0.1:9999"
        list_results = [
            [{"id": 2, "percent_done": 100.0, "status": "Idle", "name": "x"}],
            [],
        ]
        callbacks = []

        with (
            patch.object(ts, "list", side_effect=lambda: list_results.pop(0)),
            patch.object(ts, "info_file", return_value=""),
            patch.object(ts, "remove"),
            patch("time.sleep"),
        ):
            ts.wait_for_all(on_complete=lambda tid, name: callbacks.append((tid, name)))

        assert callbacks == [(2, "")], (
            "on_complete must fire even when info_file returns empty"
        )

    def test_wait_for_all_keyboard_interrupt_propagates(self, tmp_path):
        ts = TransmissionSession(str(tmp_path), poll_interval=0.0)
        ts._rpc = "127.0.0.1:9999"
        with (
            patch.object(ts, "list", side_effect=KeyboardInterrupt),
            patch("time.sleep"),
        ):
            with pytest.raises(KeyboardInterrupt):
                ts.wait_for_all(on_complete=lambda *a: None)

    def test_exit_calls_stop_and_cleans_cfg_dir(self, tmp_path):
        proc_mock = MagicMock()
        probe_result = MagicMock(returncode=0, stdout="", stderr="")
        rmtree_mock = MagicMock()
        with (
            patch("hate_crack.api._pick_free_port", return_value=12345),
            patch("subprocess.Popen", return_value=proc_mock),
            patch("subprocess.run", return_value=probe_result) as run_mock,
            patch("atexit.register"),
            patch("tempfile.mkdtemp", return_value="/tmp/fake_cfg_dir"),
            patch("shutil.rmtree", rmtree_mock),
        ):
            with TransmissionSession(str(tmp_path)):
                pass
            # transmission-remote --exit was called
            exit_called = any(
                "--exit" in (call.args[0] if call.args else [])
                for call in run_mock.call_args_list
            )
            assert exit_called
            # cfg_dir removed
            rmtree_mock.assert_called_with("/tmp/fake_cfg_dir", ignore_errors=True)

    def test_stop_is_idempotent(self, tmp_path):
        ts = TransmissionSession(str(tmp_path))
        ts._stopped = True
        # No subprocess calls should be made when already stopped.
        with patch("subprocess.run") as run_mock:
            ts._stop()
        run_mock.assert_not_called()


class TestRunTorrentSession:
    def test_returns_early_when_daemon_missing(self):
        with (
            patch("hate_crack.api.check_transmission_daemon", return_value=False),
            patch("hate_crack.api.check_7z") as seven_z,
        ):
            run_torrent_session(["a.torrent"], "/tmp/save")
        seven_z.assert_not_called()

    def test_returns_early_when_7z_missing(self):
        with (
            patch("hate_crack.api.check_transmission_daemon", return_value=True),
            patch("hate_crack.api.check_7z", return_value=False),
            patch("hate_crack.api.TransmissionSession") as ts_cls,
        ):
            run_torrent_session(["a.torrent"], "/tmp/save")
        ts_cls.assert_not_called()

    def test_happy_path_adds_and_waits(self):
        ts_instance = MagicMock()
        ts_cls = MagicMock()
        ts_cls.return_value.__enter__ = MagicMock(return_value=ts_instance)
        ts_cls.return_value.__exit__ = MagicMock(return_value=None)
        with (
            patch("hate_crack.api.check_transmission_daemon", return_value=True),
            patch("hate_crack.api.check_7z", return_value=True),
            patch("hate_crack.api.TransmissionSession", ts_cls),
        ):
            run_torrent_session(["a.torrent", "b.torrent"], "/tmp/save")
        # ts.add called for each torrent
        assert ts_instance.add.call_count == 2
        ts_instance.wait_for_all.assert_called_once()

    def test_keyboard_interrupt_propagates(self):
        ts_instance = MagicMock()
        ts_instance.wait_for_all.side_effect = KeyboardInterrupt
        ts_cls = MagicMock()
        ts_cls.return_value.__enter__ = MagicMock(return_value=ts_instance)
        ts_cls.return_value.__exit__ = MagicMock(return_value=None)
        with (
            patch("hate_crack.api.check_transmission_daemon", return_value=True),
            patch("hate_crack.api.check_7z", return_value=True),
            patch("hate_crack.api.TransmissionSession", ts_cls),
        ):
            with pytest.raises(KeyboardInterrupt):
                run_torrent_session(["a.torrent"], "/tmp/save")


class TestGetHcatPotfilePath:
    def test_returns_config_value_when_set(self, tmp_path):
        config_data = {"hcatPotfilePath": "/custom/hashcat.potfile"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch(
            "hate_crack.api._resolve_config_path", return_value=str(config_file)
        ):
            result = get_hcat_potfile_path()
        assert result == "/custom/hashcat.potfile"

    def test_returns_default_when_key_missing(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({}))
        with patch(
            "hate_crack.api._resolve_config_path", return_value=str(config_file)
        ):
            result = get_hcat_potfile_path()
        # Not the hardcoded pre-7 ~/.hashcat path: hashcat 7 moved per-user
        # state, and pinning the old location left hate_crack reading an empty
        # potfile while hashcat wrote the real one elsewhere.
        assert result == hashcat_paths.default_potfile_path()

    def test_returns_empty_string_when_key_is_empty(self, tmp_path):
        config_data = {"hcatPotfilePath": ""}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch(
            "hate_crack.api._resolve_config_path", return_value=str(config_file)
        ):
            result = get_hcat_potfile_path()
        assert result == ""

    def test_resolves_relative_path_from_config_dir(self, tmp_path):
        config_data = {"hcatPotfilePath": "hashcat.potfile"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with (
            patch("hate_crack.api._resolve_config_path", return_value=str(config_file)),
            patch("hate_crack.api._get_hate_path", return_value=str(tmp_path)),
        ):
            result = get_hcat_potfile_path()
        assert result == str(tmp_path / "hashcat.potfile")

    def test_returns_default_when_no_config(self):
        with patch("hate_crack.api._resolve_config_path", return_value=None):
            result = get_hcat_potfile_path()
        assert result == hashcat_paths.default_potfile_path()

    def test_expands_tilde_in_config_value(self, tmp_path):
        config_data = {"hcatPotfilePath": "~/.custom/hashcat.potfile"}
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))
        with patch(
            "hate_crack.api._resolve_config_path", return_value=str(config_file)
        ):
            result = get_hcat_potfile_path()
        assert result == os.path.expanduser("~/.custom/hashcat.potfile")
        assert "~" not in result


class TestGetHcatPotfileArgs:
    def test_returns_list_with_potfile_arg(self):
        with patch(
            "hate_crack.api.get_hcat_potfile_path",
            return_value="/some/path/hashcat.potfile",
        ):
            result = get_hcat_potfile_args()
        assert result == ["--potfile-path=/some/path/hashcat.potfile"]

    def test_returns_non_empty_list_by_default(self):
        # Default path always resolves to something (expanduser never returns empty)
        with patch("hate_crack.api._resolve_config_path", return_value=None):
            result = get_hcat_potfile_args()
        assert len(result) == 1
        assert result[0].startswith("--potfile-path=")


class TestGetHashmobApiKey:
    """These used to patch ``os.path.isfile``/``dirname``/``abspath`` wholesale so
    the helper's own hand-rolled config.json walk would land on a fixture. That
    walk is gone -- the helper goes through ``_load_merged_config()`` now -- so
    the tests patch the two path-resolution seams instead, which is both narrower
    and actually representative of how the value is found at runtime.
    """

    def test_returns_key_from_the_env_file(self, tmp_path, monkeypatch):
        """``hashmob_api_key`` is ``home="env"``, so the value comes from
        `.env`. A leftover entry in ``config.json`` is deliberately ignored --
        see test_returns_none_when_only_config_json_has_it."""
        env_file = tmp_path / ".env"
        env_file.write_text("HASHMOB_API_KEY=placeholder-dotenv\n")
        monkeypatch.setattr(api, "_resolve_env_path", lambda: str(env_file))
        monkeypatch.setattr(api, "_resolve_config_path", lambda: None)

        assert get_hashmob_api_key() == "placeholder-dotenv"

    def test_returns_none_when_only_config_json_has_it(self, tmp_path, monkeypatch):
        """The key's home is `.env`; a stale ``config.json`` entry must not be
        read, or a user who updated `.env` would keep getting the old value."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"hashmob_api_key": "placeholder-json"}))
        monkeypatch.setattr(api, "_resolve_env_path", lambda: None)
        monkeypatch.setattr(api, "_resolve_config_path", lambda: str(config_file))

        assert get_hashmob_api_key() is None

    def test_returns_none_when_missing(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({}))
        monkeypatch.setattr(api, "_resolve_env_path", lambda: None)
        monkeypatch.setattr(api, "_resolve_config_path", lambda: str(config_file))

        # Schema default is "", which callers test with `if key:` -- so this
        # helper must keep normalising it to None.
        assert get_hashmob_api_key() is None

    def test_returns_none_when_no_config(self, monkeypatch):
        monkeypatch.setattr(api, "_resolve_env_path", lambda: None)
        monkeypatch.setattr(api, "_resolve_config_path", lambda: None)

        assert get_hashmob_api_key() is None

    def test_env_file_wins_over_a_leftover_config_json(self, tmp_path, monkeypatch):
        """The regression this fix is for: after migrating to `.env`, updating
        HASHMOB_API_KEY there must take effect. The old private search order read
        config.json only, so a user kept getting the stale value with nothing to
        indicate why.
        """
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"hashmob_api_key": "placeholder-stale"}))
        env_file = tmp_path / ".env"
        write_env(str(env_file), {"hashmob_api_key": "placeholder-current"})
        monkeypatch.setattr(api, "_resolve_env_path", lambda: str(env_file))
        monkeypatch.setattr(api, "_resolve_config_path", lambda: str(config_file))

        assert get_hashmob_api_key() == "placeholder-current"

    def test_process_environment_wins_over_the_env_file(self, tmp_path, monkeypatch):
        env_file = tmp_path / ".env"
        write_env(str(env_file), {"hashmob_api_key": "placeholder-dotenv"})
        monkeypatch.setattr(api, "_resolve_env_path", lambda: str(env_file))
        monkeypatch.setattr(api, "_resolve_config_path", lambda: None)
        monkeypatch.setenv("HASHMOB_API_KEY", "placeholder-environ")

        assert get_hashmob_api_key() == "placeholder-environ"


class TestFetchTorrentMetadataApiKey:
    def test_api_key_not_sent_to_weakpass(self, tmp_path, monkeypatch):
        """fetch_torrent_metadata() must not send the Hashmob API key to weakpass.com."""
        env_file = tmp_path / ".env"
        write_env(str(env_file), {"hashmob_api_key": "placeholder-current"})
        monkeypatch.setattr(api, "_resolve_env_path", lambda: str(env_file))
        monkeypatch.setattr(api, "_resolve_config_path", lambda: None)
        monkeypatch.setattr(api, "register_torrent_cleanup", lambda: None)

        seen = {}

        def _fake_get(url, headers=None, timeout=None, **kwargs):
            seen["headers"] = headers
            raise RuntimeError("stop here: the header is all this test needs")

        monkeypatch.setattr(api.requests, "get", _fake_get)
        with pytest.raises(RuntimeError):
            api.fetch_torrent_metadata("http://example.invalid/a.torrent")

        assert "api-key" not in seen["headers"]


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
        with (
            patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = extract_with_7z(str(archive), str(tmp_path), remove_archive=False)
        assert result is True

    def test_returns_false_on_failure(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=1)
        with (
            patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = extract_with_7z(str(archive), str(tmp_path))
        assert result is False

    def test_removes_archive_on_success(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=0)
        with (
            patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = extract_with_7z(str(archive), str(tmp_path), remove_archive=True)
        assert result is True
        assert not archive.exists()

    def test_keeps_archive_when_remove_false(self, tmp_path):
        archive = tmp_path / "test.7z"
        archive.write_text("fake archive data")
        mock_result = self._make_run_result(returncode=0)
        with (
            patch("hate_crack.api.shutil.which", return_value="/usr/bin/7z"),
            patch("subprocess.run", return_value=mock_result),
        ):
            result = extract_with_7z(str(archive), str(tmp_path), remove_archive=False)
        assert result is True
        assert archive.exists()


class TestDownloadHashmobWordlistListSizeAndLineCount:
    def _mock_resource_response(self, data):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = data
        return mock_response

    def test_entry_includes_human_size_and_line_count(self, capsys):
        data = [
            {
                "type": "wordlist",
                "name": "rockyou",
                "information": "classic",
                "file_size": 139921507,
                "line_count": 14344391,
            }
        ]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            result = download_hashmob_wordlist_list()
        out = capsys.readouterr().out
        assert result == data
        assert "MB" in out
        assert "14,344,391 lines" in out

    def test_omits_line_count_clause_when_missing_or_zero(self, capsys):
        data = [
            {"type": "wordlist", "name": "no_line_count", "file_size": 512},
            {
                "type": "wordlist",
                "name": "zero_line_count",
                "file_size": 1024,
                "line_count": 0,
            },
        ]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            download_hashmob_wordlist_list()
        out = capsys.readouterr().out
        assert "lines" not in out
        assert "B" in out  # the size string is still present


class TestDownloadHashmobRuleListSizeAndLineCount:
    def _mock_resource_response(self, data):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = data
        return mock_response

    def test_entry_includes_human_size_and_line_count(self, capsys):
        data = [
            {
                "type": "rule",
                "name": "best64",
                "file_size": 1288,
                "line_count": 77,
            }
        ]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            result = download_hashmob_rule_list()
        out = capsys.readouterr().out
        assert result == data
        assert "77 lines" in out
        assert "KB" in out or "B" in out

    def test_omits_line_count_clause_when_missing(self, capsys):
        data = [{"type": "official_rule", "name": "no_meta.rule"}]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            download_hashmob_rule_list()
        out = capsys.readouterr().out
        assert "lines" not in out


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
        mock_response = self._make_mock_response(
            status_code=200, content=b"wordlist data"
        )
        out = tmp_path / "test.txt"
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
        ):
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
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
        ):
            result = download_hashmob_wordlist("test.txt", str(out))
        assert result is False


class TestDownloadHashmobRule:
    def _make_mock_response(self, status_code=200, content=b"rule data"):
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status_code = status_code
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.iter_content.return_value = [content]
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def test_rule_type_uses_www_hashmob_rules_url(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "best64.rule"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_rule(
                "best64.rule", str(out), resource_type="rule"
            )
        assert result is True
        called_url = mock_get.call_args.args[0]
        assert (
            called_url
            == "https://www.hashmob.net/api/v2/downloads/research/rules/best64.rule"
        )

    def test_official_rule_type_uses_official_hashmob_rules_url(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "HashMob.10k.rule"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_rule(
                "HashMob.10k.rule", str(out), resource_type="official_rule"
            )
        assert result is True
        called_url = mock_get.call_args.args[0]
        assert (
            called_url
            == "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.10k.rule"
        )

    def test_404_on_primary_falls_back_to_official_alternate_url(self, tmp_path):
        mock_404 = self._make_mock_response(status_code=404)
        mock_ok = self._make_mock_response(status_code=200)
        out = tmp_path / "some.rule"
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_404, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_rule("some.rule", str(out), resource_type="rule")
        assert result is True
        assert mock_get.call_count == 2
        first_url = mock_get.call_args_list[0].args[0]
        second_url = mock_get.call_args_list[1].args[0]
        assert (
            first_url
            == "https://www.hashmob.net/api/v2/downloads/research/rules/some.rule"
        )
        assert (
            second_url
            == "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/some.rule"
        )

    def test_missing_resource_type_falls_back_to_public_prefix(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "unknown.rule"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_rule("unknown.rule", str(out))
        assert result is True
        called_url = mock_get.call_args.args[0]
        assert (
            called_url
            == "https://www.hashmob.net/api/v2/downloads/research/rules/unknown.rule"
        )


class TestDownloadHashmobMaskList:
    def _mock_resource_response(self, data):
        mock_response = MagicMock()
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = data
        return mock_response

    def test_filters_masks_type_only(self, capsys):
        data = [
            {"type": "wordlist", "file_name": "rockyou.txt"},
            {"type": "masks", "file_name": "rockyou-1-60.hcmask"},
            {"type": "rule", "file_name": "best64.rule"},
            {"type": "masks", "file_name": "hashcat-default.hcmask"},
        ]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            result = download_hashmob_mask_list()
        assert len(result) == 2
        assert all(r["type"] == "masks" for r in result)

    def test_dedupes_by_file_name_keeping_first_occurrence(self, capsys):
        data = [
            {"type": "masks", "file_name": "hashcat-default.hcmask", "name": "first"},
            {"type": "masks", "file_name": "hashcat-default.hcmask", "name": "second"},
            {"type": "masks", "file_name": "rockyou-1-60.hcmask", "name": "unique"},
        ]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            result = download_hashmob_mask_list()
        names = [r["file_name"] for r in result]
        assert names == ["hashcat-default.hcmask", "rockyou-1-60.hcmask"]
        assert result[0]["name"] == "first"

    def test_entry_includes_human_size_and_line_count(self, capsys):
        data = [
            {
                "type": "masks",
                "name": "rockyou-1-60",
                "file_name": "rockyou-1-60.hcmask",
                "file_size": 1024,
                "line_count": 12,
            }
        ]
        with patch(
            "hate_crack.api.requests.get",
            return_value=self._mock_resource_response(data),
        ):
            download_hashmob_mask_list()
        out = capsys.readouterr().out
        assert "12 lines" in out
        assert "KB" in out or "B" in out


class TestDownloadHashmobMask:
    def _make_mock_response(self, status_code=200, content=b"mask data"):
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status_code = status_code
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.iter_content.return_value = [content]
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def test_successful_download(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "test.hcmask"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_mask("test.hcmask", str(out))
        assert result is True
        assert out.exists()
        assert out.read_bytes() == b"mask data"
        called_url = mock_get.call_args.args[0]
        assert (
            called_url
            == "https://hashmob.net/api/v2/downloads/research/masks/test.hcmask"
        )

    def test_sends_api_key_header_when_configured(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "test.hcmask"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value="secret-key"),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            download_hashmob_mask("test.hcmask", str(out))
        assert mock_get.call_args.kwargs["headers"] == {"api-key": "secret-key"}

    def test_calls_limiter_before_request(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "test.hcmask"
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            download_hashmob_mask("test.hcmask", str(out))
        mock_wait.assert_called_once()

    def test_429_triggers_backoff_and_retries(self, tmp_path):
        mock_429 = self._make_mock_response(status_code=429)
        mock_ok = self._make_mock_response(status_code=200)
        out = tmp_path / "test.hcmask"
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_mask("test.hcmask", str(out))
        assert result is True
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()

    def test_404_returns_false(self, tmp_path):
        import requests as req

        mock_response = self._make_mock_response(status_code=404)
        mock_response.raise_for_status.side_effect = req.exceptions.HTTPError(
            response=MagicMock(status_code=404)
        )
        out = tmp_path / "test.hcmask"
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_mask("test.hcmask", str(out))
        assert result is False


class TestListHashmobArchives:
    def _mock_response(self, data, status_code=200):
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = data
        return mock_response

    def test_flattens_year_keyed_dict(self, capsys):
        data = {
            "current": [
                {
                    "name": "current.7z",
                    "url": "https://hashmob.net/api/v2/archive/current.7z",
                }
            ],
            "2021": [
                {
                    "name": "2021_a.7z",
                    "url": "https://hashmob.net/api/v2/archive/2021_a.7z",
                },
                {
                    "name": "2021_b.7z",
                    "url": "https://hashmob.net/api/v2/archive/2021_b.7z",
                },
            ],
        }
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_archives()
        assert len(result) == 3
        assert {entry["year"] for entry in result} == {"current", "2021"}
        assert [entry["name"] for entry in result] == [
            "current.7z",
            "2021_a.7z",
            "2021_b.7z",
        ]
        assert [entry["url"] for entry in result] == [
            "https://hashmob.net/api/v2/archive/current.7z",
            "https://hashmob.net/api/v2/archive/2021_a.7z",
            "https://hashmob.net/api/v2/archive/2021_b.7z",
        ]
        out = capsys.readouterr().out
        assert "current:" in out
        assert "2021:" in out

    def test_calls_limiter_and_sends_api_key(self):
        data = {
            "2022": [{"name": "a.7z", "url": "https://hashmob.net/api/v2/archive/a.7z"}]
        }
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ) as mock_get,
            patch("hate_crack.api.get_hashmob_api_key", return_value="secret-key"),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            list_hashmob_archives()
        mock_wait.assert_called_once()
        assert mock_get.call_args.kwargs["headers"] == {"api-key": "secret-key"}

    def test_429_triggers_backoff_and_retries(self):
        mock_429 = self._mock_response({}, status_code=429)
        mock_429.headers = {}
        mock_ok = self._mock_response({"2022": []})
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_archives()
        assert result == []
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()

    def test_empty_response_returns_empty_list(self):
        with (
            patch("hate_crack.api.requests.get", return_value=self._mock_response({})),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_archives()
        assert result == []


class TestDownloadHashmobArchive:
    def _make_mock_response(self, status_code=200, content=b"archive data"):
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status_code = status_code
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.iter_content.return_value = [content]
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def _patch_stdin_tty(self):
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True
        return patch("hate_crack.api.sys.stdin", mock_stdin)

    def _patch_stdin_no_tty(self):
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = False
        return patch("hate_crack.api.sys.stdin", mock_stdin)

    def test_resolves_url_from_listing_entry(self, tmp_path):
        entry = {
            "year": "2021",
            "name": "2021_a.7z",
            "url": "https://hashmob.net/api/v2/archive/2021_a.7z",
        }
        mock_response = self._make_mock_response()
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("builtins.input", return_value="y"),
            self._patch_stdin_tty(),
        ):
            result = download_hashmob_archive(entry)
        assert result is True
        assert (
            mock_get.call_args.args[0] == "https://hashmob.net/api/v2/archive/2021_a.7z"
        )
        assert (tmp_path / "2021_a.7z").exists()

    def test_constructs_url_from_bare_file_name(self, tmp_path):
        mock_response = self._make_mock_response()
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("builtins.input", return_value="y"),
            self._patch_stdin_tty(),
        ):
            result = download_hashmob_archive("full.7z")
        assert result is True
        assert (
            mock_get.call_args.args[0] == "https://hashmob.net/api/v2/archive/full.7z"
        )

    def test_declined_confirmation_aborts_download(self, tmp_path):
        entry = {"name": "big.7z", "url": "https://hashmob.net/api/v2/archive/big.7z"}
        with (
            patch("hate_crack.api.requests.get") as mock_get,
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("builtins.input", return_value="n"),
            self._patch_stdin_tty(),
        ):
            result = download_hashmob_archive(entry)
        assert result is False
        mock_get.assert_not_called()

    def test_non_interactive_context_declines_without_prompting(self, tmp_path):
        entry = {"name": "big.7z", "url": "https://hashmob.net/api/v2/archive/big.7z"}
        with (
            patch("hate_crack.api.requests.get") as mock_get,
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            self._patch_stdin_no_tty(),
        ):
            result = download_hashmob_archive(entry)
        assert result is False
        mock_get.assert_not_called()

    def test_calls_limiter_before_request(self, tmp_path):
        mock_response = self._make_mock_response()
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("builtins.input", return_value="y"),
            self._patch_stdin_tty(),
        ):
            download_hashmob_archive("full.7z")
        mock_wait.assert_called_once()


class TestListHashmobCombinedLeft:
    def _mock_response(self, data, status_code=200):
        mock_response = MagicMock()
        mock_response.status_code = status_code
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = data
        return mock_response

    def test_parses_combined_left_files(self, capsys):
        data = {
            "combined_left_files": [
                {
                    "mode": 0,
                    "hash_count": 1234567,
                    "algorithm": "MD5",
                    "time": "1h",
                    "updated_at": "2026-08-01",
                },
                {
                    "mode": 1000,
                    "hash_count": 89,
                    "algorithm": "NTLM",
                    "time": "1h",
                    "updated_at": "2026-08-15",
                },
            ]
        }
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_combined_left()
        assert result == data["combined_left_files"]
        out = capsys.readouterr().out
        assert "0: MD5 (1,234,567 hashes, updated 2026-08-01)" in out
        assert "1000: NTLM (89 hashes, updated 2026-08-15)" in out

    def test_missing_key_returns_empty_list(self):
        with (
            patch("hate_crack.api.requests.get", return_value=self._mock_response({})),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_combined_left()
        assert result == []


class TestDownloadHashmobCombinedLeft:
    def _make_mock_response(self, status_code=200, content=b"left data"):
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status_code = status_code
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.iter_content.return_value = [content]
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def test_default_variant_builds_all_url(self, tmp_path):
        mock_response = self._make_mock_response()
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
        ):
            result = download_hashmob_combined_left(1000)
        assert result is True
        assert (
            mock_get.call_args.args[0]
            == "https://hashmob.net/api/v2/downloads/combined_left/1000"
        )

    def test_official_variant_builds_official_url(self, tmp_path):
        mock_response = self._make_mock_response()
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
        ):
            download_hashmob_combined_left(0, variant="official")
        assert (
            mock_get.call_args.args[0]
            == "https://hashmob.net/api/v2/downloads/official_combined_left/0"
        )

    def test_premium_variant_builds_premium_url(self, tmp_path):
        mock_response = self._make_mock_response()
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
        ):
            download_hashmob_combined_left(100, variant="premium")
        assert (
            mock_get.call_args.args[0]
            == "https://hashmob.net/api/v2/downloads/combined_left_premium/100"
        )

    def test_invalid_variant_raises_value_error(self, tmp_path):
        with patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)):
            with pytest.raises(ValueError):
                download_hashmob_combined_left(0, variant="bogus")

    def test_defaults_to_wordlists_dir(self, tmp_path):
        mock_response = self._make_mock_response()
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
        ):
            download_hashmob_combined_left(1000)
        found = list(tmp_path.glob("combined_left_all_1000*"))
        assert found


class TestDownloadOfficialWordlist:
    def _make_mock_response(self, status_code=200, content=b"official wordlist data"):
        mock_response = MagicMock()
        mock_response.__enter__ = lambda s: mock_response
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_response.status_code = status_code
        mock_response.headers = {"Content-Type": "application/octet-stream"}
        mock_response.iter_content.return_value = [content]
        mock_response.raise_for_status = MagicMock()
        return mock_response

    def test_writes_to_caller_supplied_out_path(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "custom_name.txt"
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
        ):
            result = download_official_wordlist("official.txt", str(out))
        assert result is True
        assert out.exists()
        assert out.read_bytes() == b"official wordlist data"

    def test_falls_back_to_sanitized_name_under_wordlists_dir_when_out_path_omitted(
        self, tmp_path
    ):
        mock_response = self._make_mock_response()
        with (
            patch("hate_crack.api.requests.get", return_value=mock_response),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
        ):
            result = download_official_wordlist("official file.txt")
        assert result is True
        expected = tmp_path / sanitize_filename("official file.txt")
        assert expected.exists()

    def test_sends_api_key_header_and_waits_on_limiter(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "official.txt"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch(
                "hate_crack.api.get_hashmob_api_key",
                return_value="placeholder-key",
            ),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            result = download_official_wordlist("official.txt", str(out))
        assert result is True
        mock_wait.assert_called_once()
        assert mock_get.call_args.kwargs["headers"] == {"api-key": "placeholder-key"}

    def test_no_api_key_omits_header(self, tmp_path):
        mock_response = self._make_mock_response()
        out = tmp_path / "official.txt"
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
        ):
            download_official_wordlist("official.txt", str(out))
        assert mock_get.call_args.kwargs["headers"] == {}

    def test_retries_through_backoff_on_429(self, tmp_path):
        mock_429 = self._make_mock_response(status_code=429)
        mock_ok = self._make_mock_response(status_code=200)
        out = tmp_path / "official.txt"
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_official_wordlist("official.txt", str(out))
        assert result is True
        assert mock_get.call_count == 2
        assert mock_sleep.call_count == 1
        assert out.exists()

    def test_meta_refresh_redirect_uses_verbatim_url(self, tmp_path):
        real_url = "https://real-server.example.com/actual_official_file.7z"
        html_content = (
            "<html><head>"
            f'<meta http-equiv="refresh" content="0;url={real_url}">'
            "</head></html>"
        ).encode()
        mock_resp = _make_mock_response(
            status_code=200,
            content=html_content,
            content_type="text/plain",
        )
        out = tmp_path / "official.7z"
        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api._streamed_download", return_value=True) as mock_sd,
        ):
            download_official_wordlist("official.7z", str(out))

        mock_sd.assert_called_once()
        called_url = mock_sd.call_args.args[0]
        assert called_url == real_url

    def test_html_without_meta_refresh_returns_false_and_does_not_write_file(
        self, tmp_path
    ):
        html_content = b"<html><body>Quota exceeded</body></html>"
        mock_resp = _make_mock_response(
            status_code=200,
            content=html_content,
            content_type="text/plain",
        )
        out = tmp_path / "official.7z"
        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_official_wordlist("official.7z", str(out))

        assert result is False
        assert not out.exists()


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
        with (
            patch("hate_crack.api.download_hashmob_rule_list", return_value=rules),
            patch("hate_crack.api.download_hashmob_rule") as mock_dl,
            self._patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_rules(rules_dir=rules_dir)
        assert mock_dl.call_count == 3
        downloaded_names = {c.args[0] for c in mock_dl.call_args_list}
        assert downloaded_names == {"rule1.rule", "rule2.rule", "rule3.rule"}

    def test_failure_does_not_block_others(self, tmp_path, capsys):
        rules = self._make_rules(["good.rule", "bad.rule", "also_good.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        def side_effect(file_name, out_path, resource_type=None):
            if file_name == "bad.rule":
                raise RuntimeError("download error")

        with (
            patch("hate_crack.api.download_hashmob_rule_list", return_value=rules),
            patch("hate_crack.api.download_hashmob_rule", side_effect=side_effect),
            self._patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        captured = capsys.readouterr()
        assert "2 succeeded" in captured.out
        assert "1 failed" in captured.out

    def test_skips_already_downloaded(self, tmp_path, capsys):
        rules = self._make_rules(["existing.rule", "new.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        (tmp_path / "rules" / "existing.rule").touch()
        with (
            patch("hate_crack.api.download_hashmob_rule_list", return_value=rules),
            patch("hate_crack.api.download_hashmob_rule") as mock_dl,
            self._patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
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
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(
                fn, max_attempts=3, base_delay=1, step=1, max_delay=10
            )
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
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(
                fn, max_attempts=6, base_delay=1, step=1, max_delay=10
            )
        assert result is True
        assert fn.call_count == 3
        assert mock_sleep.call_count == 2

    def test_non_429_exception_reraises(self):
        fn = MagicMock(side_effect=ValueError("not a 429"))
        with pytest.raises(ValueError, match="not a 429"):
            _with_hashmob_backoff(fn)

    def test_respects_retry_after_over_default_ladder_step(self):
        """A 429 carrying Retry-After: 5 should sleep ~5s, not the default
        30s ladder step."""
        fn = MagicMock(side_effect=[_Hashmob429(retry_after=5.0), True])
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(fn)
        assert result is True
        mock_sleep.assert_called_once_with(5.0)

    def test_retry_after_still_capped_by_max_delay(self):
        fn = MagicMock(side_effect=[_Hashmob429(retry_after=9999.0), True])
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(
                fn, max_attempts=6, base_delay=30, step=30, max_delay=300
            )
        assert result is True
        mock_sleep.assert_called_once_with(300)

    def test_missing_retry_after_falls_back_to_ladder(self):
        """A 429 with no Retry-After keeps the existing fixed-ladder delay."""
        fn = MagicMock(side_effect=[_Hashmob429(), True])
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(
                fn, max_attempts=6, base_delay=30, step=30, max_delay=300
            )
        assert result is True
        mock_sleep.assert_called_once_with(30)

    def test_retry_after_advances_ladder_for_subsequent_attempts(self):
        """A later 429 with no Retry-After must still see the ladder having
        advanced, even though the first attempt slept for retry_after instead
        of the ladder's own penalty."""
        fn = MagicMock(side_effect=[_Hashmob429(retry_after=5.0), _Hashmob429(), True])
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(
                fn, max_attempts=6, base_delay=30, step=30, max_delay=300
            )
        assert result is True
        assert mock_sleep.call_args_list == [call(5.0), call(60)]


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
        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp),
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api._streamed_download", return_value=True) as mock_sd,
        ):
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

        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get,
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist") as mock_dl,
            patch("hate_crack.api.sys.stdin", mock_stdin),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_official_wordlists()

        assert mock_dl.call_count == 1
        called_filename = mock_dl.call_args.args[0]
        assert called_filename == "new.txt"
        assert mock_get.call_args.kwargs["headers"] == {}
        captured = capsys.readouterr()
        assert "Skipping existing.txt" in captured.out

    def test_sends_api_key_header_on_listing_request(self, tmp_path, capsys):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()

        api_data = [{"file_name": "new.txt"}]
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = api_data

        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True

        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get,
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist"),
            patch("hate_crack.api.sys.stdin", mock_stdin),
            patch("builtins.input", return_value="a"),
            patch(
                "hate_crack.api.get_hashmob_api_key",
                return_value="placeholder-key",
            ),
        ):
            list_and_download_official_wordlists()

        assert mock_get.call_args.kwargs["headers"] == {"api-key": "placeholder-key"}


class TestGetWeakpassInertiaVersion:
    def setup_method(self):
        _api_mod._WEAKPASS_INERTIA_VERSION = None  # reset cache before each test

    def _html(self, version):
        return f'<div id="app" data-page="{{&quot;version&quot;:&quot;{version}&quot;,&quot;props&quot;:{{}}}}"></div>'

    def test_returns_version_from_html(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = self._html("abc123def456")
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod._get_weakpass_inertia_version({"User-Agent": "test"})
        assert result == "abc123def456"

    def test_caches_version_on_second_call(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = self._html("cached_ver")
        with patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get:
            _api_mod._get_weakpass_inertia_version({"User-Agent": "test"})
            _api_mod._get_weakpass_inertia_version({"User-Agent": "test"})
        assert mock_get.call_count == 1  # second call uses cache

    def test_returns_none_on_network_error(self):
        with patch("hate_crack.api.requests.get", side_effect=Exception("timeout")):
            result = _api_mod._get_weakpass_inertia_version({"User-Agent": "test"})
        assert result is None

    def test_returns_none_when_version_absent(self):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = '<div id="app" data-page="{&quot;props&quot;:{}}"></div>'
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod._get_weakpass_inertia_version({"User-Agent": "test"})
        assert result is None


class TestFetchWeakpassListingPage:
    def setup_method(self):
        _api_mod._WEAKPASS_INERTIA_VERSION = None

    def _inertia_json(self, entries, last_page=1):
        """Return the JSON dict that Inertia returns directly."""
        return {
            "props": {
                "wordlists": {
                    "data": entries,
                    "last_page": last_page,
                }
            }
        }

    def _html_with_data_page(self, props_dict):
        """Return HTML with data-page attribute encoding the given props."""
        import json as _json

        payload = _json.dumps({"props": props_dict}).replace('"', "&quot;")
        return f'<div id="app" data-page="{payload}"></div>'

    def test_uses_inertia_headers_when_version_available(self):
        _api_mod._WEAKPASS_INERTIA_VERSION = "ver123"
        entry = {
            "id": 1,
            "name": "test.txt",
            "torrent_link": "test.txt.7z.torrent",
            "size": 100,
            "rank": 5,
            "downloaded": 10,
        }
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = self._inertia_json([entry], last_page=3)
        with patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get:
            entries, last_page = _api_mod._fetch_weakpass_listing_page(
                1, {"User-Agent": "t"}
            )
        sent_headers = mock_get.call_args[1]["headers"]
        assert sent_headers.get("X-Inertia") == "true"
        assert sent_headers.get("X-Inertia-Version") == "ver123"
        assert sent_headers.get("X-Requested-With") == "XMLHttpRequest"
        assert len(entries) == 1
        assert entries[0]["name"] == "test.txt"
        assert entries[0]["torrent_url"] == "test.txt.7z.torrent"
        assert last_page == 3

    def test_falls_back_to_html_parse_when_version_unavailable(self):
        # _WEAKPASS_INERTIA_VERSION is None; preflight also fails
        entry = {
            "id": 2,
            "name": "rock.txt",
            "torrent_link": "rock.txt.7z.torrent",
            "size": 200,
            "rank": 4,
            "downloaded": 5,
        }
        html = self._html_with_data_page(
            {"wordlists": {"data": [entry], "last_page": 1}}
        )
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = html
        with (
            patch("hate_crack.api._get_weakpass_inertia_version", return_value=None),
            patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get,
        ):
            entries, last_page = _api_mod._fetch_weakpass_listing_page(
                1, {"User-Agent": "t"}
            )
        sent_headers = mock_get.call_args[1]["headers"]
        assert "X-Inertia" not in sent_headers
        assert len(entries) == 1
        assert entries[0]["name"] == "rock.txt"

    def test_clears_version_cache_and_retries_on_409(self):
        _api_mod._WEAKPASS_INERTIA_VERSION = "stale_ver"
        entry = {
            "id": 3,
            "name": "mini.txt",
            "torrent_link": "mini.txt.7z.torrent",
            "size": 50,
            "rank": 6,
            "downloaded": 1,
        }
        resp_409 = MagicMock()
        resp_409.status_code = 409
        html = self._html_with_data_page(
            {"wordlists": {"data": [entry], "last_page": 1}}
        )
        resp_html = MagicMock()
        resp_html.status_code = 200
        resp_html.text = html
        with patch("hate_crack.api.requests.get", side_effect=[resp_409, resp_html]):
            entries, last_page = _api_mod._fetch_weakpass_listing_page(
                1, {"User-Agent": "t"}
            )
        assert _api_mod._WEAKPASS_INERTIA_VERSION is None  # cache cleared
        assert len(entries) == 1
        assert entries[0]["name"] == "mini.txt"

    def test_returns_empty_on_non_200(self):
        _api_mod._WEAKPASS_INERTIA_VERSION = "ver"
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp),
            patch("hate_crack.api._get_weakpass_inertia_version", return_value="ver"),
        ):
            entries, last_page = _api_mod._fetch_weakpass_listing_page(
                1, {"User-Agent": "t"}
            )
        assert entries == []
        assert last_page is None


class TestMatchEntry:
    def _entries(self):
        return [
            {"id": 10, "name": "rockyou.txt", "torrent_url": "rockyou.txt.7z.torrent"},
            {
                "id": 20,
                "name": "ignis-10K.txt",
                "torrent_url": "ignis-10K.txt.7z.torrent",
            },
            {
                "id": 30,
                "name": "hashmob.net_2025.micro.found",
                "torrent_url": "hashmob.net_2025.micro.found.7z.torrent",
            },
        ]

    def test_exact_name_match(self):
        result = _api_mod._match_entry(self._entries(), "ignis-10K.txt")
        assert result == (20, "ignis-10K.txt.7z.torrent")

    def test_wordlist_base_partial_match(self):
        # "ignis-10K" (base after stripping .txt) matches entry named "ignis-10K.txt"
        result = _api_mod._match_entry(self._entries(), "ignis-10K")
        assert result == (20, "ignis-10K.txt.7z.torrent")

    def test_substring_match_does_not_fire_on_ambiguous_base(self):
        # "rock" is a substring of "rockyou.txt" but "rock" stripped of extensions is still "rock"
        # Only an exact name "rock" or an entry containing substring "rock" would match.
        # This documents the known behavior: "rock" DOES match "rockyou.txt" via substring.
        result = _api_mod._match_entry(self._entries(), "rock")
        # "rock" is a substring of "rockyou.txt", so it matches — document this behavior
        assert result == (10, "rockyou.txt.7z.torrent")

    def test_no_match_returns_none(self):
        result = _api_mod._match_entry(self._entries(), "mini.txt")
        assert result is None

    def test_empty_entries_returns_none(self):
        result = _api_mod._match_entry([], "rockyou.txt")
        assert result is None

    def test_filename_without_txt_extension_matches(self):
        # "hashmob.net_2025.micro.found" has no .txt to strip; base == filename
        result = _api_mod._match_entry(self._entries(), "hashmob.net_2025.micro.found")
        assert result == (30, "hashmob.net_2025.micro.found.7z.torrent")


class TestStreamedDownloadChunkSize:
    """chunk_size was accepted by _streamed_download and never forwarded, so
    tuning it did nothing (the writer hardcoded 8192)."""

    def _fake_response(self):
        r = MagicMock()
        r.__enter__ = lambda s: s
        r.__exit__ = lambda s, *a: False
        r.headers = {}
        r.iter_content = MagicMock(return_value=[b"data"])
        return r

    def test_custom_chunk_size_reaches_iter_content(self, tmp_path):
        r = self._fake_response()
        with patch.object(_api_mod.requests, "get", return_value=r):
            ok = _streamed_download(
                "http://example.invalid/f.txt",
                str(tmp_path / "f.txt"),
                chunk_size=4096,
                show_progress=False,
            )
        assert ok is True
        r.iter_content.assert_called_once_with(chunk_size=4096)

    def test_default_chunk_size_is_unchanged(self, tmp_path):
        r = self._fake_response()
        with patch.object(_api_mod.requests, "get", return_value=r):
            _streamed_download(
                "http://example.invalid/f.txt",
                str(tmp_path / "f.txt"),
                show_progress=False,
            )
        r.iter_content.assert_called_once_with(chunk_size=8192)
