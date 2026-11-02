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
    _parse_hashmob_found_name,
    _pick_free_port,
    _replace_older_hashmob_found,
    _streamed_download,
    _with_hashmob_backoff,
    list_and_download_official_wordlists,
)
import requests as req_lib

from hate_crack.config_writer import write_env

def _weakpass_entry(id, name="list", rank="S", size=100, count=10, rate=1.0,
                    slug=None, torrent_url="url"):
    """Build a single Weakpass wordlist entry for tests."""
    return {"id": id, "name": name, "rank": rank, "size": size, "count": count,
            "rate": rate, "slug": slug or name, "torrent_url": torrent_url}

def _json_response(data, last_page=1):
    """Mock a paged Weakpass API JSON response."""
    resp = MagicMock()
    resp.json.return_value = {"data": data, "meta": {"last_page": last_page}}
    resp.raise_for_status.return_value = None
    return resp

def _failing_resp(error):
    """Mock a response whose raise_for_status raises the given error."""
    resp = MagicMock()
    resp.raise_for_status.side_effect = error
    return resp

def _json_decode_error_resp():
    """Mock a response whose .json() raises ValueError (malformed JSON)."""
    resp = MagicMock()
    resp.json.side_effect = ValueError("Expecting value")
    resp.raise_for_status.return_value = None
    return resp

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
                assert args[0] == "transmission-daemon", "daemon binary is invoked"
                assert "-f" in args, "daemon runs in foreground"
                assert "--port" in args, "RPC port flag is passed"
                assert "12345" in args, "chosen free port is used"
                assert "--no-auth" in args, "auth is disabled for the local daemon"
                assert "--download-dir" in args, "download dir flag is passed"
                assert str(tmp_path) in args, "download dir points to the session path"
                # Probe used transmission-remote with -l
                probe_args = run_mock.call_args[0][0]
                assert probe_args[0] == "transmission-remote", "probe uses transmission-remote"
                assert probe_args[-1] == "-l", "probe lists torrents with -l"
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
            with pytest.raises(RuntimeError, match="Transmission daemon failed") as exc_info:
                ts.__enter__()
        assert "Transmission daemon failed" in str(exc_info.value), "startup timeout surfaces a clear error"

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
            with pytest.raises(RuntimeError) as exc_info:
                ts.add("/tmp/foo.torrent")
        assert isinstance(exc_info.value, RuntimeError), "add raises RuntimeError when no new torrent id appears"

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
        assert len(entries) == 2, "should parse two torrent rows"
        assert entries[0]["id"] == 1, "first torrent should have id 1"
        assert entries[0]["percent_done"] == 100.0, "first torrent is fully downloaded"
        assert entries[1]["id"] == 2, "second torrent should have id 2"
        assert entries[1]["percent_done"] == 45.0, "second torrent is 45% done"

    def _list_with(self, tmp_path, stdout):
        ts = TransmissionSession(str(tmp_path))
        ts._rpc = "127.0.0.1:9999"
        result = MagicMock(returncode=0, stdout=stdout, stderr="")
        with patch("subprocess.run", return_value=result):
            return ts.list()

    def test_list_parses_real_transmission_4_row(self, tmp_path):
        """Captured verbatim from transmission-remote 4.1.1: 'Have' is the
        single token None and Done carries decimals."""
        stdout = (
            "    ID    Done       Have  ETA              Up      Down  Ratio  Status       Name\n"
            "     1   0.00%       None  Unknown         0.0       0.0   0.00  Idle         f.bin\n"
            "Sum:                 None                  0.0       0.0\n"
        )
        [entry] = self._list_with(tmp_path, stdout)
        assert entry["id"] == 1, "row id is parsed"
        assert entry["percent_done"] == 0.0, "decimal Done is parsed to float"
        assert entry["have"] == "None", "single-token 'None' Have is preserved"
        assert entry["eta"] == "Unknown", "ETA column is parsed"
        assert entry["status"] == "Idle", "status column is parsed"
        assert entry["name"] == "f.bin", "name column is parsed"

    def test_list_parses_two_token_have_and_eta(self, tmp_path):
        """'Have' and 'ETA' are each two tokens here, which used to shift the
        status and name columns."""
        stdout = "  2    45%  500 MB   3 hours        0.0   200.0   0.1  Downloading  another list.7z\n"
        [entry] = self._list_with(tmp_path, stdout)
        assert entry["percent_done"] == 45.0, "percent is parsed"
        assert entry["have"] == "500 MB", "two-token Have is kept together"
        assert entry["eta"] == "3 hours", "two-token ETA is kept together"
        assert entry["down"] == 200.0, "download rate is parsed"
        assert entry["status"] == "Downloading", "status is not shifted by multi-token columns"
        assert entry["name"] == "another list.7z", "name with a space is preserved"

    def test_list_parses_multi_word_status(self, tmp_path):
        stdout = "  3    12.5%  1.20 GB  2 min      10.0   900.0   0.1  Up & Down    big.7z\n"
        [entry] = self._list_with(tmp_path, stdout)
        assert entry["status"] == "Up & Down"
        assert entry["name"] == "big.7z"
        assert entry["eta"] == "2 min"

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

    @staticmethod
    def _entry(tid, pct, name="big.7z", **kw):
        base = {
            "id": tid,
            "percent_done": pct,
            "status": "Downloading",
            "name": name,
            "have": "500 MB",
            "eta": "3 hours",
            "down": 200.0,
        }
        base.update(kw)
        return base

    def _run_wait(self, tmp_path, polls, stream, on_complete=None):
        ts = TransmissionSession(str(tmp_path), poll_interval=0.0)
        ts._rpc = "127.0.0.1:9999"
        with (
            patch.object(ts, "list", side_effect=lambda: polls.pop(0)),
            patch.object(ts, "info_file", return_value="big.7z"),
            patch.object(ts, "remove"),
            patch("time.sleep"),
        ):
            ts.wait_for_all(
                on_complete=on_complete or (lambda *a: None), progress_stream=stream
            )

    def test_wait_for_all_reports_progress(self, tmp_path):
        import io

        stream = io.StringIO()
        polls = [[self._entry(1, 45.0)], [self._entry(1, 100.0)], []]
        self._run_wait(tmp_path, polls, stream)
        out = stream.getvalue()
        assert "big.7z" in out, "torrent name is reported"
        assert "45.0%" in out, "progress percent is reported"
        assert "500 MB" in out, "downloaded size is reported"
        assert "ETA 3 hours" in out, "ETA is reported"
        assert "200.0 kB/s" in out, "download speed is reported"
        assert "0/1 complete" in out, "completion count is reported"

    def test_wait_for_all_progress_counts_completed_torrents(self, tmp_path):
        import io

        stream = io.StringIO()
        polls = [
            [self._entry(1, 100.0, name="a.7z"), self._entry(2, 10.0, name="b.7z")],
            [self._entry(2, 60.0, name="b.7z")],
            [],
        ]
        self._run_wait(tmp_path, polls, stream)
        assert "1/2 complete" in stream.getvalue()

    def test_wait_for_all_non_tty_does_not_repeat_unchanged_progress(self, tmp_path):
        """A log file must not get a line every poll interval for hours."""
        import io

        stream = io.StringIO()
        polls = [
            [self._entry(1, 45.0, eta="3 hours")],
            [self._entry(1, 45.4, eta="2 hours")],
            [self._entry(1, 71.0)],
            [],
        ]
        self._run_wait(tmp_path, polls, stream)
        lines = [ln for ln in stream.getvalue().splitlines() if "big.7z" in ln]
        assert len(lines) == 2
        assert "\r" not in stream.getvalue()

    def test_wait_for_all_tty_redraws_in_place_and_breaks_line_before_completion(
        self, tmp_path
    ):
        import io

        class TTY(io.StringIO):
            def isatty(self):
                return True

        stream = TTY()
        seen_at_complete = []
        polls = [[self._entry(1, 45.0)], [self._entry(1, 100.0)], []]
        self._run_wait(
            tmp_path,
            polls,
            stream,
            on_complete=lambda *a: seen_at_complete.append(stream.getvalue()),
        )
        assert stream.getvalue().startswith("\r")
        # Whatever on_complete prints (7z extraction) must start on a fresh line.
        assert seen_at_complete[0].endswith("\n")

    def test_wait_for_all_keyboard_interrupt_propagates(self, tmp_path):
        ts = TransmissionSession(str(tmp_path), poll_interval=0.0)
        ts._rpc = "127.0.0.1:9999"
        with (
            patch.object(ts, "list", side_effect=KeyboardInterrupt),
            patch("time.sleep"),
        ):
            with pytest.raises(KeyboardInterrupt) as exc_info:
                ts.wait_for_all(on_complete=lambda *a: None)
        assert isinstance(exc_info.value, KeyboardInterrupt), "KeyboardInterrupt propagates out of wait_for_all"

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
            with pytest.raises(KeyboardInterrupt) as exc_info:
                run_torrent_session(["a.torrent"], "/tmp/save")
        assert isinstance(exc_info.value, KeyboardInterrupt), "KeyboardInterrupt propagates out of run_torrent_session"


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


class TestResolveWeakpassTorrentUrl:
    """Test _resolve_weakpass_torrent_url which resolves filenames to torrent URLs."""

    def test_first_candidate_resolves(self, monkeypatch):
        """example-list.txt resolves on the first detail lookup."""
        calls = []

        def mock_get(url, params=None, headers=None, timeout=None):
            calls.append((url, params))
            resp = MagicMock()
            resp.json.return_value = {
                "data": {
                    "torrent_url": "https://weakpass.com/download/1/example-list.txt.torrent"
                }
            }
            resp.raise_for_status = MagicMock()
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("example-list.txt")
        assert result == "https://weakpass.com/download/1/example-list.txt.torrent"
        # Assert the full composed URL
        assert calls[0][0] == "https://weakpass.com/api/v1/wordlists/example-list.txt"
        assert calls[0][1] is None

    def test_multiple_candidates_tries_each(self, monkeypatch):
        """example-list.txt.7z.torrent 404s twice then resolves on example-list.txt."""
        calls = []

        def _not_found():
            err = req_lib.HTTPError()
            err.response = MagicMock(status_code=404)
            return MagicMock(raise_for_status=MagicMock(side_effect=err))

        def _resolved():
            return MagicMock(
                json=MagicMock(return_value={
                    "data": {"torrent_url": "https://weakpass.com/download/1/example-list.txt.torrent"}
                }),
                raise_for_status=MagicMock(),
            )

        def mock_get(url, params=None, headers=None, timeout=None):
            calls.append(url)
            return {True: _not_found(), False: _resolved()}[".7z" in url]

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("example-list.txt.7z.torrent")
        assert result == "https://weakpass.com/download/1/example-list.txt.torrent", "resolves on the bare name after the .7z candidates 404"
        assert len(calls) == 3, "all three candidates are tried"

    def test_path_with_space_and_slash_is_quoted(self, monkeypatch):
        """Names containing space and / are quoted (%20, %2F) in request path."""
        calls = []

        def mock_get(url, params=None, headers=None, timeout=None):
            calls.append(url)
            resp = MagicMock()
            resp.json.return_value = {
                "data": {"torrent_url": "https://weakpass.com/download/1/file.torrent"}
            }
            resp.raise_for_status = MagicMock()
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("My List/file.txt")
        assert result == "https://weakpass.com/download/1/file.torrent"
        # Path should be quoted in the full URL
        assert calls[0] == "https://weakpass.com/api/v1/wordlists/My%20List%2Ffile.txt"

    def test_all_candidates_fail_search_returns_exact_match(self, monkeypatch):
        """Search with exact case-insensitive match among several entries."""

        def mock_get(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            if params and "name" in params:
                # Search results: multiple entries, one exact match case-insensitively
                resp.json.return_value = {
                    "data": [
                        {"name": "Similar List", "torrent_url": "similar.torrent"},
                        {"name": "example-list.txt", "torrent_url": "exact.torrent"},
                        {"name": "Other List", "torrent_url": "other.torrent"},
                    ]
                }
                resp.raise_for_status = MagicMock()
            else:
                # Detail lookup 404
                err = req_lib.HTTPError()
                err.response = MagicMock(status_code=404)
                resp.raise_for_status = MagicMock(side_effect=err)
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("EXAMPLE-LIST.TXT")
        assert result == "exact.torrent"

    def test_all_candidates_fail_search_multiple_no_exact_match(
        self, monkeypatch, capsys
    ):
        """Search returns 2+ entries without exact match -> None with message."""

        def mock_get(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            if params and "name" in params:
                resp.json.return_value = {
                    "data": [
                        {"name": "example-list-a.txt", "torrent_url": "a.torrent"},
                        {"name": "example-list-b.txt", "torrent_url": "b.torrent"},
                    ]
                }
                resp.raise_for_status = MagicMock()
            else:
                err = req_lib.HTTPError()
                err.response = MagicMock(status_code=404)
                resp.raise_for_status = MagicMock(side_effect=err)
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("example-list.txt")
        assert result is None
        captured = capsys.readouterr()
        assert "matches 2 Weakpass wordlists" in captured.out

    def test_search_single_entry_returned(self, monkeypatch):
        """If search returns exactly one entry, use it."""

        def mock_get(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            if params and "name" in params:
                resp.json.return_value = {
                    "data": [
                        {"name": "example-list.txt", "torrent_url": "single.torrent"}
                    ]
                }
                resp.raise_for_status = MagicMock()
            else:
                err = req_lib.HTTPError()
                err.response = MagicMock(status_code=404)
                resp.raise_for_status = MagicMock(side_effect=err)
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("example-list.txt")
        assert result == "single.torrent"

    def test_non_404_error_stops_search(self, monkeypatch, capsys):
        """Non-404 error (500) -> None plus failed line, no search issued."""
        calls = []

        def mock_get(url, params=None, headers=None, timeout=None):
            calls.append(url)
            err = req_lib.HTTPError()
            err.response = MagicMock(status_code=500)
            resp = MagicMock()
            resp.raise_for_status = MagicMock(side_effect=err)
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("example-list.txt")
        assert result is None
        # Should only try once (detail lookup) then stop
        assert len(calls) == 1
        captured = capsys.readouterr()
        assert "lookup for example-list.txt failed" in captured.out

    def test_resolver_returns_none_when_all_lookups_fail(self, monkeypatch):
        """_resolve_weakpass_torrent_url returns None when all lookups and search fail."""

        def mock_get(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            if params and "name" in params:
                resp.json.return_value = {"data": []}  # No search results
                resp.raise_for_status = MagicMock()
            else:
                err = req_lib.HTTPError()
                err.response = MagicMock(status_code=404)
                resp.raise_for_status = MagicMock(side_effect=err)
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("nonexistent.txt")
        assert result is None

    def test_resolver_with_empty_torrent_url(self, monkeypatch, capsys):
        """Entry found but with empty torrent_url prints specific message."""

        def mock_get(url, params=None, headers=None, timeout=None):
            resp = MagicMock()
            if params and "name" in params:
                resp.json.return_value = {
                    "data": [{"name": "example-list.txt", "torrent_url": ""}]
                }
                resp.raise_for_status = MagicMock()
            else:
                err = req_lib.HTTPError()
                err.response = MagicMock(status_code=404)
                resp.raise_for_status = MagicMock(side_effect=err)
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api._resolve_weakpass_torrent_url("example-list.txt")
        assert result is None
        captured = capsys.readouterr()
        assert "is on Weakpass but has no torrent" in captured.out


class TestFetchTorrentMetadataUpdated:
    """Test fetch_torrent_metadata updates for torrent resolution."""

    def test_url_with_encoded_characters_decoded(self, monkeypatch, tmp_path):
        """fetch_torrent_metadata decodes %20 in filenames."""
        monkeypatch.setattr(api, "register_torrent_cleanup", lambda: None)
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/octet-stream"}
        resp.iter_content = MagicMock(return_value=[b"fake torrent data"])

        def mock_get(*args, **kwargs):
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)

        result = api.fetch_torrent_metadata(
            "https://weakpass.com/download/9/Example%20List.txt.gz.torrent"
        )
        # Should write the file with decoded name
        assert "Example List.txt.gz.torrent" in result

    def test_bare_name_with_wordlist_id_quotes_path(self, monkeypatch, tmp_path):
        """Bare name with wordlist_id quotes the path segment."""
        monkeypatch.setattr(api, "register_torrent_cleanup", lambda: None)
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

        seen_url = {}

        def mock_get(url, headers=None, stream=False, timeout=None, **kwargs):
            seen_url["url"] = url
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "application/octet-stream"}
            resp.iter_content = MagicMock(return_value=[b"torrent"])
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        api.fetch_torrent_metadata("My List.txt", wordlist_id="123")
        # Path should be quoted
        assert "%20" in seen_url["url"]
        assert "/download/123/" in seen_url["url"]

    def test_unresolvable_bare_name_not_found_message(
        self, monkeypatch, tmp_path, capsys
    ):
        """Unresolvable bare name prints the new error message, no /files/ URL."""
        monkeypatch.setattr(api, "register_torrent_cleanup", lambda: None)
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

        seen_urls = []

        def _empty():
            return MagicMock(json=MagicMock(return_value={"data": []}), raise_for_status=MagicMock())

        def _not_found():
            err = req_lib.HTTPError()
            err.response = MagicMock(status_code=404)
            return MagicMock(raise_for_status=MagicMock(side_effect=err))

        def mock_get(url, params=None, headers=None, stream=False, timeout=None, **kwargs):
            seen_urls.append(url)
            return {True: _empty(), False: _not_found()}[bool(params and "name" in params)]

        monkeypatch.setattr(api.requests, "get", mock_get)
        result = api.fetch_torrent_metadata("nonexistent.txt")
        assert result is None, "an unresolvable name returns None"
        captured = capsys.readouterr()
        assert "Could not resolve a Weakpass torrent for" in captured.out, "prints the not-found message"
        assert "weakpass.com/files/" not in "\n".join(seen_urls), "no legacy /files/ fallback URL is used"

    def test_torrent_download_gets_timeout(self, monkeypatch, tmp_path):
        """The torrent GET is passed timeout=WEAKPASS_TIMEOUT."""
        monkeypatch.setattr(api, "register_torrent_cleanup", lambda: None)
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

        seen_kwargs = {}

        def mock_get(url, headers=None, stream=False, timeout=None, **kwargs):
            seen_kwargs["timeout"] = timeout
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"Content-Type": "application/octet-stream"}
            resp.iter_content = MagicMock(return_value=[b"torrent"])
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)
        api.fetch_torrent_metadata("http://example.com/file.torrent")
        assert seen_kwargs.get("timeout") == api.WEAKPASS_TIMEOUT

    def test_path_traversal_blocked_in_filename(self, monkeypatch, tmp_path):
        """Encoded path traversal (..%2F..%2Fevil) is stripped, file stays in temp dir."""
        monkeypatch.setattr(api, "register_torrent_cleanup", lambda: None)
        monkeypatch.setattr("tempfile.gettempdir", lambda: str(tmp_path))

        resp = MagicMock()
        resp.status_code = 200
        resp.headers = {"Content-Type": "application/octet-stream"}
        resp.iter_content = MagicMock(return_value=[b"fake torrent data"])

        def mock_get(*args, **kwargs):
            return resp

        monkeypatch.setattr(api.requests, "get", mock_get)

        result = api.fetch_torrent_metadata(
            "https://weakpass.com/download/9/..%2F..%2Fevil.txt"
        )
        # Should use basename, preventing directory traversal
        assert result is not None
        # Verify the file was saved under the torrent dir, not above it
        saved_dir = os.path.dirname(result)
        expected_dir = os.path.join(str(tmp_path), "hate_crack")
        assert saved_dir == expected_dir


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

    def test_calls_limiter_before_request(self):
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._mock_resource_response([]),
            ),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            download_hashmob_wordlist_list()
        mock_wait.assert_called_once()

    def test_429_triggers_backoff_and_retries(self):
        mock_429 = self._mock_resource_response([])
        mock_429.status_code = 429
        mock_429.headers = {}
        mock_ok = self._mock_resource_response([])
        mock_ok.status_code = 200
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_wordlist_list()
        assert result == []
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()

    def test_unauthorized_payload_returns_empty_list_without_raising(self, capsys):
        data = {"message": "Unauthorized."}
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._mock_resource_response(data),
            ),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_wordlist_list()
        assert result == []
        out = capsys.readouterr().out
        assert "Error fetching Hashmob wordlists" in out


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

    def test_calls_limiter_before_request(self):
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._mock_resource_response([]),
            ),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            download_hashmob_rule_list()
        mock_wait.assert_called_once()

    def test_429_triggers_backoff_and_retries(self):
        mock_429 = self._mock_resource_response([])
        mock_429.status_code = 429
        mock_429.headers = {}
        mock_ok = self._mock_resource_response([])
        mock_ok.status_code = 200
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_rule_list()
        assert result == []
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()

    def test_unauthorized_payload_returns_empty_list_without_raising(self, capsys):
        data = {"message": "Unauthorized."}
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._mock_resource_response(data),
            ),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_rule_list()
        assert result == []
        out = capsys.readouterr().out
        assert "Error fetching Hashmob rules" in out


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
        assert result is True, "download reports success"
        assert out.exists(), "output file is created"
        assert out.read_bytes() == b"wordlist data", "downloaded content is written"

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
        assert result is True, "download succeeds via the fallback URL"
        assert mock_get.call_count == 2, "primary then fallback are both tried"
        first_url = mock_get.call_args_list[0].args[0]
        second_url = mock_get.call_args_list[1].args[0]
        assert (
            first_url
                == "https://www.hashmob.net/api/v2/downloads/research/rules/some.rule"
        ), "primary URL tried first"
        assert (
            second_url
                == "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/some.rule"
        ), "official alternate URL tried second"

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

    def test_calls_limiter_before_request(self):
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._mock_resource_response([]),
            ),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            download_hashmob_mask_list()
        mock_wait.assert_called_once()

    def test_429_triggers_backoff_and_retries(self):
        mock_429 = self._mock_resource_response([])
        mock_429.status_code = 429
        mock_429.headers = {}
        mock_ok = self._mock_resource_response([])
        mock_ok.status_code = 200
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_mask_list()
        assert result == []
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()

    def test_unauthorized_payload_returns_empty_list_without_raising(self, capsys):
        data = {"message": "Unauthorized."}
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._mock_resource_response(data),
            ),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = download_hashmob_mask_list()
        assert result == []
        out = capsys.readouterr().out
        assert "Error fetching Hashmob masks" in out


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
        assert result is True, "download reports success"
        assert out.exists(), "output file is created"
        assert out.read_bytes() == b"mask data", "downloaded mask content is written"
        called_url = mock_get.call_args.args[0]
        assert (
            called_url
            == "https://hashmob.net/api/v2/downloads/research/masks/test.hcmask", "mask download URL is correct"
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

    def test_unauthorized_payload_returns_empty_list_without_raising(self, capsys):
        data = {"message": "Unauthorized."}
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_archives()
        assert result == []
        out = capsys.readouterr().out
        assert "Error fetching Hashmob archives" in out

    def test_preserves_extra_entry_fields(self):
        data = {
            "2022": [
                {
                    "name": "a.7z",
                    "url": "https://hashmob.net/api/v2/archive/a.7z",
                    "file_size": 12345,
                }
            ]
        }
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_archives()
        assert result[0]["file_size"] == 12345


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

    def test_untrusted_url_falls_back_to_hashmob_host(self, tmp_path):
        entry = {
            "name": "evil.7z",
            "url": "https://evil.example.com/steal/evil.7z",
        }
        mock_response = self._make_mock_response()
        with (
            patch(
                "hate_crack.api.requests.get", return_value=mock_response
            ) as mock_get,
            patch("hate_crack.api.time.sleep"),
            patch("hate_crack.api.get_hashmob_api_key", return_value="secret-key"),
            patch("hate_crack.api._hashmob_limiter.wait"),
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("builtins.input", return_value="y"),
            self._patch_stdin_tty(),
        ):
            result = download_hashmob_archive(entry)
        assert result is True, "download succeeds"
        # The api-key header must never reach the untrusted host: the request
        # actually made must target the constructed hashmob.net fallback URL.
        called_url = mock_get.call_args.args[0]
        assert called_url == "https://hashmob.net/api/v2/archive/evil.7z", "request targets the trusted hashmob host, not the untrusted url"
        assert mock_get.call_args.kwargs["headers"] == {"api-key": "secret-key"}, "api-key is sent only to the trusted host"
        assert mock_get.call_count == 1, "exactly one request is made"

    def test_trusted_www_host_is_kept(self, tmp_path):
        entry = {
            "name": "a.7z",
            "url": "https://www.hashmob.net/api/v2/archive/a.7z",
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
            download_hashmob_archive(entry)
        called_url = mock_get.call_args.args[0]
        assert called_url == "https://www.hashmob.net/api/v2/archive/a.7z"


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

    def test_unauthorized_payload_returns_empty_list_without_raising(self, capsys):
        data = {"message": "Unauthorized."}
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_combined_left()
        assert result == []
        out = capsys.readouterr().out
        assert "Error fetching Hashmob combined-left listing" in out

    def test_combined_left_files_not_a_list_returns_empty_list(self, capsys):
        data = {"combined_left_files": "not-a-list"}
        with (
            patch(
                "hate_crack.api.requests.get", return_value=self._mock_response(data)
            ),
            patch("hate_crack.api.get_hashmob_api_key", return_value=None),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = list_hashmob_combined_left()
        assert result == []
        out = capsys.readouterr().out
        assert "Error fetching Hashmob combined-left listing" in out


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
            with pytest.raises(ValueError) as exc_info:
                download_hashmob_combined_left(0, variant="bogus")
        assert isinstance(exc_info.value, ValueError), "an invalid variant raises ValueError"

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
        assert result is True, "download eventually succeeds after retry"
        assert mock_get.call_count == 2, "retries once after the 429"
        assert mock_sleep.call_count == 1, "backoff sleeps once between attempts"
        assert out.exists(), "output file is created on success"

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
        assert result is True, "download reports success"
        assert out.exists(), "output file is created"
        assert out.read_bytes() == content, "full content is written"
        assert not (tmp_path / "out.txt.part").exists(), "temporary .part file is cleaned up"
        mock_get.assert_called_once()
        assert mock_get.call_args.args[0] == "https://example.com/file.txt", "correct URL is requested"

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
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            with pytest.raises(KeyboardInterrupt):
                _streamed_download("https://example.com/file.txt", str(out))
        assert not (tmp_path / "out.txt.part").exists(), "partial .part file must be removed on interrupt"

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
        assert result is False, "returns failure after exhausting attempts"
        assert fn.call_count == 3, "function is tried max_attempts times"
        # sleep called between attempts, but NOT after the last attempt
        assert mock_sleep.call_count == 2, "sleeps between attempts but not after the last"
        captured = capsys.readouterr()
        assert "gave up after 3 attempts" in captured.out, "gives a clear give-up message"

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
        with pytest.raises(ValueError, match="not a 429") as exc_info:
            _with_hashmob_backoff(fn)
        assert "not a 429" in str(exc_info.value), "a non-429 error is re-raised unchanged"

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

    def test_negative_retry_after_is_clamped_to_zero(self):
        """A malformed Retry-After: -1 must not reach time.sleep(-1), which
        raises ValueError and would escape the backoff helper as a generic
        error instead of being treated as an invalid Retry-After."""
        fn = MagicMock(side_effect=[_Hashmob429(retry_after=-1.0), True])
        with (
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            result = _with_hashmob_backoff(fn)
        assert result is True
        mock_sleep.assert_called_once_with(0.0)


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

        assert mock_dl.call_count == 1, "only the missing file is downloaded"
        called_filename = mock_dl.call_args.args[0]
        assert called_filename == "new.txt", "the new file is the one downloaded"
        assert mock_get.call_args.kwargs["headers"] == {}, "no auth header on the public listing"
        captured = capsys.readouterr()
        assert "Skipping existing.txt" in captured.out, "existing file is reported as skipped"

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

    def test_calls_limiter_before_listing_request(self, tmp_path):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        api_data = [{"file_name": "new.txt"}]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = api_data
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True
        with (
            patch("hate_crack.api.requests.get", return_value=mock_resp),
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist"),
            patch("hate_crack.api.sys.stdin", mock_stdin),
            patch("builtins.input", return_value="q"),
            patch("hate_crack.api._hashmob_limiter.wait") as mock_wait,
        ):
            list_and_download_official_wordlists()
        mock_wait.assert_called_once()

    def test_429_triggers_backoff_and_retries_on_listing(self, tmp_path, capsys):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        api_data = [{"file_name": "new.txt"}]

        mock_429 = MagicMock()
        mock_429.status_code = 429
        mock_429.headers = {}

        mock_ok = MagicMock()
        mock_ok.status_code = 200
        mock_ok.raise_for_status = MagicMock()
        mock_ok.json.return_value = api_data

        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True
        with (
            patch(
                "hate_crack.api.requests.get", side_effect=[mock_429, mock_ok]
            ) as mock_get,
            patch("hate_crack.api.time.sleep") as mock_sleep,
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist"),
            patch("hate_crack.api.sys.stdin", mock_stdin),
            patch("builtins.input", return_value="q"),
            patch("hate_crack.api._hashmob_limiter.wait"),
        ):
            list_and_download_official_wordlists()
        assert mock_get.call_count == 2
        mock_sleep.assert_called_once()


class TestWeakpassApiListing:
    def test_request_url_and_params(self):
        """Test that requests use correct URL, params, timeout, and User-Agent."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": [], "meta": {"last_page": 1}}
        with patch("hate_crack.api.requests.get", return_value=mock_resp) as mock_get:
            _api_mod._fetch_weakpass_page(1)

        # Verify the call
        call_args = mock_get.call_args
        assert call_args[0][0] == "https://weakpass.com/api/v1/wordlists"
        assert call_args[1]["params"]["page"] == 1
        assert call_args[1]["params"]["per_page"] == 100
        assert call_args[1]["timeout"] == 30

        # Check headers
        headers = call_args[1]["headers"]
        assert headers["User-Agent"].startswith("hate_crack/")
        assert headers["Accept"] == "application/json"
        assert "X-Inertia" not in headers
        assert "api-key" not in headers

    def test_three_pages_fetched_and_returned_in_order(self):
        """Test that all pages are fetched and results are in page order."""

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                1: _json_response([_weakpass_entry(1, "list1", "S")], last_page=3),
                2: _json_response([_weakpass_entry(2, "list2", "A", 200, 20, 2.0, "list2", "url2")], last_page=3),
                3: _json_response([_weakpass_entry(3, "list3", "B", 300, 30, 3.0, "list3", "url3")], last_page=3),
            }
            return pages.get(page, _json_response([], last_page=3))

        with patch("hate_crack.api.requests.get", side_effect=mock_get_impl):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        assert len(result) == 3
        assert result[0]["id"] == 1
        assert result[1]["id"] == 2
        assert result[2]["id"] == 3

    def test_two_entries_same_name_different_id_both_kept(self):
        """Test that two entries with same name but different id are both kept."""
        mock_resp = _json_response([
            _weakpass_entry(1, "example-list.txt", "S", slug="example-list-txt"),
            _weakpass_entry(2, "example-list.txt", "A", 200, 20, 2.0, "example-list-txt-2", "url2"),
        ])
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()
        assert len(result) == 2, "both entries with same name but different id are kept"
        assert result[0]["id"] == 1, "first entry preserved"
        assert result[1]["id"] == 2, "second entry preserved"

    def test_same_id_on_two_pages_kept_once(self):
        """Test that the same id on two pages is kept only once (first occurrence)."""

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                1: _json_response([_weakpass_entry(1, "list1", "S")], last_page=2),
                2: _json_response([_weakpass_entry(1, "list1_dup", "B", 150, 15, 1.5, "list1_dup", "url1_dup")], last_page=2),
            }
            return pages.get(page, _json_response([], last_page=2))

        with patch("hate_crack.api.requests.get", side_effect=mock_get_impl):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        assert len(result) == 1
        assert result[0]["id"] == 1
        assert result[0]["name"] == "list1"  # First occurrence wins

    def test_tier_mapping(self):
        """Test tier to rank mapping: S=7, b(lowercase)=5, None=0."""
        mock_resp = _json_response([
            _weakpass_entry(1, "s-tier", "S"),
            _weakpass_entry(2, "b-tier", "b", 200, 20, 2.0, "b-tier", "url2"),
            _weakpass_entry(3, "no-tier", None, 300, 30, 3.0, "no-tier", "url3"),
        ])
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        assert result[0]["rank"] == 7
        assert result[0]["tier"] == "S"
        assert result[1]["rank"] == 5
        assert result[1]["tier"] == "B"
        assert result[2]["rank"] == 0
        assert result[2]["tier"] == ""

    def test_page1_http500_returns_empty_and_prints_error(self, capsys):
        """Test that page 1 returning HTTP 500 returns [] and prints 'Weakpass listing failed'."""
        mock_resp = MagicMock()
        mock_resp.raise_for_status.side_effect = req_lib.HTTPError("500 Server Error")

        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        captured = capsys.readouterr()
        assert result == []
        assert "Weakpass listing failed" in captured.out

    def test_page2_of3_fails_returns_pages1and3(self, capsys):
        """Test that a failed page 2 of 3 still returns pages 1 and 3, and prints error."""

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                1: _json_response([_weakpass_entry(1, "list1", "S")], last_page=3),
                2: _failing_resp(req_lib.HTTPError("500 Server Error")),
                3: _json_response([_weakpass_entry(3, "list3", "B", 300, 30, 3.0, "list3", "url3")], last_page=3),
            }
            return pages.get(page, _json_response([], last_page=3))

        with patch("hate_crack.api.requests.get", side_effect=mock_get_impl):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        captured = capsys.readouterr()
        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 3
        assert "page 2 failed" in captured.out

    def test_total_pages_caps_at_last_page(self):
        """Test that total_pages=2 with last_page=5 fetches exactly pages 1 and 2."""

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                p: _json_response(
                    [_weakpass_entry(p, f"list{p}", "S", 100 * p, 10 * p, 1.0 * p, f"list{p}", f"url{p}")],
                    last_page=5,
                )
                for p in (1, 2)
            }
            return pages.get(page, _json_response([], last_page=5))

        with patch(
            "hate_crack.api.requests.get", side_effect=mock_get_impl
        ) as mock_get:
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded(total_pages=2)

        # Should only call pages 1 and 2, not 3-5
        pages_called = {
            c.kwargs.get("params", {}).get("page") for c in mock_get.call_args_list
        } - {None}
        assert pages_called == {1, 2}, "only pages 1 and 2 are requested"
        assert len(result) == 2

    def test_page1_malformed_json_response_returns_empty_and_prints_error(self, capsys):
        """Test page 1 with malformed data (last_page=None) returns [] and prints error."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"data": [], "meta": {"last_page": None}}
        mock_resp.raise_for_status.return_value = None

        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        captured = capsys.readouterr()
        assert result == []
        assert "Weakpass listing failed" in captured.out

    def test_page2_json_decode_error_returns_pages1and3(self, capsys):
        """Test page 2 with .json() raising ValueError still returns pages 1 and 3."""

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                1: _json_response([_weakpass_entry(1, "list1", "S")], last_page=3),
                2: _json_decode_error_resp(),
                3: _json_response([_weakpass_entry(3, "list3", "B", 300, 30, 3.0, "list3", "url3")], last_page=3),
            }
            return pages.get(page, _json_response([], last_page=3))

        with patch("hate_crack.api.requests.get", side_effect=mock_get_impl):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        captured = capsys.readouterr()
        assert len(result) == 2
        assert result[0]["id"] == 1
        assert result[1]["id"] == 3
        assert "page 2 failed" in captured.out

    def test_rank_as_int_coerced_correctly(self):
        """F4: Test that rank as an int (1-7) is coerced and tier reverse-looked-up."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {
                    "id": 1,
                    "name": "list1",
                    "rank": 7,  # int instead of string
                    "size": 100,
                    "count": 10,
                    "rate": 1.0,
                    "slug": "list1",
                    "torrent_url": "url1",
                },
            ],
            "meta": {"last_page": 1},
        }
        mock_resp.raise_for_status.return_value = None

        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()

        assert len(result) == 1
        assert result[0]["rank"] == 7
        assert result[0]["tier"] == "S"

    def test_rate_coerced_to_float(self):
        """F4: Test that rate is coerced to float, defaulting to 0.0 on failure."""
        mock_resp = _json_response([
            _weakpass_entry(1, "valid-rate", "A", rate="2.5"),
            _weakpass_entry(2, "invalid-rate", "B", 200, 20, "not-a-number", "invalid-rate", "url2"),
            _weakpass_entry(3, "missing-rate", "C", 300, 30, None, "missing-rate", "url3"),
        ])
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()
        assert len(result) == 3, "all three entries are kept"
        assert result[0]["rate"] == 2.5, "numeric string rate is coerced to float"
        assert result[1]["rate"] == 0.0, "invalid rate defaults to 0.0"
        assert result[2]["rate"] == 0.0, "missing rate defaults to 0.0"

    def test_falsy_ids_not_deduplicated(self):
        """F5: Test that entries with falsy ids are kept, not de-duplicated."""
        mock_resp = _json_response([
            _weakpass_entry(1, "list1", "A"),
            _weakpass_entry(None, "no-id-1", "B", 200, 20, 2.0, "no-id-1", "url2"),
            _weakpass_entry(None, "no-id-2", "C", 300, 30, 3.0, "no-id-2", "url3"),
            _weakpass_entry("", "empty-id", "D", 400, 40, 4.0, "empty-id", "url4"),
        ])
        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod.fetch_all_weakpass_wordlists_multithreaded()
        assert len(result) == 4, "entries with falsy ids are all kept"
        assert result[0]["name"] == "list1", "entry 1 kept"
        assert result[1]["name"] == "no-id-1", "falsy-id entry kept"
        assert result[2]["name"] == "no-id-2", "second falsy-id entry kept"
        assert result[3]["name"] == "empty-id", "empty-string-id entry kept"


class TestWeakpassWordlistMenu:
    """Test the weakpass_wordlist_menu function with rank filtering."""

    def _mock_wordlists(self):
        """Return mock wordlist data with tier and rate."""
        return [
            {
                "id": 1,
                "name": "s-tier-list",
                "tier": "S",
                "rank": 7,
                "rate": 5.0,
                "torrent_url": "url1",
            },
            {
                "id": 2,
                "name": "a-tier-list",
                "tier": "A",
                "rank": 6,
                "rate": 4.0,
                "torrent_url": "url2",
            },
            {
                "id": 3,
                "name": "b-tier-list",
                "tier": "B",
                "rank": 5,
                "rate": 3.0,
                "torrent_url": "url3",
            },
            {
                "id": 4,
                "name": "c-tier-list",
                "tier": "C",
                "rank": 4,
                "rate": 2.0,
                "torrent_url": "url4",
            },
            {
                "id": 5,
                "name": "unranked-list",
                "tier": "",
                "rank": 0,
                "rate": 1.0,
                "torrent_url": "url5",
            },
        ]

    def test_rank_equals_minus_one_filters_to_gt_4(self, capsys, monkeypatch):
        """rank=-1 shows only rank > 4, i.e., tiers S(7), A(6), B(5)."""
        wordlists = self._mock_wordlists()

        monkeypatch.setattr(
            api, "fetch_all_weakpass_wordlists_multithreaded", lambda: wordlists
        )
        monkeypatch.setattr(
            "sys.stdin", MagicMock(isatty=MagicMock(return_value=False))
        )

        api.weakpass_wordlist_menu(rank=-1)

        captured = capsys.readouterr()
        # Should show 3 entries: S, A, B
        assert "s-tier-list" in captured.out
        assert "a-tier-list" in captured.out
        assert "b-tier-list" in captured.out
        # Should not show C or unranked
        assert "c-tier-list" not in captured.out
        assert "unranked-list" not in captured.out
        # Check header mentions tier and crack rate
        assert "tier S-F" in captured.out
        assert "crack rate" in captured.out

    def test_rank_equals_zero_shows_all(self, capsys, monkeypatch):
        """rank=0 shows all wordlists regardless of tier."""
        wordlists = self._mock_wordlists()

        monkeypatch.setattr(
            api, "fetch_all_weakpass_wordlists_multithreaded", lambda: wordlists
        )
        monkeypatch.setattr(
            "sys.stdin", MagicMock(isatty=MagicMock(return_value=False))
        )

        api.weakpass_wordlist_menu(rank=0)

        captured = capsys.readouterr()
        # All 5 should appear
        assert "s-tier-list" in captured.out
        assert "a-tier-list" in captured.out
        assert "b-tier-list" in captured.out
        assert "c-tier-list" in captured.out
        assert "unranked-list" in captured.out

    def test_rank_equals_six_shows_only_tier_a(self, capsys, monkeypatch):
        """rank=6 shows only rank == 6 (tier A)."""
        wordlists = self._mock_wordlists()

        monkeypatch.setattr(
            api, "fetch_all_weakpass_wordlists_multithreaded", lambda: wordlists
        )
        monkeypatch.setattr(
            "sys.stdin", MagicMock(isatty=MagicMock(return_value=False))
        )

        api.weakpass_wordlist_menu(rank=6)

        captured = capsys.readouterr()
        # Only A-tier
        assert "a-tier-list" in captured.out
        # Others should not appear
        assert "s-tier-list" not in captured.out
        assert "b-tier-list" not in captured.out

    def test_output_format_shows_tier_and_rate(self, capsys, monkeypatch):
        """Output format should show tier and crack rate as specified."""
        wordlists = [
            {
                "id": 1,
                "name": "test-list",
                "tier": "S",
                "rank": 7,
                "rate": 5.5,
                "torrent_url": "url1",
            }
        ]

        monkeypatch.setattr(
            api, "fetch_all_weakpass_wordlists_multithreaded", lambda: wordlists
        )
        monkeypatch.setattr(
            "sys.stdin", MagicMock(isatty=MagicMock(return_value=False))
        )

        api.weakpass_wordlist_menu(rank=0)

        captured = capsys.readouterr()
        # Check entry row contains name, tier, and rate
        assert "test-list" in captured.out
        assert " S " in captured.out  # tier with spaces
        assert "5.5%" in captured.out  # rate percentage


class TestDownloadAllWeakpassTorrents:
    """Test the download_all_weakpass_torrents function."""

    def test_creates_cache_when_missing(self, tmp_path, monkeypatch):
        """When cache file is missing, fetches wordlists and writes cache."""
        cache_file = tmp_path / "wordlists.json"
        wordlists = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]

        def mock_fetch():
            return wordlists

        def mock_download(url, wordlist_id=None):
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Cache should have been written
        assert cache_file.exists(), "cache file is created"
        with open(cache_file) as f:
            cached = json.load(f)
        assert len(cached) == 2, "both wordlists are cached"
        assert cached[0]["id"] == 1, "first cached entry id"
        assert cached[1]["id"] == 2, "second cached entry id"

    def test_prints_error_and_returns_when_fetch_empty(self, tmp_path, capsys):
        """When fetch returns [], prints error and doesn't write cache."""
        cache_file = tmp_path / "wordlists.json"

        def mock_fetch():
            return []

        api.download_all_weakpass_torrents(
            mock_fetch,
            lambda url, wordlist_id=None: None,
            cache_path=str(cache_file),
        )

        # Cache should NOT have been written
        assert not cache_file.exists()
        # Error message should have been printed
        captured = capsys.readouterr()
        assert "[!] Could not fetch" in captured.out

    def test_refreshes_cache_when_entry_lacks_id(self, tmp_path, monkeypatch):
        """When an entry in cache lacks id, refreshes the cache."""
        cache_file = tmp_path / "wordlists.json"
        # Write a cache with missing id
        cache_file.write_text(json.dumps([{"name": "list1", "torrent_url": "url1"}]))

        new_wordlists = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]

        def mock_fetch():
            return new_wordlists

        def mock_download(url, wordlist_id=None):
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Cache should have been updated
        with open(cache_file) as f:
            cached = json.load(f)
        assert len(cached) == 2
        assert all("id" in wl for wl in cached)

    def test_download_called_with_wordlist_id(self, tmp_path, monkeypatch):
        """download_torrent is called with wordlist_id for each entry."""
        cache_file = tmp_path / "wordlists.json"
        wordlists = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]

        def mock_fetch():
            return wordlists

        download_calls = []

        def mock_download(url, wordlist_id=None):
            download_calls.append({"url": url, "wordlist_id": wordlist_id})
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Each wordlist should be downloaded with its id
        assert len(download_calls) == 2
        assert download_calls[0]["wordlist_id"] == 1
        assert download_calls[1]["wordlist_id"] == 2

    def test_valid_complete_cache_used_as_is(self, tmp_path, monkeypatch):
        """A valid, complete cache (every entry has id) is used as-is."""
        cache_file = tmp_path / "wordlists.json"
        original_wordlists = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]
        cache_file.write_text(json.dumps(original_wordlists))
        original_mtime = cache_file.stat().st_mtime

        fetch_called = []

        def mock_fetch():
            fetch_called.append(True)
            return []  # Should never be called

        download_calls = []

        def mock_download(url, wordlist_id=None):
            download_calls.append({"url": url, "wordlist_id": wordlist_id})
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # fetch_all_wordlists should NOT have been called
        assert len(fetch_called) == 0
        # Cache file should not have been rewritten
        assert cache_file.stat().st_mtime == original_mtime
        # download_torrent should have been called once per entry
        assert len(download_calls) == 2
        assert download_calls[0]["wordlist_id"] == 1
        assert download_calls[1]["wordlist_id"] == 2

    def test_partial_fetch_not_cached_and_warning_printed(
        self, tmp_path, capsys, monkeypatch
    ):
        """F1: When fetch returns (entries, failed_pages) with failures, cache is NOT written."""
        cache_file = tmp_path / "wordlists.json"
        entries = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]
        failed_pages = [2, 3]

        def mock_fetch():
            # Return tuple with failed pages
            return (entries, failed_pages)

        def mock_download(url, wordlist_id=None):
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Cache should NOT have been written
        assert not cache_file.exists()
        # Warning should have been printed
        captured = capsys.readouterr()
        assert "not caching it, so the next run refetches" in captured.out
        assert "2 page(s) failed" in captured.out

    def test_complete_fetch_tuple_is_cached(self, tmp_path, monkeypatch):
        """F1: When fetch returns (entries, []) with no failures, cache IS written."""
        cache_file = tmp_path / "wordlists.json"
        entries = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]
        failed_pages = []

        def mock_fetch():
            # Return tuple with empty failed_pages
            return (entries, failed_pages)

        def mock_download(url, wordlist_id=None):
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Cache should have been written
        assert cache_file.exists()
        with open(cache_file) as f:
            cached = json.load(f)
        assert len(cached) == 2

    def test_partial_fetch_still_downloads_fetched_entries(self, tmp_path, monkeypatch):
        """F1: Even with failures, downloads still happen for the entries that were fetched."""
        cache_file = tmp_path / "wordlists.json"
        entries = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]
        failed_pages = [3]

        def mock_fetch():
            return (entries, failed_pages)

        download_calls = []

        def mock_download(url, wordlist_id=None):
            download_calls.append({"url": url, "wordlist_id": wordlist_id})
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Downloads should still happen for the 2 fetched entries
        assert len(download_calls) == 2
        assert download_calls[0]["wordlist_id"] == 1
        assert download_calls[1]["wordlist_id"] == 2

    def test_plain_list_callback_still_works(self, tmp_path, monkeypatch):
        """F1: Callback returning a plain list (old shape) still works."""
        cache_file = tmp_path / "wordlists.json"
        wordlists = [
            {"id": 1, "name": "list1", "torrent_url": "url1"},
            {"id": 2, "name": "list2", "torrent_url": "url2"},
        ]

        def mock_fetch():
            # Return plain list, not tuple
            return wordlists

        def mock_download(url, wordlist_id=None):
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            mock_fetch, mock_download, cache_path=str(cache_file)
        )

        # Cache should have been written (no failures)
        assert cache_file.exists()
        with open(cache_file) as f:
            cached = json.load(f)
        assert len(cached) == 2

    def test_fetch_returns_2tuple_not_3tuple(self):
        """Pin that _fetch_all_weakpass_wordlists returns exactly (entries, failed_pages), not (entries, failed_pages, last_page)."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "data": [
                {
                    "id": 1,
                    "name": "list1",
                    "rank": "A",
                    "size": 100,
                    "count": 10,
                    "rate": 1.0,
                    "slug": "list1",
                    "torrent_url": "url1",
                }
            ],
            "meta": {"last_page": 1},
        }
        mock_resp.raise_for_status.return_value = None

        with patch("hate_crack.api.requests.get", return_value=mock_resp):
            result = _api_mod._fetch_all_weakpass_wordlists()

        # Should be a 2-tuple, not 3-tuple
        assert isinstance(result, tuple)
        assert len(result) == 2
        entries, failed_pages = result
        assert len(entries) == 1
        assert failed_pages == []

    def test_real_fetch_integration_all_pages_ok(self, tmp_path, monkeypatch, capsys):
        """Real integration: _fetch_all_weakpass_wordlists as callback, all pages OK."""
        cache_file = tmp_path / "wordlists.json"

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                1: _json_response([_weakpass_entry(1, "list1", "A")], last_page=2),
                2: _json_response([_weakpass_entry(2, "list2", "B", 200, 20, 2.0, "list2", "url2")], last_page=2),
            }
            return pages.get(page, _json_response([], last_page=2))

        download_calls = []

        def mock_download(url, wordlist_id=None):
            download_calls.append({"url": url, "wordlist_id": wordlist_id})
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api.requests, "get", mock_get_impl)
        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            fetch_all_wordlists=_api_mod._fetch_all_weakpass_wordlists,
            download_torrent=mock_download,
            cache_path=str(cache_file),
        )

        # Cache should have been written
        assert cache_file.exists()
        with open(cache_file) as f:
            cached = json.load(f)
        assert len(cached) == 2

        # Downloads should have been called
        assert len(download_calls) == 2

        # Summary should print without failure notice
        captured = capsys.readouterr()
        assert "[i] Weakpass:" in captured.out
        assert "failed" not in captured.out

    def test_real_fetch_integration_page2_fails(self, tmp_path, monkeypatch, capsys):
        """Real integration: _fetch_all_weakpass_wordlists as callback, page 2 fails."""
        cache_file = tmp_path / "wordlists.json"

        def mock_get_impl(url, **kwargs):
            page = kwargs.get("params", {}).get("page", 1)
            pages = {
                1: _json_response([_weakpass_entry(1, "list1", "A")], last_page=3),
                2: _failing_resp(req_lib.HTTPError("500")),
                3: _json_response([_weakpass_entry(3, "list3", "C", 300, 30, 3.0, "list3", "url3")], last_page=3),
            }
            return pages.get(page, _json_response([], last_page=3))

        download_calls = []

        def mock_download(url, wordlist_id=None):
            download_calls.append({"url": url, "wordlist_id": wordlist_id})
            return f"torrent_{wordlist_id}"

        monkeypatch.setattr(api.requests, "get", mock_get_impl)
        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            fetch_all_wordlists=_api_mod._fetch_all_weakpass_wordlists,
            download_torrent=mock_download,
            cache_path=str(cache_file),
        )

        # Cache should NOT have been written (page 2 failed)
        assert not cache_file.exists()

        # Downloads should still happen for pages 1 and 3
        assert len(download_calls) == 2
        assert download_calls[0]["wordlist_id"] == 1
        assert download_calls[1]["wordlist_id"] == 3

        # Incomplete warning should print
        captured = capsys.readouterr()
        assert "not caching it, so the next run refetches" in captured.out

    def test_real_fetch_integration_page1_fails(self, tmp_path, monkeypatch, capsys):
        """Real integration: _fetch_all_weakpass_wordlists as callback, page 1 fails."""
        cache_file = tmp_path / "wordlists.json"

        def mock_get_impl(url, **kwargs):
            mock_resp = MagicMock()
            mock_resp.raise_for_status.side_effect = req_lib.HTTPError("500")
            return mock_resp

        monkeypatch.setattr(api.requests, "get", mock_get_impl)
        monkeypatch.setattr(api, "run_torrent_session", MagicMock())

        api.download_all_weakpass_torrents(
            fetch_all_wordlists=_api_mod._fetch_all_weakpass_wordlists,
            download_torrent=lambda url, wordlist_id=None: None,
            cache_path=str(cache_file),
        )

        # Cache should NOT have been written
        assert not cache_file.exists()

        # Error message should print
        captured = capsys.readouterr()
        assert "[!] Could not fetch the Weakpass wordlist list" in captured.out


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


class TestParseHashmobFoundName:
    def test_plain_found_has_empty_tier(self):
        assert _parse_hashmob_found_name("hashmob.net_2026-09-13.found") == (
            "2026-09-13",
            "",
        )

    def test_tier_is_parsed(self):
        assert _parse_hashmob_found_name("hashmob.net_2026-09-13.tiny.found") == (
            "2026-09-13",
            "tiny",
        )

    def test_archive_suffix_is_stripped(self):
        assert _parse_hashmob_found_name(
            "hashmob.net_2026-09-13.official.found.7z"
        ) == ("2026-09-13", "official")

    def test_large_and_larger_stay_distinct(self):
        assert _parse_hashmob_found_name("hashmob.net_2026-09-13.large.found")[1] == (
            "large"
        )
        assert _parse_hashmob_found_name("hashmob.net_2026-09-13.larger.found")[1] == (
            "larger"
        )

    def test_year_only_current_archive_is_not_dated(self):
        assert _parse_hashmob_found_name("hashmob.net_2026.found") is None

    def test_yearly_all_archive_is_not_matched(self):
        assert _parse_hashmob_found_name("hashmob.net_2021.all.7z") is None

    def test_unrelated_name_is_none(self):
        assert _parse_hashmob_found_name("rockyou.txt") is None


class TestReplaceOlderHashmobFound:
    """Replacement is automatic, gated on the new file being complete and larger.

    The gate is the whole safety story now that nothing is confirmed: an
    older corpus is only ever removed once its replacement is on disk and
    strictly bigger, so a truncated download or a mis-parsed name leaves
    every existing file alone.
    """

    @staticmethod
    def _write(directory, name, size=10):
        path = directory / name
        path.write_bytes(b"x" * size)
        return path

    def test_removes_older_same_tier_without_prompting(self, tmp_path, capsys):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        newer = self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        with patch("builtins.input") as mock_input:
            removed = _replace_older_hashmob_found(
                "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
            )
        assert removed == 1
        assert not older.exists()
        assert newer.exists()
        assert "Removed" in capsys.readouterr().out
        mock_input.assert_not_called()

    def test_smaller_new_file_leaves_the_old_one(self, tmp_path, capsys):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=50)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 0
        assert older.exists()
        assert "not larger" in capsys.readouterr().out

    def test_equal_size_new_file_leaves_the_old_one(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=20)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 0
        assert older.exists()

    def test_missing_new_file_is_a_noop(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found")
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 0
        assert older.exists()

    def test_empty_new_file_is_a_noop(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=0)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 0
        assert older.exists()

    def test_archive_name_resolves_to_the_extracted_file(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found.7z", str(tmp_path)
        )
        assert removed == 1
        assert not older.exists()

    def test_unextracted_archive_is_measured_when_that_is_all_there_is(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found.7z", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found.7z", str(tmp_path)
        )
        assert removed == 1
        assert not older.exists()

    def test_other_tiers_are_untouched(self, tmp_path):
        tiny = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        huge = self._write(tmp_path, "hashmob.net_2026-04-26.huge.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 1
        assert not tiny.exists()
        assert huge.exists()

    def test_newer_same_tier_is_untouched(self, tmp_path):
        newer = self._write(tmp_path, "hashmob.net_2026-12-01.tiny.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 0
        assert newer.exists()

    def test_plain_found_tier_is_isolated_from_tiered_files(self, tmp_path):
        plain = self._write(tmp_path, "hashmob.net_2026-04-26.found", size=10)
        tiny = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.found", str(tmp_path)
        )
        assert removed == 1
        assert not plain.exists()
        assert tiny.exists()

    def test_stale_archive_and_extracted_copy_are_both_removed(self, tmp_path):
        old_7z = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found.7z", size=5)
        old_extracted = self._write(
            tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10
        )
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 2
        assert not old_7z.exists()
        assert not old_extracted.exists()

    def test_a_single_oversized_old_file_does_not_block_the_others(self, tmp_path):
        small = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        oversized = self._write(tmp_path, "hashmob.net_2026-05-26.tiny.found", size=100)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
        )
        assert removed == 1
        assert not small.exists()
        assert oversized.exists()

    def test_non_interactive_context_still_removes(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found", size=10)
        self._write(tmp_path, "hashmob.net_2026-09-13.tiny.found", size=20)
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = False
        with patch("hate_crack.api.sys.stdin", mock_stdin):
            removed = _replace_older_hashmob_found(
                "hashmob.net_2026-09-13.tiny.found", str(tmp_path)
            )
        assert removed == 1
        assert not older.exists()

    def test_undated_new_name_is_a_noop(self, tmp_path):
        older = self._write(tmp_path, "hashmob.net_2026-04-26.tiny.found")
        removed = _replace_older_hashmob_found("rockyou.txt", str(tmp_path))
        assert removed == 0
        assert older.exists()

    def test_missing_directory_is_a_noop(self, tmp_path):
        removed = _replace_older_hashmob_found(
            "hashmob.net_2026-09-13.tiny.found", str(tmp_path / "does-not-exist")
        )
        assert removed == 0


class TestOfficialWordlistAdditiveReplacement:
    @staticmethod
    def _listing_response(api_data):
        mock_resp = MagicMock()
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = api_data
        return mock_resp

    @staticmethod
    def _tty_stdin():
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True
        return mock_stdin

    def test_cleanup_runs_after_a_successful_download(self, tmp_path):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        api_data = [{"file_name": "hashmob.net_2026-09-13.tiny.found.7z"}]
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._listing_response(api_data),
            ),
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch(
                "hate_crack.api.download_official_wordlist", return_value=True
            ) as mock_dl,
            patch("hate_crack.api._replace_older_hashmob_found") as mock_replace,
            patch("hate_crack.api.sys.stdin", self._tty_stdin()),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_official_wordlists()
        mock_dl.assert_called_once_with("hashmob.net_2026-09-13.tiny.found.7z")
        mock_replace.assert_called_once_with(
            "hashmob.net_2026-09-13.tiny.found.7z", str(wordlists_dir)
        )

    def test_cleanup_runs_when_the_new_version_is_already_present(self, tmp_path):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        (wordlists_dir / "hashmob.net_2026-09-13.tiny.found").write_bytes(b"present")
        api_data = [{"file_name": "hashmob.net_2026-09-13.tiny.found.7z"}]
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._listing_response(api_data),
            ),
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist") as mock_dl,
            patch("hate_crack.api._replace_older_hashmob_found") as mock_replace,
            patch("hate_crack.api.sys.stdin", self._tty_stdin()),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_official_wordlists()
        mock_dl.assert_not_called()
        mock_replace.assert_called_once_with(
            "hashmob.net_2026-09-13.tiny.found.7z", str(wordlists_dir)
        )

    def test_no_cleanup_when_the_download_fails(self, tmp_path):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        api_data = [{"file_name": "hashmob.net_2026-09-13.tiny.found.7z"}]
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._listing_response(api_data),
            ),
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist", return_value=False),
            patch("hate_crack.api._replace_older_hashmob_found") as mock_replace,
            patch("hate_crack.api.sys.stdin", self._tty_stdin()),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_official_wordlists()
        mock_replace.assert_not_called()

    def test_cleanup_runs_in_the_numeric_selection_branch(self, tmp_path):
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir()
        api_data = [
            {"file_name": "rockyou.7z"},
            {"file_name": "hashmob.net_2026-09-13.tiny.found.7z"},
        ]
        with (
            patch(
                "hate_crack.api.requests.get",
                return_value=self._listing_response(api_data),
            ),
            patch(
                "hate_crack.api.get_hcat_wordlists_dir", return_value=str(wordlists_dir)
            ),
            patch("hate_crack.api.download_official_wordlist", return_value=True),
            patch("hate_crack.api._replace_older_hashmob_found") as mock_replace,
            patch("hate_crack.api.sys.stdin", self._tty_stdin()),
            patch("builtins.input", return_value="2"),
        ):
            list_and_download_official_wordlists()
        mock_replace.assert_called_once_with(
            "hashmob.net_2026-09-13.tiny.found.7z", str(wordlists_dir)
        )
