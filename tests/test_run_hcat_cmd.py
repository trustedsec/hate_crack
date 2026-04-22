"""Tests for the ``_run_hcat_cmd`` subprocess/notify wrapper in main.py."""
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _make_mock_proc(wait_side_effect=None):
    proc = MagicMock()
    if wait_side_effect is not None:
        proc.wait.side_effect = wait_side_effect
    else:
        proc.wait.return_value = None
    proc.pid = 12345
    return proc


class TestRunHcatCmd:
    def test_normal_flow_waits_and_notifies(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc) as mock_popen,
            patch.object(main_module, "lineCount", return_value=42),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=True)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                ["hashcat", "-m", "1000"], attack_name="Brute Force", hash_file=hash_file
            )

        mock_popen.assert_called_once()
        proc.wait.assert_called_once()
        proc.kill.assert_not_called()
        mock_notify.notify_job_done.assert_called_once_with(
            "Brute Force", 42, hash_file
        )

    def test_keyboard_interrupt_kills_process(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                ["hashcat"], attack_name="Brute Force", hash_file=hash_file
            )

        proc.kill.assert_called_once()

    def test_no_notify_when_attack_name_empty(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            main_module._run_hcat_cmd(["hashcat"], attack_name="", hash_file=hash_file)

        mock_notify.notify_job_done.assert_not_called()
        mock_notify.start_tailer.assert_not_called()

    def test_suppressed_skips_notifications(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = True
            mock_notify.get_settings.return_value = MagicMock(enabled=True)
            main_module._run_hcat_cmd(
                ["hashcat"], attack_name="Brute Force", hash_file=hash_file
            )

        mock_notify.start_tailer.assert_not_called()
        mock_notify.notify_job_done.assert_not_called()

    def test_stdin_is_forwarded_to_popen(self, main_module, tmp_path):
        stdin_stub = object()
        proc = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc) as mock_popen,
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(["hashcat"], stdin=stdin_stub)

        _, kwargs = mock_popen.call_args
        assert kwargs.get("stdin") is stdin_stub

    def test_companion_procs_killed_on_interrupt(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())
        companion = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                ["hashcat"],
                attack_name="Combinator3",
                hash_file=hash_file,
                companion_procs=[companion],
            )

        proc.kill.assert_called_once()
        companion.kill.assert_called_once()

    def test_companion_procs_waited_on_normal_exit(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc()
        companion = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                ["hashcat"],
                attack_name="Combinator3",
                hash_file=hash_file,
                companion_procs=[companion],
            )

        companion.wait.assert_called_once()
        companion.kill.assert_not_called()

    def test_reraise_interrupt_propagates(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            with pytest.raises(KeyboardInterrupt):
                main_module._run_hcat_cmd(
                    ["hashcat"],
                    attack_name="YOLO",
                    hash_file=hash_file,
                    reraise_interrupt=True,
                )

    def test_out_path_override(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        alt_out = str(tmp_path / "hashes.lm.cracked")
        proc = _make_mock_proc()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch.object(main_module, "lineCount", return_value=9) as mock_lc,
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=True)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                ["hashcat"],
                attack_name="LM Phase",
                hash_file=hash_file,
                out_path=alt_out,
            )

        mock_lc.assert_called_with(alt_out)
        mock_notify.notify_job_done.assert_called_once_with(
            "LM Phase", 9, hash_file
        )

    def test_tailer_is_stopped_in_finally(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc(wait_side_effect=KeyboardInterrupt())
        tailer = MagicMock()

        with (
            patch("hate_crack.main.subprocess.Popen", return_value=proc),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=True)
            mock_notify.start_tailer.return_value = tailer
            main_module._run_hcat_cmd(
                ["hashcat"], attack_name="Brute Force", hash_file=hash_file
            )

        mock_notify.stop_tailer.assert_called_once_with(tailer)
