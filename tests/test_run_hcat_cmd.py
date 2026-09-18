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
                ["hashcat", "-m", "1000"],
                attack_name="Brute Force",
                hash_file=hash_file,
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
        mock_notify.notify_job_done.assert_called_once_with("LM Phase", 9, hash_file)

    def test_debug_mode_5_rejection_falls_back_to_4_and_retries(
        self, main_module, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(main_module, "_debug_mode_level", 5)
        hash_file = str(tmp_path / "hashes.txt")

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 255
        ok_proc = _make_mock_proc()
        ok_proc.returncode = 0
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append((list(cmd), kwargs))
            if len(popen_calls) == 1:
                kwargs["stderr"].write(b"Invalid --debug-mode value specified.\n")
                return fail_proc
            return ok_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                [
                    "hashcat",
                    "-r",
                    "best64.rule",
                    "--debug-mode",
                    "5",
                    "--debug-file",
                    "x.log",
                ],
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        assert len(popen_calls) == 2
        first_cmd, second_cmd = popen_calls[0][0], popen_calls[1][0]
        assert first_cmd[first_cmd.index("--debug-mode") + 1] == "5"
        assert second_cmd[second_cmd.index("--debug-mode") + 1] == "4"
        assert main_module._debug_mode_level == 4

    def test_debug_mode_fallback_level_is_reused_without_retrying(
        self, main_module, tmp_path, monkeypatch
    ):
        # Once a prior invocation fell back, later ones request mode 4
        # directly, so a rejection can only be re-triggered by mode 5.
        monkeypatch.setattr(main_module, "_debug_mode_level", 4)
        hash_file = str(tmp_path / "hashes.txt")

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 255
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append(list(cmd))
            kwargs["stderr"].write(b"Invalid --debug-mode value specified.\n")
            return fail_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                [
                    "hashcat",
                    "-r",
                    "best64.rule",
                    "--debug-mode",
                    "4",
                    "--debug-file",
                    "x.log",
                ],
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        # Already at mode 4: no retry loop, and the level is untouched.
        assert len(popen_calls) == 1
        assert main_module._debug_mode_level == 4

    def test_unrelated_stderr_is_surfaced_not_treated_as_fallback(
        self, main_module, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(main_module, "_debug_mode_level", 5)
        hash_file = str(tmp_path / "hashes.txt")

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 1
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append(list(cmd))
            kwargs["stderr"].write(b"Some unrelated hashcat error.\n")
            return fail_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                [
                    "hashcat",
                    "-r",
                    "best64.rule",
                    "--debug-mode",
                    "5",
                    "--debug-file",
                    "x.log",
                ],
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        assert len(popen_calls) == 1
        assert main_module._debug_mode_level == 5
        assert "Some unrelated hashcat error." in capsys.readouterr().err

    _BRAIN_CMD = [
        "hashcat",
        "-m",
        "3200",
        "-z",
        "--brain-host",
        "127.0.0.1",
        "--brain-port",
        "6863",
        "--brain-password",
        "pw",
        "--brain-client-features",
        "3",
        "--brain-session",
        "0xdeadbeef",
    ]

    def test_brain_rejection_disables_brain_and_retries_without_it(
        self, main_module, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(main_module, "_brain_enabled", True)
        hash_file = str(tmp_path / "hashes.txt")

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 255
        ok_proc = _make_mock_proc()
        ok_proc.returncode = 0
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append((list(cmd), kwargs))
            if len(popen_calls) == 1:
                kwargs["stderr"].write(
                    b"Brain server 127.0.0.1:6863 is not reachable: "
                    b"Connection refused\n"
                )
                return fail_proc
            return ok_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                list(self._BRAIN_CMD),
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        assert len(popen_calls) == 2
        first_cmd, second_cmd = popen_calls[0][0], popen_calls[1][0]
        assert "-z" in first_cmd
        assert "-z" not in second_cmd
        assert not any(str(a).startswith("--brain-") for a in second_cmd)
        assert main_module._brain_enabled is False

    def test_brain_rejection_retries_at_most_once(
        self, main_module, tmp_path, monkeypatch
    ):
        # Even a pathological build that somehow keeps emitting the brain
        # failure message must not be retried a second time. The fallback
        # command carries no brain flags, so under normal conditions
        # nothing would trigger the brain branch again regardless of the
        # ``_brain_retry`` guard -- which would make that guard untested.
        # To actually exercise it, this command also carries --debug-mode,
        # which _strip_brain_flags never touches, so stderr is captured on
        # every invocation (retried or not) and the fake can keep emitting
        # the brain message. That way ``_brain_retry`` -- not "the retry
        # never got a stderr pipe" -- is what stops a third invocation.
        monkeypatch.setattr(main_module, "_brain_enabled", True)
        hash_file = str(tmp_path / "hashes.txt")

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 255
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append(list(cmd))
            # Bounded defensively: if the guard under test is broken, this
            # would otherwise recurse forever (the debug-mode flags are
            # never stripped, so every retry re-triggers the same "failure").
            if len(popen_calls) > 4:
                raise RuntimeError(
                    "popen called too many times; the _brain_retry guard "
                    "did not stop the recursion"
                )
            kwargs["stderr"].write(
                b"Brain server 127.0.0.1:6863 rejected the password\n"
            )
            return fail_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                list(self._BRAIN_CMD) + ["--debug-mode", "4", "--debug-file", "x.log"],
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        # Both calls captured stderr and both saw the brain message; only
        # the _brain_retry guard stops a third.
        assert len(popen_calls) == 2
        assert main_module._brain_enabled is False

    def test_brain_failure_is_not_disabled_on_a_plain_interrupt(
        self, main_module, tmp_path, monkeypatch
    ):
        # The stderr block must actually contain the brain message for this
        # test to exercise the "not interrupted" guard -- otherwise the
        # content check (_is_brain_failure on an empty buffer) is what ends
        # it, and the guard under test is never reached. So the fake writes
        # the brain message to the captured stderr pipe before the
        # KeyboardInterrupt is raised.
        monkeypatch.setattr(main_module, "_brain_enabled", True)
        hash_file = str(tmp_path / "hashes.txt")
        proc = _make_mock_proc()
        proc.returncode = 255

        def fake_popen(cmd, **kwargs):
            kwargs["stderr"].write(
                b"Brain server 127.0.0.1:6863 is not reachable: Connection refused\n"
            )

            def raise_interrupt():
                raise KeyboardInterrupt()

            proc.wait.side_effect = raise_interrupt
            return proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                list(self._BRAIN_CMD),
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        assert main_module._brain_enabled is True

    def test_unrelated_255_is_not_treated_as_a_brain_failure(
        self, main_module, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(main_module, "_brain_enabled", True)
        hash_file = str(tmp_path / "hashes.txt")

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 255
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append(list(cmd))
            kwargs["stderr"].write(b"Some unrelated fatal hashcat error.\n")
            return fail_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                list(self._BRAIN_CMD),
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        assert len(popen_calls) == 1
        assert main_module._brain_enabled is True
        assert "Some unrelated fatal hashcat error." in capsys.readouterr().err

    def test_brain_rejection_recovers_with_the_long_form_client_flag(
        self, main_module, tmp_path, monkeypatch
    ):
        # _maybe_add_brain's own guard treats any "--brain-*" token as
        # brain-ish (so an operator's own long-form flags in hcatTuning are
        # respected), but the stderr-capture decision used to be keyed on
        # "-z" alone. An operator who wrote hashcat's long form
        # "--brain-client" instead of "-z" got no stderr capture and thus no
        # recovery at all. This pins that both halves now agree.
        monkeypatch.setattr(main_module, "_brain_enabled", True)
        hash_file = str(tmp_path / "hashes.txt")

        long_form_cmd = [
            "hashcat",
            "-m",
            "3200",
            "--brain-client",
            "--brain-host",
            "127.0.0.1",
            "--brain-port",
            "6863",
            "--brain-password",
            "pw",
            "--brain-client-features",
            "3",
            "--brain-session",
            "0xdeadbeef",
        ]

        fail_proc = _make_mock_proc()
        fail_proc.returncode = 255
        ok_proc = _make_mock_proc()
        ok_proc.returncode = 0
        popen_calls = []

        def fake_popen(cmd, **kwargs):
            popen_calls.append((list(cmd), kwargs))
            if len(popen_calls) == 1:
                kwargs["stderr"].write(
                    b"Brain server 127.0.0.1:6863 is not reachable: "
                    b"Connection refused\n"
                )
                return fail_proc
            return ok_proc

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch("hate_crack.main._notify") as mock_notify,
        ):
            mock_notify.is_suppressed.return_value = False
            mock_notify.get_settings.return_value = MagicMock(enabled=False)
            mock_notify.start_tailer.return_value = None
            main_module._run_hcat_cmd(
                list(long_form_cmd),
                attack_name="Dictionary",
                hash_file=hash_file,
            )

        assert len(popen_calls) == 2
        first_cmd, second_cmd = popen_calls[0][0], popen_calls[1][0]
        assert "--brain-client" in first_cmd
        assert not any(str(a).startswith("--brain-") for a in second_cmd)
        assert main_module._brain_enabled is False

    def test_strip_brain_flags_handles_the_equals_form(self, main_module):
        # hcatTuning is fed through shlex.split, so an operator controls the
        # token shape. "--brain-host=127.0.0.1" carries its value in the
        # same token -- there is no separate value token to skip -- so the
        # naive "skip the next token for every --brain-* flag" rule silently
        # drops the unrelated argument that follows it.
        cmd = ["hashcat", "-m", "3200", "--brain-host=127.0.0.1", "-O"]
        stripped = main_module._strip_brain_flags(cmd)
        assert stripped == ["hashcat", "-m", "3200", "-O"]

    def test_strip_brain_flags_handles_a_valueless_flag(self, main_module):
        # "--brain-client" (hashcat's long form of "-z") takes no value at
        # all, so the next token belongs to the rest of the command, not to
        # this flag.
        cmd = ["hashcat", "-m", "3200", "--brain-client", "-O"]
        stripped = main_module._strip_brain_flags(cmd)
        assert stripped == ["hashcat", "-m", "3200", "-O"]

    def test_is_brain_failure_matches_an_unenumerated_message_shape(self, main_module):
        # The three markers this used to require were only the shapes
        # verified by hand. Any other brain-client failure -- e.g. a
        # non-hashcat process squatting the port and failing the handshake
        # with a message we have never seen -- must still be recognized,
        # since a false negative here means every slow-mode attack for the
        # rest of the session fails at zero candidates with no recovery.
        assert main_module._is_brain_failure(
            b"Brain server 127.0.0.1:6863 handshake failed unexpectedly\n"
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
