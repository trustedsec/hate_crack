"""Integration-style tests for the notify public API."""
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from hate_crack import notify


@pytest.fixture(autouse=True)
def _reset_notify_state():
    notify.clear_state_for_tests()
    yield
    notify.clear_state_for_tests()


def _init_with(tmp_path: Path, **kwargs) -> Path:
    """Create a config file and initialize notify against it."""
    cfg = {
        "notify_enabled": True,
        "notify_pushover_token": "tok",
        "notify_pushover_user": "usr",
    }
    cfg.update(kwargs)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(cfg))
    notify.init(str(config_path), cfg)
    return config_path


class TestNotifyJobDone:
    def test_no_op_when_disabled(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=False)
        with patch("hate_crack.notify._send_pushover") as send:
            notify.notify_job_done("Brute Force", 3)
        send.assert_not_called()

    def test_fires_when_enabled_and_in_allowlist(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        with patch("hate_crack.notify._send_pushover") as send:
            notify.notify_job_done("Brute Force", 7, hash_file="/tmp/h")
        assert send.called
        args = send.call_args.args
        # (token, user, title, message)
        assert args[0] == "tok"
        assert args[1] == "usr"
        assert "Brute Force" in args[2]
        assert "7" in args[3]

    def test_no_op_when_enabled_but_attack_not_allowed(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=True)
        # No allowlist, no consent -> should not fire.
        with patch("hate_crack.notify._send_pushover") as send:
            notify.notify_job_done("Brute Force", 1)
        send.assert_not_called()

    def test_fires_after_per_run_consent(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=True)
        notify.set_input_func(lambda _prompt: "y")
        assert notify.prompt_notify_for_attack("Brute Force") is True
        with patch("hate_crack.notify._send_pushover") as send:
            notify.notify_job_done("Brute Force", 1)
        assert send.called

    def test_suppression_silences_fire(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        with patch("hate_crack.notify._send_pushover") as send:
            with notify.suppressed_notifications():
                notify.notify_job_done("Brute Force", 1)
        send.assert_not_called()

    def test_does_not_leak_plaintext_in_message(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        # Message we pass to notify_job_done is count + attack_name + hash
        # path only. Confirm nothing in the payload contains a plausible
        # plaintext password token.
        with patch("hate_crack.notify._send_pushover") as send:
            notify.notify_job_done("Brute Force", 42, hash_file="/tmp/h.txt")
        title, message = send.call_args.args[2], send.call_args.args[3]
        for banned in ("plaintext", "password=", "secret"):
            assert banned not in title
            assert banned not in message


class TestNotifyCrack:
    def test_fires_when_allowed(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        with patch("hate_crack.notify._send_pushover") as send:
            notify.notify_crack("alice", "Brute Force")
        assert send.called

    def test_no_op_when_suppressed(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        with patch("hate_crack.notify._send_pushover") as send:
            with notify.suppressed_notifications():
                notify.notify_crack("alice", "Brute Force")
        send.assert_not_called()


class TestPromptNotifyForAttack:
    def test_no_prompt_when_globally_disabled(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=False)
        calls: list[str] = []
        notify.set_input_func(lambda p: calls.append(p) or "y")
        assert notify.prompt_notify_for_attack("Brute Force") is False
        assert calls == []

    def test_no_prompt_when_already_in_allowlist(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        calls: list[str] = []
        notify.set_input_func(lambda p: calls.append(p) or "n")
        assert notify.prompt_notify_for_attack("Brute Force") is True
        assert calls == []

    def test_answer_yes(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=True)
        notify.set_input_func(lambda _: "y")
        assert notify.prompt_notify_for_attack("Brute Force") is True

    def test_answer_no(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=True)
        notify.set_input_func(lambda _: "n")
        assert notify.prompt_notify_for_attack("Brute Force") is False

    def test_answer_empty_defaults_to_no(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=True)
        notify.set_input_func(lambda _: "")
        assert notify.prompt_notify_for_attack("Brute Force") is False

    def test_answer_always_persists_to_allowlist(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_enabled=True)
        notify.set_input_func(lambda _: "always")
        assert notify.prompt_notify_for_attack("Brute Force") is True
        data = json.loads(config_path.read_text())
        assert "Brute Force" in data.get("notify_attack_allowlist", [])
        # Settings in memory also updated so we don't re-prompt next call.
        settings = notify.get_settings()
        assert "Brute Force" in settings.attack_allowlist

    def test_always_is_idempotent(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_enabled=True)
        notify.set_input_func(lambda _: "always")
        notify.prompt_notify_for_attack("Brute Force")
        notify.prompt_notify_for_attack("Brute Force")
        data = json.loads(config_path.read_text())
        assert data["notify_attack_allowlist"].count("Brute Force") == 1


class TestToggleEnabled:
    def test_toggle_flips_and_persists(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_enabled=False)
        assert notify.get_settings().enabled is False
        new_state = notify.toggle_enabled()
        assert new_state is True
        assert notify.get_settings().enabled is True
        data = json.loads(config_path.read_text())
        assert data["notify_enabled"] is True

        # Flip back.
        assert notify.toggle_enabled() is False
        data = json.loads(config_path.read_text())
        assert data["notify_enabled"] is False

    def test_toggle_without_init_still_works(self) -> None:
        notify.clear_state_for_tests()
        # Call toggle before init ever ran — should just flip in-memory.
        assert notify.toggle_enabled() is True
        assert notify.get_settings().enabled is True


class TestStartStopTailer:
    def test_start_tailer_noop_when_disabled(self, tmp_path: Path) -> None:
        _init_with(tmp_path, notify_enabled=False, notify_per_crack_enabled=True)
        t = notify.start_tailer(str(tmp_path / "h.out"), "Brute Force")
        assert t is None

    def test_start_tailer_noop_when_per_crack_disabled(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_per_crack_enabled=False,
            notify_attack_allowlist=["Brute Force"],
        )
        t = notify.start_tailer(str(tmp_path / "h.out"), "Brute Force")
        assert t is None

    def test_start_tailer_noop_when_suppressed(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_per_crack_enabled=True,
            notify_attack_allowlist=["Brute Force"],
        )
        with notify.suppressed_notifications():
            t = notify.start_tailer(str(tmp_path / "h.out"), "Brute Force")
        assert t is None

    def test_start_tailer_when_enabled_and_consented(self, tmp_path: Path) -> None:
        _init_with(
            tmp_path,
            notify_enabled=True,
            notify_per_crack_enabled=True,
            notify_attack_allowlist=["Brute Force"],
            notify_poll_interval_seconds=0.05,
        )
        out = tmp_path / "h.out"
        out.write_text("")
        t = notify.start_tailer(str(out), "Brute Force")
        try:
            assert t is not None
            assert t.is_alive()
        finally:
            notify.stop_tailer(t)

    def test_stop_tailer_none_is_noop(self) -> None:
        # Must not raise.
        notify.stop_tailer(None)
