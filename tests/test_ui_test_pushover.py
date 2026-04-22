"""Unit tests for main.test_pushover_notification()."""
from unittest.mock import patch

import pytest

from hate_crack import main as hc_main
from hate_crack import notify
from hate_crack.notify.settings import NotifySettings


@pytest.fixture(autouse=True)
def _reset_notify_state():
    notify.clear_state_for_tests()
    yield
    notify.clear_state_for_tests()


def _install_settings(
    *,
    enabled: bool = True,
    token: str = "tok",
    user: str = "usr",
) -> None:
    """Swap fresh settings into the notify module for this test."""
    settings = NotifySettings()
    settings.enabled = enabled
    settings.pushover_token = token
    settings.pushover_user = user
    notify._settings = settings


class TestTestPushoverNotification:
    def test_success_prints_confirmation_and_sends(self, capsys):
        _install_settings(enabled=True, token="tok", user="usr")
        with patch("hate_crack.notify._send_pushover", return_value=True) as send:
            hc_main.test_pushover_notification()
        assert send.called
        args = send.call_args.args
        assert args[0] == "tok"
        assert args[1] == "usr"
        assert args[2] == "hate_crack: test notification"
        assert "test notification from hate_crack" in args[3]
        out = capsys.readouterr().out
        assert "[+] Test Pushover notification sent" in out

    def test_failure_prints_failure_line(self, capsys):
        _install_settings(enabled=True, token="tok", user="usr")
        with patch("hate_crack.notify._send_pushover", return_value=False):
            hc_main.test_pushover_notification()
        out = capsys.readouterr().out
        assert "[!] Test Pushover notification failed" in out

    def test_missing_token_skips_send_and_warns(self, capsys):
        _install_settings(enabled=True, token="", user="usr")
        with patch("hate_crack.notify._send_pushover") as send:
            hc_main.test_pushover_notification()
        send.assert_not_called()
        out = capsys.readouterr().out
        assert "[!] Pushover credentials missing" in out
        assert "notify_pushover_token" in out

    def test_missing_user_skips_send_and_warns(self, capsys):
        _install_settings(enabled=True, token="tok", user="")
        with patch("hate_crack.notify._send_pushover") as send:
            hc_main.test_pushover_notification()
        send.assert_not_called()
        out = capsys.readouterr().out
        assert "[!] Pushover credentials missing" in out

    def test_globally_off_still_sends_with_note(self, capsys):
        _install_settings(enabled=False, token="tok", user="usr")
        with patch("hate_crack.notify._send_pushover", return_value=True) as send:
            hc_main.test_pushover_notification()
        send.assert_called_once()
        out = capsys.readouterr().out
        assert "notifications are globally OFF" in out
        assert "[+] Test Pushover notification sent" in out
