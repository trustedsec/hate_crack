"""Unit tests for main.test_pushover_notification().

These tests patch ``hate_crack.main._notify`` directly rather than
``hate_crack.notify._send_pushover``.  The latter is fragile because
``tests/test_random_rules_attack.py`` purges ``hate_crack.*`` from
``sys.modules`` and re-imports, which leaves ``main._notify`` pointing
at a different module object than the one a top-level ``patch`` would
touch.  Patching the attribute on ``main`` itself is robust to that.

We use ``patch.object(hc_main, "_notify")`` rather than
``patch("hate_crack.main._notify")`` so the patch target is the exact
module object whose function we invoke.  A string target would re-resolve
``hate_crack.main`` through ``sys.modules``, which — again thanks to the
purge in ``test_random_rules_attack.py`` — can be a different object from
the ``hc_main`` reference bound at test-module import time.
"""

from types import SimpleNamespace
from unittest.mock import patch

from hate_crack import main as hc_main


def _settings(
    *, enabled: bool = True, token: str = "tok", user: str = "usr"
) -> SimpleNamespace:
    """Minimal stand-in for ``NotifySettings`` — we only read three fields."""
    return SimpleNamespace(enabled=enabled, pushover_token=token, pushover_user=user)


class TestTestPushoverNotification:
    def test_success_prints_confirmation_and_sends(self, capsys):
        with patch.object(hc_main, "_notify") as mock_notify:
            mock_notify.get_settings.return_value = _settings(enabled=True)
            mock_notify._send_pushover.return_value = True
            hc_main.test_pushover_notification()
        mock_notify._send_pushover.assert_called_once()
        args = mock_notify._send_pushover.call_args.args
        assert args[0] == "tok"
        assert args[1] == "usr"
        assert args[2] == "hate_crack: test notification"
        assert "test notification from hate_crack" in args[3]
        out = capsys.readouterr().out
        assert "[+] Test Pushover notification sent" in out

    def test_failure_prints_failure_line(self, capsys):
        with patch.object(hc_main, "_notify") as mock_notify:
            mock_notify.get_settings.return_value = _settings(enabled=True)
            mock_notify._send_pushover.return_value = False
            hc_main.test_pushover_notification()
        out = capsys.readouterr().out
        assert "[!] Test Pushover notification failed" in out

    def test_missing_token_skips_send_and_warns(self, capsys):
        with patch.object(hc_main, "_notify") as mock_notify:
            mock_notify.get_settings.return_value = _settings(enabled=True, token="")
            hc_main.test_pushover_notification()
        mock_notify._send_pushover.assert_not_called()
        out = capsys.readouterr().out
        assert "[!] Pushover credentials missing" in out
        assert "notify_pushover_token" in out

    def test_missing_user_skips_send_and_warns(self, capsys):
        with patch.object(hc_main, "_notify") as mock_notify:
            mock_notify.get_settings.return_value = _settings(enabled=True, user="")
            hc_main.test_pushover_notification()
        mock_notify._send_pushover.assert_not_called()
        out = capsys.readouterr().out
        assert "[!] Pushover credentials missing" in out

    def test_globally_off_still_sends_with_note(self, capsys):
        with patch.object(hc_main, "_notify") as mock_notify:
            mock_notify.get_settings.return_value = _settings(enabled=False)
            mock_notify._send_pushover.return_value = True
            hc_main.test_pushover_notification()
        mock_notify._send_pushover.assert_called_once()
        out = capsys.readouterr().out
        assert "notifications are globally OFF" in out
        assert "[+] Test Pushover notification sent" in out
