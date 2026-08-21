"""Interactive-menu coverage for the "Download All Rules" Hashview option."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _pick_by_text(choices):
    """Build an interactive_menu stand-in that pops one wanted label per call.

    A genexpr predicate that calls next() on a shared iterator is evaluated
    once per candidate item, not once per menu invocation, so a plain
    iterator silently desyncs; popping outside the predicate avoids that.
    """

    def _pick(items, **kwargs):
        wanted = choices.pop(0)
        return next(key for key, text in items if text == wanted)

    return _pick


def _drive_menu(main_module, monkeypatch, download_all_rules_return):
    monkeypatch.setattr(main_module, "hcatHashFile", None)
    monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)

    harness = MagicMock()
    harness.download_all_rules.return_value = download_all_rules_return

    monkeypatch.setattr(
        main_module,
        "interactive_menu",
        _pick_by_text(["Download All Rules", "Back to Main Menu"]),
        raising=False,
    )

    with patch.object(main_module, "HashviewAPI", return_value=harness):
        main_module.hashview_api()

    return harness


def test_download_all_rules_calls_harness_once(main_module, monkeypatch):
    harness = _drive_menu(
        main_module,
        monkeypatch,
        [
            {
                "id": 4,
                "name": "best64.rule",
                "output_file": "/tmp/best64.rule",
                "size": 77,
            }
        ],
    )
    harness.download_all_rules.assert_called_once_with()


def test_download_all_rules_reports_success_and_failure_counts(
    main_module, monkeypatch, capsys
):
    _drive_menu(
        main_module,
        monkeypatch,
        [
            {
                "id": 4,
                "name": "best64.rule",
                "output_file": "/tmp/best64.rule",
                "size": 77,
            },
            {"id": 5, "name": "stale.rule", "error": "404"},
        ],
    )
    out = capsys.readouterr().out
    assert "Downloaded 77 bytes: /tmp/best64.rule" in out
    assert "Error downloading rule 5: 404" in out
    assert "Downloaded 1 of 2 rules (1 failed)" in out


def test_download_all_rules_handles_no_rules(main_module, monkeypatch, capsys):
    _drive_menu(main_module, monkeypatch, [])
    assert "No rules found." in capsys.readouterr().out


def test_download_all_rules_reports_fetch_error(main_module, monkeypatch, capsys):
    monkeypatch.setattr(main_module, "hcatHashFile", None)
    monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)

    harness = MagicMock()
    harness.download_all_rules.side_effect = Exception("boom")

    monkeypatch.setattr(
        main_module,
        "interactive_menu",
        _pick_by_text(["Download All Rules", "Back to Main Menu"]),
        raising=False,
    )

    with patch.object(main_module, "HashviewAPI", return_value=harness):
        main_module.hashview_api()

    assert "Error fetching rules: boom" in capsys.readouterr().out
