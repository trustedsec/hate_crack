"""The "Download Rule" prompt accepts 'a'/'all' to fetch every rule."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _pick_by_text(choices):
    def _pick(items, **kwargs):
        wanted = choices.pop(0)
        return next(key for key, text in items if text == wanted)

    return _pick


def _drive(main_module, monkeypatch, entry, harness=None):
    monkeypatch.setattr(main_module, "hcatHashFile", None)
    monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)

    if harness is None:
        harness = MagicMock()
        harness.list_rules.return_value = [{"id": 4, "name": "best64.rule", "size": 77}]
        harness.download_all_rules.return_value = [
            {
                "id": 4,
                "name": "best64.rule",
                "output_file": "/tmp/best64.rule",
                "size": 77,
            }
        ]

    inputs = iter([entry])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
    monkeypatch.setattr(
        main_module,
        "interactive_menu",
        _pick_by_text(["Download Rule", "Back to Main Menu"]),
        raising=False,
    )

    with patch.object(main_module, "HashviewAPI", return_value=harness):
        main_module.hashview_api()

    return harness


@pytest.mark.parametrize("entry", ["a", "A", "all", "ALL", " all "])
def test_all_shortcut_downloads_every_rule(main_module, monkeypatch, entry, capsys):
    """Only one input is consumed: no output-filename prompt follows."""
    harness = _drive(main_module, monkeypatch, entry)
    harness.download_all_rules.assert_called_once_with()
    harness.download_rules.assert_not_called()
    out = capsys.readouterr().out
    assert "Downloaded 77 bytes: /tmp/best64.rule" in out
    assert "Downloaded 1 of 1 rules" in out


def test_prompt_advertises_the_all_shortcut(main_module, monkeypatch, capsys):
    prompts = []

    monkeypatch.setattr(main_module, "hcatHashFile", None)
    monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)

    harness = MagicMock()
    harness.list_rules.return_value = [{"id": 4, "name": "best64.rule", "size": 77}]
    harness.download_all_rules.return_value = []

    def _input(prompt=""):
        prompts.append(prompt)
        return "a"

    monkeypatch.setattr("builtins.input", _input)
    monkeypatch.setattr(
        main_module,
        "interactive_menu",
        _pick_by_text(["Download Rule", "Back to Main Menu"]),
        raising=False,
    )
    with patch.object(main_module, "HashviewAPI", return_value=harness):
        main_module.hashview_api()

    assert len(prompts) == 1
    assert "a" in prompts[0].lower() and "all" in prompts[0].lower()


def test_numeric_entry_still_downloads_a_single_rule(main_module, monkeypatch, capsys):
    monkeypatch.setattr(main_module, "hcatHashFile", None)
    monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)

    harness = MagicMock()
    harness.list_rules.return_value = [{"id": 4, "name": "best64.rule", "size": 77}]
    harness.download_rules.return_value = {
        "size": 77,
        "output_file": "/tmp/best64.rule",
    }

    inputs = iter(["4", ""])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(inputs))
    monkeypatch.setattr(
        main_module,
        "interactive_menu",
        _pick_by_text(["Download Rule", "Back to Main Menu"]),
        raising=False,
    )
    with patch.object(main_module, "HashviewAPI", return_value=harness):
        main_module.hashview_api()

    harness.download_rules.assert_called_once_with(4, "best64.rule")
    harness.download_all_rules.assert_not_called()


def test_all_shortcut_reports_fetch_error(main_module, monkeypatch, capsys):
    harness = MagicMock()
    harness.list_rules.return_value = [{"id": 4, "name": "best64.rule", "size": 77}]
    harness.download_all_rules.side_effect = Exception("boom")
    _drive(main_module, monkeypatch, "a", harness=harness)
    assert "Error fetching rules: boom" in capsys.readouterr().out


def test_non_numeric_entry_still_rejected(main_module, monkeypatch, capsys):
    harness = MagicMock()
    harness.list_rules.return_value = [{"id": 4, "name": "best64.rule", "size": 77}]
    _drive(main_module, monkeypatch, "banana", harness=harness)
    assert "Invalid ID entered" in capsys.readouterr().out
    harness.download_all_rules.assert_not_called()
