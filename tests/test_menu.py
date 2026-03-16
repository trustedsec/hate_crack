from unittest.mock import MagicMock, patch

from hate_crack.menu import (
    _arrow_menu,
    _numbered_menu,
    _use_arrow_menu,
    interactive_menu,
)

SAMPLE_ITEMS = [
    ("1", "Quick Crack"),
    ("2", "Brute Force"),
    ("99", "Quit"),
]


class TestUseArrowMenu:
    def test_falls_back_without_library(self, monkeypatch):
        import hate_crack.menu as mod

        monkeypatch.setattr(mod, "_HAS_TERM_MENU", False)
        monkeypatch.delenv("HATE_CRACK_PLAIN_MENU", raising=False)
        assert _use_arrow_menu() is False

    def test_falls_back_on_non_tty(self, monkeypatch):
        import hate_crack.menu as mod

        monkeypatch.setattr(mod, "_HAS_TERM_MENU", True)
        monkeypatch.delenv("HATE_CRACK_PLAIN_MENU", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: False)
        assert _use_arrow_menu() is False

    def test_falls_back_with_env_var(self, monkeypatch):
        import hate_crack.menu as mod

        monkeypatch.setattr(mod, "_HAS_TERM_MENU", True)
        monkeypatch.setenv("HATE_CRACK_PLAIN_MENU", "1")
        assert _use_arrow_menu() is False

    def test_enabled_when_all_conditions_met(self, monkeypatch):
        import hate_crack.menu as mod

        monkeypatch.setattr(mod, "_HAS_TERM_MENU", True)
        monkeypatch.delenv("HATE_CRACK_PLAIN_MENU", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        assert _use_arrow_menu() is True


class TestNumberedMenu:
    def test_returns_correct_key(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "2")
        result = _numbered_menu(SAMPLE_ITEMS, "\nSelect: ")
        assert result == "2"

    def test_prints_all_labels(self, monkeypatch, capsys):
        monkeypatch.setattr("builtins.input", lambda _: "1")
        _numbered_menu(SAMPLE_ITEMS, "\nSelect: ")
        captured = capsys.readouterr().out
        for key, label in SAMPLE_ITEMS:
            assert f"({key}) {label}" in captured

    def test_returns_none_on_empty_input(self, monkeypatch):
        monkeypatch.setattr("builtins.input", lambda _: "")
        result = _numbered_menu(SAMPLE_ITEMS, "\nSelect: ")
        assert result is None


class TestArrowMenu:
    def test_returns_correct_key(self):
        mock_menu_instance = MagicMock()
        mock_menu_instance.show.return_value = 1  # index 1 -> key "2"
        with patch(
            "hate_crack.menu.TerminalMenu",
            create=True,
            return_value=mock_menu_instance,
        ):
            result = _arrow_menu(SAMPLE_ITEMS, "Title")
        assert result == "2"

    def test_returns_none_on_escape(self):
        mock_menu_instance = MagicMock()
        mock_menu_instance.show.return_value = None
        with patch(
            "hate_crack.menu.TerminalMenu",
            create=True,
            return_value=mock_menu_instance,
        ):
            result = _arrow_menu(SAMPLE_ITEMS, "Title")
        assert result is None


class TestInteractiveMenu:
    def test_uses_numbered_when_no_tty(self, monkeypatch):
        import hate_crack.menu as mod

        monkeypatch.setattr(mod, "_HAS_TERM_MENU", False)
        monkeypatch.delenv("HATE_CRACK_PLAIN_MENU", raising=False)
        monkeypatch.setattr("builtins.input", lambda _: "99")
        result = interactive_menu(SAMPLE_ITEMS)
        assert result == "99"

    def test_uses_arrow_when_available(self, monkeypatch):
        import hate_crack.menu as mod

        monkeypatch.setattr(mod, "_HAS_TERM_MENU", True)
        monkeypatch.delenv("HATE_CRACK_PLAIN_MENU", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True)
        mock_menu_instance = MagicMock()
        mock_menu_instance.show.return_value = 0
        with patch(
            "hate_crack.menu.TerminalMenu",
            create=True,
            return_value=mock_menu_instance,
        ):
            result = interactive_menu(SAMPLE_ITEMS, title="Test")
        assert result == "1"
