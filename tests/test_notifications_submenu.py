"""Unit tests for the Notifications submenu dispatcher (main-menu option 82).

Patching note: ``notifications_submenu`` is defined in ``hate_crack/main.py``
and resolves ``toggle_notifications`` / ``toggle_per_crack_notifications`` /
``test_pushover_notification`` against ``hate_crack.main``'s own globals.
We therefore patch that module directly — patching the ``hate_crack.py``
proxy would have no effect on the submenu's internal dispatch.
"""

import hate_crack.main as _main_mod
import hate_crack.menu as _menu_mod
from hate_crack.notify.settings import NotifySettings


def _stub_action_handlers(monkeypatch, calls):
    monkeypatch.setattr(
        _main_mod, "toggle_notifications", lambda: calls.append("toggle")
    )
    monkeypatch.setattr(
        _main_mod,
        "toggle_per_crack_notifications",
        lambda: calls.append("toggle_pc"),
    )
    monkeypatch.setattr(
        _main_mod,
        "test_pushover_notification",
        lambda: calls.append("test"),
    )


def _queue_menu_choices(monkeypatch, choices):
    """Queue ``choices`` as sequential return values from ``interactive_menu``.

    Always appends a final ``"99"`` so the loop exits even if the caller
    forgot — this mirrors how the real user ends a submenu.
    """
    iterator = iter(list(choices) + ["99"])

    def _fake_menu(items, title=""):
        return next(iterator)

    monkeypatch.setattr(_menu_mod, "interactive_menu", _fake_menu)


class TestNotificationsSubmenu:
    def test_choice_1_dispatches_toggle_notifications(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)
        _queue_menu_choices(monkeypatch, ["1"])
        _main_mod.notifications_submenu()
        assert calls == ["toggle"]

    def test_choice_2_dispatches_toggle_per_crack(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)
        _queue_menu_choices(monkeypatch, ["2"])
        _main_mod.notifications_submenu()
        assert calls == ["toggle_pc"]

    def test_choice_3_dispatches_test_pushover(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)
        _queue_menu_choices(monkeypatch, ["3"])
        _main_mod.notifications_submenu()
        assert calls == ["test"]

    def test_choice_99_exits_without_dispatch(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)

        def _only_99(items, title=""):
            return "99"

        monkeypatch.setattr(_menu_mod, "interactive_menu", _only_99)
        _main_mod.notifications_submenu()
        assert calls == []

    def test_none_choice_exits_without_dispatch(self, monkeypatch):
        calls = []
        _stub_action_handlers(monkeypatch, calls)

        def _returns_none(items, title=""):
            return None

        monkeypatch.setattr(_menu_mod, "interactive_menu", _returns_none)
        _main_mod.notifications_submenu()
        assert calls == []

    def test_submenu_labels_reflect_live_settings(self, monkeypatch):
        captured_items = {}

        def _capture(items, title=""):
            captured_items["items"] = items
            captured_items["title"] = title
            return "99"

        monkeypatch.setattr(_menu_mod, "interactive_menu", _capture)
        monkeypatch.setattr(
            _main_mod._notify,
            "get_settings",
            lambda: NotifySettings(enabled=True, per_crack_enabled=False),
        )
        _main_mod.notifications_submenu()
        labels = {k: v for k, v in captured_items["items"]}
        assert "ON" in labels["1"]
        assert "OFF" in labels["2"]
        assert labels["3"] == "Send Test Pushover Notification"
        assert labels["99"] == "Back to Main Menu"
        assert "Notifications" in captured_items["title"]

    def test_labels_refresh_between_iterations(self, monkeypatch):
        # Guards against a regression where items are built once outside
        # the while-loop: labels would go stale after a toggle.
        settings = NotifySettings(enabled=False, per_crack_enabled=False)
        monkeypatch.setattr(_main_mod._notify, "get_settings", lambda: settings)

        def _flip_enabled():
            settings.enabled = not settings.enabled

        monkeypatch.setattr(_main_mod, "toggle_notifications", _flip_enabled)
        monkeypatch.setattr(_main_mod, "toggle_per_crack_notifications", lambda: None)
        monkeypatch.setattr(_main_mod, "test_pushover_notification", lambda: None)

        captured = []
        choices = iter(["1", "99"])

        def _fake_menu(items, title=""):
            captured.append(dict(items))
            return next(choices)

        monkeypatch.setattr(_menu_mod, "interactive_menu", _fake_menu)
        _main_mod.notifications_submenu()

        assert len(captured) == 2
        assert "[OFF]" in captured[0]["1"]
        assert "[ON]" in captured[1]["1"]
