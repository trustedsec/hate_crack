"""Unit tests for the toggle_per_crack_enabled runtime toggle."""

import importlib.util
import json
from pathlib import Path

from hate_crack import notify as _notify

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_CLI_SPEC = importlib.util.spec_from_file_location(
    "hate_crack_cli_percrack", PROJECT_ROOT / "hate_crack.py"
)
CLI_MODULE = importlib.util.module_from_spec(_CLI_SPEC)
_CLI_SPEC.loader.exec_module(CLI_MODULE)


def _init_with(tmp_path: Path, **overrides) -> Path:
    """Seed a config file with defaults + overrides and init the notify module."""
    config_path = tmp_path / "config.json"
    cfg = {
        "notify_enabled": False,
        "notify_per_crack_enabled": False,
        "notify_pushover_token": "",
        "notify_pushover_user": "",
    }
    cfg.update(overrides)
    config_path.write_text(json.dumps(cfg))
    _notify.init(str(config_path), cfg)
    return config_path


class TestTogglePerCrackEnabled:
    def test_off_to_on_flips_and_persists(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path)
        try:
            new_state = _notify.toggle_per_crack_enabled()
            assert new_state is True
            assert _notify.get_settings().per_crack_enabled is True
            data = json.loads(config_path.read_text())
            assert data["notify_per_crack_enabled"] is True
        finally:
            _notify.clear_state_for_tests()

    def test_on_to_off_flips_and_persists(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_per_crack_enabled=True)
        try:
            new_state = _notify.toggle_per_crack_enabled()
            assert new_state is False
            assert _notify.get_settings().per_crack_enabled is False
            data = json.loads(config_path.read_text())
            assert data["notify_per_crack_enabled"] is False
        finally:
            _notify.clear_state_for_tests()

    def test_toggle_without_init_uses_defaults(self) -> None:
        # Mirrors the behavior of toggle_enabled: must not crash when init
        # was never called. The toggle flips an in-memory default; nothing
        # is persisted because _config_path is None.
        try:
            _notify.clear_state_for_tests()
            new_state = _notify.toggle_per_crack_enabled()
            assert new_state is True
            assert _notify.get_settings().per_crack_enabled is True
        finally:
            _notify.clear_state_for_tests()

    def test_does_not_touch_global_enabled(self, tmp_path: Path) -> None:
        config_path = _init_with(tmp_path, notify_enabled=False)
        try:
            _notify.toggle_per_crack_enabled()
            data = json.loads(config_path.read_text())
            # notify_enabled stays False; only per-crack flipped.
            assert data["notify_enabled"] is False
            assert data["notify_per_crack_enabled"] is True
        finally:
            _notify.clear_state_for_tests()


class TestTogglePerCrackNotificationsUI:
    def _seed_settings(self, monkeypatch, *, enabled: bool, per_crack: bool):
        from hate_crack.notify.settings import NotifySettings

        settings = NotifySettings(enabled=enabled, per_crack_enabled=per_crack)
        monkeypatch.setattr(CLI_MODULE._notify, "get_settings", lambda: settings)
        return settings

    def test_guard_refuses_on_when_global_off(self, monkeypatch, capsys):
        self._seed_settings(monkeypatch, enabled=False, per_crack=False)
        called = {"n": 0}

        def _fake_toggle() -> bool:
            called["n"] += 1
            return True

        monkeypatch.setattr(
            CLI_MODULE._notify, "toggle_per_crack_enabled", _fake_toggle
        )
        CLI_MODULE.toggle_per_crack_notifications()
        captured = capsys.readouterr().out
        assert "Global Pushover notifications are OFF" in captured
        assert called["n"] == 0

    def test_flips_on_when_global_on(self, monkeypatch, capsys):
        self._seed_settings(monkeypatch, enabled=True, per_crack=False)
        called = {"n": 0}

        def _fake_toggle() -> bool:
            called["n"] += 1
            return True

        monkeypatch.setattr(
            CLI_MODULE._notify, "toggle_per_crack_enabled", _fake_toggle
        )
        CLI_MODULE.toggle_per_crack_notifications()
        captured = capsys.readouterr().out
        assert "Per-crack notifications are now ON" in captured
        assert called["n"] == 1

    def test_off_to_off_is_allowed_even_if_global_off(self, monkeypatch, capsys):
        # Turning OFF must always succeed, even with global OFF, so a user
        # can clean up an inconsistent (per_crack=True, enabled=False) config.
        self._seed_settings(monkeypatch, enabled=False, per_crack=True)
        called = {"n": 0}

        def _fake_toggle() -> bool:
            called["n"] += 1
            return False

        monkeypatch.setattr(
            CLI_MODULE._notify, "toggle_per_crack_enabled", _fake_toggle
        )
        CLI_MODULE.toggle_per_crack_notifications()
        captured = capsys.readouterr().out
        assert "Per-crack notifications are now OFF" in captured
        assert called["n"] == 1
