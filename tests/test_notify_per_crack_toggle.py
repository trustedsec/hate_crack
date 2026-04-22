"""Unit tests for the toggle_per_crack_enabled runtime toggle."""
import json
from pathlib import Path

from hate_crack import notify as _notify


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
