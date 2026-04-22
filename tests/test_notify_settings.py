"""Unit tests for hate_crack.notify.settings."""
import json
from pathlib import Path

from hate_crack.notify.settings import (
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
    save_per_crack_enabled,
)


class TestNotifySettingsDataclass:
    def test_defaults(self) -> None:
        s = NotifySettings()
        assert s.enabled is False
        assert s.pushover_token == ""
        assert s.pushover_user == ""
        assert s.per_crack_enabled is False
        assert s.attack_allowlist == []
        assert s.suppress_in_orchestrators is True
        assert s.max_cracks_per_burst == 5
        assert s.poll_interval_seconds == 5.0

    def test_allowlist_default_is_fresh_per_instance(self) -> None:
        # field(default_factory=list) must not share state.
        a = NotifySettings()
        b = NotifySettings()
        a.attack_allowlist.append("Brute Force")
        assert b.attack_allowlist == []


class TestLoadSettings:
    def test_load_from_empty_dict_returns_defaults(self) -> None:
        s = load_settings({})
        assert s == NotifySettings()

    def test_load_from_none_returns_defaults(self) -> None:
        assert load_settings(None) == NotifySettings()

    def test_load_full_dict(self) -> None:
        s = load_settings({
            "notify_enabled": True,
            "notify_pushover_token": "tok",
            "notify_pushover_user": "usr",
            "notify_per_crack_enabled": True,
            "notify_attack_allowlist": ["Brute Force", "Dictionary"],
            "notify_suppress_in_orchestrators": False,
            "notify_max_cracks_per_burst": 20,
            "notify_poll_interval_seconds": 2.5,
        })
        assert s.enabled is True
        assert s.pushover_token == "tok"
        assert s.pushover_user == "usr"
        assert s.per_crack_enabled is True
        assert s.attack_allowlist == ["Brute Force", "Dictionary"]
        assert s.suppress_in_orchestrators is False
        assert s.max_cracks_per_burst == 20
        assert s.poll_interval_seconds == 2.5

    def test_load_tolerates_bad_types(self) -> None:
        s = load_settings({
            "notify_enabled": "true",
            "notify_max_cracks_per_burst": "not-a-number",
            "notify_poll_interval_seconds": "also-bad",
            "notify_attack_allowlist": "not-a-list",
        })
        # string "true" -> True
        assert s.enabled is True
        # bad ints fall back to defaults (5, 5.0)
        assert s.max_cracks_per_burst == 5
        assert s.poll_interval_seconds == 5.0
        # non-list allowlist becomes empty list
        assert s.attack_allowlist == []


class TestSaveEnabled:
    def test_writes_new_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        save_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data["notify_enabled"] is True

    def test_preserves_existing_keys(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        initial = {
            "hcatBin": "hashcat",
            "hashview_api_key": "secret",
            "notify_enabled": False,
        }
        config_path.write_text(json.dumps(initial))
        save_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data["hcatBin"] == "hashcat"
        assert data["hashview_api_key"] == "secret"
        assert data["notify_enabled"] is True

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        save_enabled(str(config_path), True)
        save_enabled(str(config_path), False)
        data = json.loads(config_path.read_text())
        assert data["notify_enabled"] is False

    def test_invalid_existing_config_replaced(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text("this is not json")
        save_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data == {"notify_enabled": True}

    def test_atomic_no_half_write(self, tmp_path: Path) -> None:
        # A partial write should never leave the main file invalid. We
        # check that after save_enabled, parsing always succeeds.
        config_path = tmp_path / "config.json"
        for flag in (True, False, True, False, True):
            save_enabled(str(config_path), flag)
            json.loads(config_path.read_text())  # must not raise


class TestAddToAllowlist:
    def test_adds_to_empty_list(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        add_to_allowlist(str(config_path), "Brute Force")
        data = json.loads(config_path.read_text())
        assert data["notify_attack_allowlist"] == ["Brute Force"]

    def test_idempotent(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        add_to_allowlist(str(config_path), "Brute Force")
        add_to_allowlist(str(config_path), "Brute Force")
        add_to_allowlist(str(config_path), "Brute Force")
        data = json.loads(config_path.read_text())
        assert data["notify_attack_allowlist"] == ["Brute Force"]

    def test_preserves_other_entries(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({
            "hcatBin": "hashcat",
            "notify_attack_allowlist": ["Existing"],
        }))
        add_to_allowlist(str(config_path), "Brute Force")
        data = json.loads(config_path.read_text())
        assert data["hcatBin"] == "hashcat"
        assert data["notify_attack_allowlist"] == ["Existing", "Brute Force"]

    def test_empty_attack_name_is_noop(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"notify_attack_allowlist": ["A"]}))
        add_to_allowlist(str(config_path), "")
        data = json.loads(config_path.read_text())
        assert data["notify_attack_allowlist"] == ["A"]

    def test_repairs_non_list_allowlist(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(json.dumps({"notify_attack_allowlist": "bogus"}))
        add_to_allowlist(str(config_path), "Brute Force")
        data = json.loads(config_path.read_text())
        assert data["notify_attack_allowlist"] == ["Brute Force"]


class TestSavePerCrackEnabled:
    def test_writes_new_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        save_per_crack_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data["notify_per_crack_enabled"] is True

    def test_preserves_existing_keys(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        initial = {
            "hcatBin": "hashcat",
            "notify_enabled": True,
            "notify_per_crack_enabled": False,
        }
        config_path.write_text(json.dumps(initial))
        save_per_crack_enabled(str(config_path), True)
        data = json.loads(config_path.read_text())
        assert data["hcatBin"] == "hashcat"
        assert data["notify_enabled"] is True
        assert data["notify_per_crack_enabled"] is True

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        save_per_crack_enabled(str(config_path), True)
        save_per_crack_enabled(str(config_path), False)
        data = json.loads(config_path.read_text())
        assert data["notify_per_crack_enabled"] is False
