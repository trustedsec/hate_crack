"""Unit tests for hate_crack.notify.settings.

The three keys this module persists are all ``home="json"``, so every write
here goes to ``config.json`` via an atomic read-modify-write. Nothing in this
module touches `.env`, which holds only the Pushover credentials.
"""

import json
import stat
from pathlib import Path

import pytest

from hate_crack.config_loader import load_config
from hate_crack.config_schema import JSON_KEYS
from hate_crack.notify.settings import (
    AllowlistNameError,
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
    save_per_crack_enabled,
)


def _seed_config(tmp_path: Path, **overrides) -> Path:
    """Write a full config.json (the 35 json-homed keys) and return its path."""
    data = {entry.legacy: entry.default for entry in JSON_KEYS}
    data.update(overrides)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(data, indent=2))
    return config_path


def _read_back(config_path: Path) -> dict:
    """Reload the persisted config.json through the shared loader."""
    return load_config(legacy_json_path=str(config_path), environ={}).config


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


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
        s = load_settings(
            {
                "notify_enabled": True,
                "notify_pushover_token": "tok",
                "notify_pushover_user": "usr",
                "notify_per_crack_enabled": True,
                "notify_attack_allowlist": ["Brute Force", "Dictionary"],
                "notify_suppress_in_orchestrators": False,
                "notify_max_cracks_per_burst": 20,
                "notify_poll_interval_seconds": 2.5,
            }
        )
        assert s.enabled is True
        assert s.pushover_token == "tok"
        assert s.pushover_user == "usr"
        assert s.per_crack_enabled is True
        assert s.attack_allowlist == ["Brute Force", "Dictionary"]
        assert s.suppress_in_orchestrators is False
        assert s.max_cracks_per_burst == 20
        assert s.poll_interval_seconds == 2.5

    def test_load_tolerates_bad_types(self) -> None:
        s = load_settings(
            {
                "notify_enabled": "true",
                "notify_max_cracks_per_burst": "not-a-number",
                "notify_poll_interval_seconds": "also-bad",
                "notify_attack_allowlist": "not-a-list",
            }
        )
        # string "true" -> True
        assert s.enabled is True
        # bad ints fall back to defaults (5, 5.0)
        assert s.max_cracks_per_burst == 5
        assert s.poll_interval_seconds == 5.0
        # non-list allowlist becomes empty list
        assert s.attack_allowlist == []


class TestSaveEnabled:
    def test_writes_notify_enabled(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_enabled(str(config_path), True)
        assert _read_back(config_path)["notify_enabled"] is True

    def test_preserves_every_other_key(self, tmp_path: Path) -> None:
        config_path = _seed_config(
            tmp_path, hcatBin="hashcat-6.2.6", bandrelmaxruntime=42
        )
        before = json.loads(config_path.read_text())

        save_enabled(str(config_path), True)

        after = json.loads(config_path.read_text())
        assert set(after) == set(before)
        differing = {k for k in before if before[k] != after[k]}
        assert differing == {"notify_enabled"}
        data = _read_back(config_path)
        assert data["hcatBin"] == "hashcat-6.2.6"
        assert data["bandrelmaxruntime"] == 42

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_enabled(str(config_path), True)
        save_enabled(str(config_path), False)
        assert _read_back(config_path)["notify_enabled"] is False

    def test_writes_a_real_json_boolean(self, tmp_path: Path) -> None:
        """Not the string "1" the .env writer used: config.json is typed."""
        config_path = _seed_config(tmp_path)
        save_enabled(str(config_path), True)
        assert json.loads(config_path.read_text())["notify_enabled"] is True

    def test_output_is_indented_json(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_enabled(str(config_path), True)
        assert '\n  "notify_enabled": true' in config_path.read_text()

    def test_leaves_no_temp_file_behind(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_enabled(str(config_path), True)
        assert sorted(p.name for p in tmp_path.iterdir()) == ["config.json"]

    def test_tolerates_a_malformed_existing_config(self, tmp_path: Path) -> None:
        """A pre-existing bad config must not be what blocks a toggle; main.py
        has already reported it fatally by the time a menu action can run."""
        config_path = tmp_path / "config.json"
        config_path.write_text("{not valid json")
        save_enabled(str(config_path), True)
        assert json.loads(config_path.read_text()) == {"notify_enabled": True}

    def test_missing_config_is_an_error_and_creates_nothing(
        self, tmp_path: Path
    ) -> None:
        """Toggling a notification setting must never be what creates a config
        file -- notably not during a HATE_CRACK_SKIP_INIT run.
        notify.toggle_enabled() catches this OSError and warns."""
        config_path = tmp_path / "config.json"
        with pytest.raises(OSError):
            save_enabled(str(config_path), True)
        assert list(tmp_path.iterdir()) == []

    def test_does_not_create_or_touch_a_dotenv(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_enabled(str(config_path), True)
        assert not (tmp_path / ".env").exists()


class TestAddToAllowlist:
    def test_adds_to_empty_list(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        add_to_allowlist(str(config_path), "Brute Force")
        assert _read_back(config_path)["notify_attack_allowlist"] == ["Brute Force"]

    def test_idempotent(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        for _ in range(3):
            add_to_allowlist(str(config_path), "Brute Force")
        assert _read_back(config_path)["notify_attack_allowlist"] == ["Brute Force"]

    def test_preserves_other_entries(self, tmp_path: Path) -> None:
        config_path = _seed_config(
            tmp_path,
            hcatBin="hashcat-6.2.6",
            notify_attack_allowlist=["Existing"],
        )
        add_to_allowlist(str(config_path), "Brute Force")
        data = _read_back(config_path)
        assert data["hcatBin"] == "hashcat-6.2.6"
        assert data["notify_attack_allowlist"] == ["Existing", "Brute Force"]

    def test_stored_as_a_json_array(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        add_to_allowlist(str(config_path), "Brute Force")
        raw = json.loads(config_path.read_text())["notify_attack_allowlist"]
        assert raw == ["Brute Force"]

    def test_empty_attack_name_is_noop(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path, notify_attack_allowlist=["A"])
        before = config_path.read_bytes()
        add_to_allowlist(str(config_path), "")
        assert config_path.read_bytes() == before

    def test_name_with_a_comma_is_rejected(self, tmp_path: Path) -> None:
        """A JSON array would survive the comma, but the key's schema type is
        csv_list, which is how an os.environ override of
        NOTIFY_ATTACK_ALLOWLIST is parsed -- so a stored comma is one env var
        away from splitting into two entries that never match."""
        config_path = _seed_config(tmp_path, notify_attack_allowlist=["Existing"])
        before = config_path.read_bytes()

        with pytest.raises(AllowlistNameError):
            add_to_allowlist(str(config_path), "Brute Force, Dictionary")

        assert config_path.read_bytes() == before
        assert _read_back(config_path)["notify_attack_allowlist"] == ["Existing"]

    def test_comma_is_rejected_before_the_file_is_even_checked(
        self, tmp_path: Path
    ) -> None:
        """The name check precedes the "does config.json exist" check, so the
        diagnostic names the real problem rather than a missing file."""
        with pytest.raises(AllowlistNameError):
            add_to_allowlist(str(tmp_path / "config.json"), "a,b")
        assert list(tmp_path.iterdir()) == []

    def test_missing_config_is_an_error_and_creates_nothing(
        self, tmp_path: Path
    ) -> None:
        config_path = tmp_path / "config.json"
        with pytest.raises(OSError):
            add_to_allowlist(str(config_path), "Brute Force")
        assert list(tmp_path.iterdir()) == []


class TestSavePerCrackEnabled:
    def test_writes_notify_per_crack_enabled(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_per_crack_enabled(str(config_path), True)
        assert _read_back(config_path)["notify_per_crack_enabled"] is True

    def test_preserves_existing_keys(self, tmp_path: Path) -> None:
        config_path = _seed_config(
            tmp_path, hcatBin="hashcat-6.2.6", notify_enabled=True
        )
        save_per_crack_enabled(str(config_path), True)
        data = _read_back(config_path)
        assert data["hcatBin"] == "hashcat-6.2.6"
        assert data["notify_enabled"] is True
        assert data["notify_per_crack_enabled"] is True

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        config_path = _seed_config(tmp_path)
        save_per_crack_enabled(str(config_path), True)
        save_per_crack_enabled(str(config_path), False)
        assert _read_back(config_path)["notify_per_crack_enabled"] is False

    def test_missing_config_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            save_per_crack_enabled(str(tmp_path / "config.json"), True)
        assert list(tmp_path.iterdir()) == []
