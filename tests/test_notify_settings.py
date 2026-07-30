"""Unit tests for hate_crack.notify.settings."""

import stat
from pathlib import Path

import pytest

from hate_crack.config_loader import load_config
from hate_crack.config_writer import write_env
from hate_crack.notify.settings import (
    AllowlistNameError,
    NotifySettings,
    add_to_allowlist,
    load_settings,
    save_enabled,
    save_per_crack_enabled,
)


def _seed_env(tmp_path: Path, **overrides) -> Path:
    """Write a full `.env` (mode 0600) and return its path."""
    env_path = tmp_path / ".env"
    write_env(str(env_path), overrides)
    return env_path


def _read_back(env_path: Path) -> dict:
    """Reload the persisted `.env` through the shared loader."""
    return load_config(env_path=str(env_path), environ={}).config


def _mode(env_path: Path) -> int:
    return stat.S_IMODE(env_path.stat().st_mode)


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
        env_path = _seed_env(tmp_path)
        save_enabled(str(env_path), True)
        assert _read_back(env_path)["notify_enabled"] is True

    def test_preserves_existing_keys_and_comments(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path, hcatBin="hashcat-6.2.6", pipal_count=42)
        before = env_path.read_text()
        save_enabled(str(env_path), True)
        after = env_path.read_text()

        data = _read_back(env_path)
        assert data["hcatBin"] == "hashcat-6.2.6"
        assert data["pipal_count"] == 42
        assert data["notify_enabled"] is True
        # set_key() edits in place: the generated comment headers and every
        # unrelated line survive untouched. Exactly one line differs.
        differing = [
            (a, b) for a, b in zip(before.splitlines(), after.splitlines()) if a != b
        ]
        assert len(differing) == 1
        assert differing[0][0].startswith("NOTIFY_ENABLED=")
        assert before.count("# hate_crack configuration.") == 1
        assert after.count("# hate_crack configuration.") == 1

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        save_enabled(str(env_path), True)
        save_enabled(str(env_path), False)
        assert _read_back(env_path)["notify_enabled"] is False

    def test_booleans_are_written_as_one_and_zero(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        save_enabled(str(env_path), True)
        assert "NOTIFY_ENABLED=1" in env_path.read_text().splitlines()
        save_enabled(str(env_path), False)
        assert "NOTIFY_ENABLED=0" in env_path.read_text().splitlines()

    def test_mode_stays_0600(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        assert _mode(env_path) == 0o600
        save_enabled(str(env_path), True)
        assert _mode(env_path) == 0o600

    def test_missing_env_is_an_error_and_creates_nothing(self, tmp_path: Path) -> None:
        """Toggling a notification setting must never be what creates a
        config file -- notably not during a HATE_CRACK_SKIP_INIT run.
        notify.toggle_enabled() catches this OSError and warns."""
        env_path = tmp_path / ".env"
        with pytest.raises(OSError):
            save_enabled(str(env_path), True)
        assert list(tmp_path.iterdir()) == []


class TestAddToAllowlist:
    def test_adds_to_empty_list(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        add_to_allowlist(str(env_path), "Brute Force")
        assert _read_back(env_path)["notify_attack_allowlist"] == ["Brute Force"]

    def test_idempotent(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        add_to_allowlist(str(env_path), "Brute Force")
        add_to_allowlist(str(env_path), "Brute Force")
        add_to_allowlist(str(env_path), "Brute Force")
        assert _read_back(env_path)["notify_attack_allowlist"] == ["Brute Force"]

    def test_preserves_other_entries(self, tmp_path: Path) -> None:
        env_path = _seed_env(
            tmp_path,
            hcatBin="hashcat-6.2.6",
            notify_attack_allowlist=["Existing"],
        )
        add_to_allowlist(str(env_path), "Brute Force")
        data = _read_back(env_path)
        assert data["hcatBin"] == "hashcat-6.2.6"
        assert data["notify_attack_allowlist"] == ["Existing", "Brute Force"]

    def test_empty_attack_name_is_noop(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path, notify_attack_allowlist=["A"])
        add_to_allowlist(str(env_path), "")
        assert _read_back(env_path)["notify_attack_allowlist"] == ["A"]

    def test_mode_stays_0600(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        add_to_allowlist(str(env_path), "Brute Force")
        assert _mode(env_path) == 0o600

    def test_name_with_a_comma_is_rejected(self, tmp_path: Path) -> None:
        """NOTIFY_ATTACK_ALLOWLIST is a csv_list: a comma in a name would be
        written as one element and read back as two, silently, surfacing much
        later as an allowlist entry that never matches. No attack name contains
        one today, which is why this has to fail loudly at the write."""
        env_path = _seed_env(tmp_path, notify_attack_allowlist=["Existing"])
        before = env_path.read_text()

        with pytest.raises(AllowlistNameError):
            add_to_allowlist(str(env_path), "Brute Force, Dictionary")

        # And the file is untouched -- no partial write.
        assert env_path.read_text() == before
        assert _read_back(env_path)["notify_attack_allowlist"] == ["Existing"]

    def test_comma_is_rejected_before_the_file_is_even_checked(
        self, tmp_path: Path
    ) -> None:
        """The name check precedes the "does the .env exist" check, so the
        diagnostic names the real problem rather than a missing file."""
        with pytest.raises(AllowlistNameError):
            add_to_allowlist(str(tmp_path / ".env"), "a,b")
        assert list(tmp_path.iterdir()) == []

    def test_missing_env_is_an_error_and_creates_nothing(self, tmp_path: Path) -> None:
        env_path = tmp_path / ".env"
        with pytest.raises(OSError):
            add_to_allowlist(str(env_path), "Brute Force")
        assert list(tmp_path.iterdir()) == []


class TestSavePerCrackEnabled:
    def test_writes_notify_per_crack_enabled(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        save_per_crack_enabled(str(env_path), True)
        assert _read_back(env_path)["notify_per_crack_enabled"] is True

    def test_preserves_existing_keys(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path, hcatBin="hashcat-6.2.6", notify_enabled=True)
        save_per_crack_enabled(str(env_path), True)
        data = _read_back(env_path)
        assert data["hcatBin"] == "hashcat-6.2.6"
        assert data["notify_enabled"] is True
        assert data["notify_per_crack_enabled"] is True

    def test_toggles_back_and_forth(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        save_per_crack_enabled(str(env_path), True)
        save_per_crack_enabled(str(env_path), False)
        assert _read_back(env_path)["notify_per_crack_enabled"] is False

    def test_mode_stays_0600(self, tmp_path: Path) -> None:
        env_path = _seed_env(tmp_path)
        save_per_crack_enabled(str(env_path), True)
        assert _mode(env_path) == 0o600
