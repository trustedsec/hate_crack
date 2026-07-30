"""Startup wiring of the `.env` loader into main.py, api.py and notify.

Covers the four file-resolution cases ``main._bootstrap_config_file()``
decides between, the process-environment override the live Hashview suite
depends on, and the two cross-module contracts (api.py's merged config,
notify's write-back) that used to be reimplemented per module.

``hate_crack.main`` is session-shared across the suite, so every global these
tests touch (``SKIP_INIT``, ``_resolve_config_destination``) is patched via
``monkeypatch``, never assigned.
"""

import json
import os
import stat
from pathlib import Path

import pytest

from hate_crack import api
from hate_crack import main as hc_main
from hate_crack import notify
from hate_crack import config_loader
from hate_crack.config_loader import load_config
from hate_crack.config_schema import CONFIG_SCHEMA
from hate_crack.config_writer import render_env, write_env

# Captured before conftest's _isolate_config_file_discovery fixture replaces it
# for the duration of each test.
_REAL_CANDIDATE_ROOTS = config_loader.candidate_roots


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _legacy_config(**overrides) -> dict:
    """A fully-populated legacy config.json body, like a real user's."""
    data = {entry.legacy: entry.default for entry in CONFIG_SCHEMA}
    data.update(overrides)
    return data


@pytest.fixture
def bootstrap(monkeypatch, tmp_path):
    """Run ``_bootstrap_config_file`` with ``tmp_path`` as the write target."""

    def _run(env_path, legacy_json_path, *, skip_init=False):
        monkeypatch.setattr(hc_main, "SKIP_INIT", skip_init)
        monkeypatch.setattr(
            hc_main, "_resolve_config_destination", lambda: str(tmp_path)
        )
        return hc_main._bootstrap_config_file(env_path, legacy_json_path)

    return _run


# ---------------------------------------------------------------------------
# Case 1 -- .env present
# ---------------------------------------------------------------------------


def test_case1_env_present_is_used_as_is(bootstrap, tmp_path, capsys):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"hcatBin": "hashcat-6.2.6"})
    before = env_path.read_bytes()

    assert bootstrap(str(env_path), None) == str(env_path)

    assert env_path.read_bytes() == before
    assert capsys.readouterr().out == ""


def test_case1_env_present_with_legacy_json_warns_naming_both(
    bootstrap, tmp_path, capsys
):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hcatBin": "hashcat"}))

    assert bootstrap(str(env_path), str(legacy_path)) == str(env_path)

    out = capsys.readouterr().out
    assert str(legacy_path) in out
    assert str(env_path) in out
    assert "deprecated" in out
    # The notice must describe what actually happens: config.json is still a
    # (lower-precedence) layer, so .env winning "key by key" is the truth.
    assert "key by key" in out


def test_case1_env_still_outranks_legacy_json_key_by_key(tmp_path):
    """The notice's claim, verified against the loader."""
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"hcatBin": "from-env"})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hcatBin": "from-json", "pipal_count": 42}))

    config = load_config(
        env_path=str(env_path), legacy_json_path=str(legacy_path), environ={}
    ).config

    assert config["hcatBin"] == "from-env"
    # A key the .env does not mention still comes from config.json... except
    # that write_env() emits every key, so this asserts the .env's own value.
    assert config["pipal_count"] == 10


# ---------------------------------------------------------------------------
# Case 2 -- migration from a legacy config.json
# ---------------------------------------------------------------------------


def test_case2_migrates_legacy_json_end_to_end(bootstrap, tmp_path, capsys):
    legacy_path = tmp_path / "config.json"
    legacy_body = _legacy_config(
        hcatBin="hashcat-6.2.6",
        pipal_count=42,
        notify_enabled=True,
        notify_attack_allowlist=["Brute Force", "Dictionary"],
        hcatPotfilePath="",
    )
    legacy_path.write_text(json.dumps(legacy_body, indent=2))
    legacy_bytes = legacy_path.read_bytes()

    result = bootstrap(None, str(legacy_path))

    env_path = tmp_path / ".env"
    assert result == str(env_path)
    assert env_path.is_file()
    assert _mode(env_path) == 0o600

    # The legacy file is byte-unchanged, so a downgrade stays possible.
    assert legacy_path.read_bytes() == legacy_bytes

    out = capsys.readouterr().out
    assert str(legacy_path) in out
    assert str(env_path) in out
    assert "left unchanged" in out

    # And the migrated config is the same config the legacy file produced.
    from_legacy = load_config(legacy_json_path=str(legacy_path), environ={}).config
    after = load_config(
        env_path=str(env_path), legacy_json_path=str(legacy_path), environ={}
    ).config
    assert after == from_legacy
    # Including the deliberate "no potfile path" sentinel, which is the value
    # a naive round-trip loses (an empty .env value must stay explicit).
    assert after["hcatPotfilePath"] == ""


def test_case2_reports_unrecognized_legacy_keys(bootstrap, tmp_path, capsys):
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hcatBin": "hashcat", "retiredKey": "x"}))

    bootstrap(None, str(legacy_path))

    out = capsys.readouterr().out
    assert "retiredKey" in out


def test_case2_malformed_legacy_json_defers_to_the_loader(bootstrap, tmp_path):
    """A config.json we cannot parse must not be migrated, and must not be
    reported here -- load_config_or_exit() owns that diagnostic."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text("{not valid json")

    assert bootstrap(None, str(legacy_path)) is None
    assert not (tmp_path / ".env").exists()


# ---------------------------------------------------------------------------
# Case 3 -- nothing on disk
# ---------------------------------------------------------------------------


def test_case3_writes_fresh_env_from_schema_defaults(bootstrap, tmp_path, capsys):
    result = bootstrap(None, None)

    env_path = tmp_path / ".env"
    assert result == str(env_path)
    assert env_path.read_text() == render_env({})
    assert _mode(env_path) == 0o600
    out = capsys.readouterr().out
    assert "Initializing .env" in out
    assert str(env_path) in out

    config = load_config(env_path=str(env_path), environ={}).config
    assert config == load_config(environ={}).config


# ---------------------------------------------------------------------------
# Case 4 -- SKIP_INIT writes nothing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "with_legacy",
    [False, True],
    ids=["no-config-at-all", "legacy-json-present"],
)
def test_case4_skip_init_writes_nothing(bootstrap, tmp_path, with_legacy, capsys):
    dest = tmp_path / "dest"
    dest.mkdir()
    legacy_path = None
    if with_legacy:
        legacy_path = tmp_path / "config.json"
        legacy_path.write_text(json.dumps({"hcatBin": "hashcat"}))

    result = bootstrap(None, str(legacy_path) if legacy_path else None, skip_init=True)

    assert result is None
    assert list(dest.iterdir()) == []
    assert not (tmp_path / ".env").exists()
    assert capsys.readouterr().out == ""


def test_case4_skip_init_still_loads_what_exists(bootstrap, tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"hcatBin": "hashcat-6.2.6"})

    assert bootstrap(str(env_path), None, skip_init=True) == str(env_path)
    assert load_config(env_path=str(env_path), environ={}).config["hcatBin"] == (
        "hashcat-6.2.6"
    )


# ---------------------------------------------------------------------------
# The process environment still outranks .env
# ---------------------------------------------------------------------------


def test_environ_outranks_env_file_for_hashview(tmp_path):
    """What HASHVIEW_TEST_LOCAL=1 depends on: exported HASHVIEW_* env vars
    point the CLI at a local docker stack without editing the persisted
    config. main.py reads these straight off config_parser now, so the
    override has to happen inside the loader."""
    env_path = tmp_path / ".env"
    write_env(
        str(env_path),
        {
            "hashview_url": "http://from-dotenv:8443",
            "hashview_api_key": "from-dotenv-placeholder",
        },
    )

    config = load_config(
        env_path=str(env_path),
        environ={
            "HASHVIEW_URL": "http://from-environ:8443",
            "HASHVIEW_API_KEY": "from-environ-placeholder",
        },
    ).config

    assert config["hashview_url"] == "http://from-environ:8443"
    assert config["hashview_api_key"] == "from-environ-placeholder"


def test_empty_environ_value_falls_through_to_env_file(tmp_path):
    """An accidentally-empty exported shell variable must not blank the
    configured value -- this is the documented environ-layer asymmetry."""
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"hashview_url": "http://from-dotenv:8443"})

    config = load_config(env_path=str(env_path), environ={"HASHVIEW_URL": ""}).config

    assert config["hashview_url"] == "http://from-dotenv:8443"


# ---------------------------------------------------------------------------
# api.py agrees with the loader (#153 regression guard)
# ---------------------------------------------------------------------------


def test_api_merged_config_matches_loader(monkeypatch, tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"hcatWordlists": "./from-dotenv"})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(
        json.dumps({"hcatWordlists": "./from-json", "rules_directory": "./from-json"})
    )

    monkeypatch.setattr(api, "_resolve_env_path", lambda: str(env_path))
    monkeypatch.setattr(api, "_resolve_config_path", lambda: str(legacy_path))

    assert (
        api._load_merged_config()
        == load_config(env_path=str(env_path), legacy_json_path=str(legacy_path)).config
    )


def test_api_merged_config_degrades_to_defaults_on_bad_file(monkeypatch, tmp_path):
    """main.py exits on a malformed config; api.py's helpers are called from
    inside menu actions and must not take the process down."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text("{not valid json")
    monkeypatch.setattr(api, "_resolve_env_path", lambda: None)
    monkeypatch.setattr(api, "_resolve_config_path", lambda: str(legacy_path))

    merged = api._load_merged_config()

    assert merged == {entry.legacy: entry.default for entry in CONFIG_SCHEMA}


def test_api_and_main_share_one_candidate_root_order(monkeypatch):
    # Opt out of the suite-wide discovery isolation: this test is about the
    # real search order, and the autouse fixture empties it.
    monkeypatch.setattr(config_loader, "candidate_roots", _REAL_CANDIDATE_ROOTS)

    assert hc_main._candidate_roots() == config_loader.candidate_roots()
    package_dir = os.path.dirname(os.path.realpath(config_loader.__file__))
    assert config_loader.candidate_roots() == [
        os.path.dirname(package_dir),
        package_dir,
        os.path.join(os.path.expanduser("~"), ".hate_crack"),
    ]


# ---------------------------------------------------------------------------
# notify write-back round-trips through the .env main.py resolved
# ---------------------------------------------------------------------------


def test_notify_toggles_round_trip_through_the_env_file(tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"notify_enabled": False})
    before = env_path.read_text()

    config = load_config(env_path=str(env_path), environ={}).config
    notify.init(str(env_path), config)
    try:
        assert notify.toggle_enabled() is True
        assert notify.toggle_per_crack_enabled() is True
    finally:
        notify.clear_state_for_tests()

    reloaded = load_config(env_path=str(env_path), environ={}).config
    assert reloaded["notify_enabled"] is True
    assert reloaded["notify_per_crack_enabled"] is True
    assert _mode(env_path) == 0o600

    # Comments and every unrelated key survived the in-place edits.
    after = env_path.read_text()
    assert after.count("#") == before.count("#")
    unrelated = {k: v for k, v in reloaded.items() if not k.startswith("notify_")}
    assert unrelated == {
        k: v
        for k, v in load_config(environ={}).config.items()
        if not k.startswith("notify_")
    }


def test_notify_toggle_without_a_config_file_stays_in_memory(tmp_path, caplog):
    """init() gets None when SKIP_INIT found nothing to load; the toggle must
    still work and must not create a .env behind the user's back."""
    notify.init(None, {})
    try:
        assert notify.toggle_enabled() is True
    finally:
        notify.clear_state_for_tests()
    assert list(tmp_path.iterdir()) == []
