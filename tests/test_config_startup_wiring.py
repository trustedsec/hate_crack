"""Startup wiring of the split-home loader into main.py, api.py and notify.

Covers the file-creation cases ``main._bootstrap_config_files()`` decides
between, the process-environment override the live Hashview suite depends on,
and the two cross-module contracts (api.py's merged config, notify's
``config.json`` write-back) that used to be reimplemented per module.

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
from hate_crack.config_schema import CONFIG_SCHEMA, ENV_KEYS, JSON_KEYS
from hate_crack.config_writer import render_env, write_env

# Captured before conftest's _isolate_config_file_discovery fixture replaces it
# for the duration of each test.
_REAL_CANDIDATE_ROOTS = config_loader.candidate_roots


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _pre_split_config(**overrides) -> dict:
    """A fully-populated pre-split config.json body, like a real user's:
    all 47 keys, the twelve integration ones included."""
    data = {entry.legacy: entry.default for entry in CONFIG_SCHEMA}
    data.update(overrides)
    return data


def _post_split_config(**overrides) -> dict:
    """A config.json in the new shape: the 35 json-homed keys only."""
    data = {entry.legacy: entry.default for entry in JSON_KEYS}
    data.update(overrides)
    return data


@pytest.fixture
def bootstrap(monkeypatch, tmp_path):
    """Run ``_bootstrap_config_files`` with ``tmp_path`` as the write target."""

    def _run(env_path, legacy_json_path, *, skip_init=False):
        monkeypatch.setattr(hc_main, "SKIP_INIT", skip_init)
        monkeypatch.setattr(
            hc_main, "_resolve_config_destination", lambda: str(tmp_path)
        )
        return hc_main._bootstrap_config_files(env_path, legacy_json_path)

    return _run


# ---------------------------------------------------------------------------
# Case 1 -- config.json holds integration keys, .env absent -> migrate
# ---------------------------------------------------------------------------


def test_case1_migrates_integration_keys_and_leaves_config_json_alone(
    bootstrap, tmp_path, capsys
):
    legacy_path = tmp_path / "config.json"
    legacy_body = _pre_split_config(
        hcatBin="hashcat-6.2.6",
        ollamaModel="synthetic-model",
        hashmob_api_key="synthetic-sentinel",
        notify_enabled=True,
        hcatPotfilePath="",
    )
    legacy_path.write_text(json.dumps(legacy_body, indent=2))
    legacy_bytes = legacy_path.read_bytes()

    env_path_result, json_path_result = bootstrap(None, str(legacy_path))

    env_path = tmp_path / ".env"
    assert env_path_result == str(env_path)
    assert json_path_result == str(legacy_path)
    assert env_path.is_file()
    assert _mode(env_path) == 0o600

    # config.json is byte-unchanged: it is still the home of the other 35.
    assert legacy_path.read_bytes() == legacy_bytes

    out = capsys.readouterr().out
    assert str(legacy_path) in out
    assert str(env_path) in out
    assert "ollamaModel" in out
    assert "hashmob_api_key" in out
    assert "Delete them from" in out
    # Never the values.
    assert "synthetic-sentinel" not in out
    assert "synthetic-model" not in out

    # And loading the resulting pair reproduces what the old file produced.
    config = load_config(
        env_path=str(env_path), legacy_json_path=str(legacy_path), environ={}
    ).config
    assert config["ollamaModel"] == "synthetic-model"
    assert config["hashmob_api_key"] == "synthetic-sentinel"
    assert config["hcatBin"] == "hashcat-6.2.6"
    assert config["notify_enabled"] is True
    assert config["hcatPotfilePath"] == ""


def test_case1_migration_defers_a_malformed_config_json_to_the_loader(
    bootstrap, tmp_path
):
    """A config.json we cannot parse holds no discoverable integration keys, so
    it is not migrated -- and it is not diagnosed here either;
    load_config_or_exit() owns that message."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text("{not valid json")

    env_path_result, _ = bootstrap(None, str(legacy_path))

    # A .env still gets created from defaults; what must not happen is a
    # second, worse diagnostic or a migration from an unparseable file.
    assert env_path_result == str(tmp_path / ".env")
    assert (tmp_path / ".env").read_text() == render_env({})


# ---------------------------------------------------------------------------
# Case 2 -- config.json present in the new shape, .env absent
# ---------------------------------------------------------------------------


def test_case2_writes_a_default_env_when_there_is_nothing_to_migrate(
    bootstrap, tmp_path, capsys
):
    """Decision: write the `.env` from schema defaults rather than nothing.

    Without it, a user who wants to set HASHMOB_API_KEY has to know both that
    `.env` is where it goes and that they must create it themselves; and the
    "both files exist" post-condition then matches the from-scratch case.
    None of the twelve defaults is a secret, so writing them costs nothing.
    """
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_post_split_config()))

    env_path_result, _ = bootstrap(None, str(legacy_path))

    env_path = tmp_path / ".env"
    assert env_path_result == str(env_path)
    assert env_path.read_text() == render_env({})
    assert _mode(env_path) == 0o600
    out = capsys.readouterr().out
    assert "Initializing .env" in out
    # Nothing was migrated, so no cleanup instruction is printed.
    assert "Delete them from" not in out


# ---------------------------------------------------------------------------
# Case 3 -- both present: nothing is written
# ---------------------------------------------------------------------------


def test_case3_both_present_writes_nothing(bootstrap, tmp_path, capsys):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"ollamaModel": "synthetic-model"})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_post_split_config(hcatBin="hashcat-6.2.6")))
    env_before = env_path.read_bytes()
    json_before = legacy_path.read_bytes()

    assert bootstrap(str(env_path), str(legacy_path)) == (
        str(env_path),
        str(legacy_path),
    )

    assert env_path.read_bytes() == env_before
    assert legacy_path.read_bytes() == json_before
    assert capsys.readouterr().out == ""


def test_case3_misplaced_keys_are_the_loaders_business_not_the_bootstraps(
    bootstrap, tmp_path, capsys
):
    """No deprecation notice, no "config.json is on its way out": a leftover
    integration key produces a loader warning naming the file it belongs in,
    on every run, and the bootstrap says nothing at all."""
    env_path = tmp_path / ".env"
    write_env(str(env_path), {})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hashmob_api_key": "synthetic-sentinel"}))

    bootstrap(str(env_path), str(legacy_path))
    assert capsys.readouterr().out == ""

    warnings = load_config(
        env_path=str(env_path), legacy_json_path=str(legacy_path), environ={}
    ).warnings
    assert any("hashmob_api_key" in w and ".env" in w for w in warnings)


# ---------------------------------------------------------------------------
# Case 4 -- neither present: create both
# ---------------------------------------------------------------------------


def test_case4_creates_both_files_from_defaults(bootstrap, tmp_path, capsys):
    env_path_result, json_path_result = bootstrap(None, None)

    env_path = tmp_path / ".env"
    json_path = tmp_path / "config.json"
    assert env_path_result == str(env_path)
    assert json_path_result == str(json_path)

    assert env_path.read_text() == render_env({})
    assert _mode(env_path) == 0o600

    # config.json comes from the shipped example, exactly as before the split.
    written = json.loads(json_path.read_text())
    assert set(written) == {entry.legacy: None for entry in JSON_KEYS}.keys()

    out = capsys.readouterr().out
    assert "Initializing config.json from config.json.example" in out
    assert "Initializing .env" in out

    # The pair loads to exactly the schema defaults.
    config = load_config(
        env_path=str(env_path), legacy_json_path=str(json_path), environ={}
    ).config
    assert config == load_config(environ={}).config


# ---------------------------------------------------------------------------
# Case 5 -- SKIP_INIT writes nothing, ever
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "with_legacy",
    [False, True],
    ids=["no-config-at-all", "config-json-present"],
)
def test_case5_skip_init_writes_nothing(bootstrap, tmp_path, with_legacy, capsys):
    legacy_path = None
    if with_legacy:
        legacy_path = tmp_path / "config.json"
        legacy_path.write_text(json.dumps(_pre_split_config()))
    before = sorted(p.name for p in tmp_path.iterdir())

    result = bootstrap(None, str(legacy_path) if legacy_path else None, skip_init=True)

    assert result == (None, str(legacy_path) if legacy_path else None)
    assert sorted(p.name for p in tmp_path.iterdir()) == before
    assert not (tmp_path / ".env").exists()
    assert capsys.readouterr().out == ""


def test_case5_skip_init_still_loads_what_exists(bootstrap, tmp_path):
    env_path = tmp_path / ".env"
    write_env(str(env_path), {"ollamaModel": "synthetic-model"})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hcatBin": "hashcat-6.2.6"}))

    assert bootstrap(str(env_path), str(legacy_path), skip_init=True) == (
        str(env_path),
        str(legacy_path),
    )
    config = load_config(
        env_path=str(env_path), legacy_json_path=str(legacy_path), environ={}
    ).config
    assert config["hcatBin"] == "hashcat-6.2.6"
    assert config["ollamaModel"] == "synthetic-model"


# ---------------------------------------------------------------------------
# No deprecation story survives anywhere
# ---------------------------------------------------------------------------


def test_no_deprecation_wording_survives_in_the_package():
    """config.json is first-class forever. Any "deprecated" / "no longer read"
    / removal-timeline wording is now factually wrong, and this asserts it
    cannot creep back in a docstring or a print()."""
    package_dir = Path(hc_main.__file__).resolve().parent
    forbidden = ("deprecat", "no longer read", "no longer needed", "two-release")
    offenders = []
    for path in sorted(package_dir.rglob("*.py")):
        text = path.read_text().lower()
        for phrase in forbidden:
            if phrase in text:
                offenders.append(f"{path.name}: {phrase!r}")
    assert offenders == [], offenders


# ---------------------------------------------------------------------------
# The process environment still outranks both home files
# ---------------------------------------------------------------------------


def test_environ_outranks_env_file_for_hashview(tmp_path):
    """What HASHVIEW_TEST_LOCAL=1 depends on: exported HASHVIEW_* env vars
    point the CLI at a local docker stack without editing the persisted
    config. main.py reads these straight off config_parser, so the override
    has to happen inside the loader."""
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


def test_environ_outranks_config_json_too(tmp_path):
    """The environ exemption is not Hashview-specific: it applies to a
    json-homed key as well, which is what makes it an override rather than a
    third home."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hcatTuning": "-w 3"}))

    config = load_config(
        legacy_json_path=str(legacy_path), environ={"HCAT_TUNING": "-w 4"}
    ).config

    assert config["hcatTuning"] == "-w 4"


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
    write_env(str(env_path), {"ollamaModel": "synthetic-model"})
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


def test_no_api_helper_reads_a_config_file_on_its_own(monkeypatch, tmp_path):
    """Global constraint: one loader, no second implementation.

    Every api.py path that wants a config value must go through
    ``_load_merged_config()``. Two of them (``get_hashmob_api_key`` and the
    torrent-header lookup that now calls it) each kept a private
    two-directory config.json walk, which is #153 in a third and fourth
    place and which the split turned into a real regression: hashmob_api_key
    is `.env`-homed now, so a private config.json walk reads a value the
    loader deliberately ignores.
    """
    monkeypatch.setattr(
        api,
        "_load_merged_config",
        lambda: {"hashmob_api_key": "placeholder", "hcatTuning": "-w 3"},
    )

    assert api.get_hashmob_api_key() == "placeholder"
    assert api.get_hcat_tuning_args() == ["-w", "3"]

    # And nothing in api.py resolves config paths by hand any more.
    source = Path(api.__file__).read_text()
    assert 'os.path.join(pkg_dir, "config.json")' not in source
    assert source.count('"config.json"') == 0


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
# notify write-back round-trips through config.json, not .env
# ---------------------------------------------------------------------------


def test_notify_toggles_round_trip_through_config_json(tmp_path):
    """The toggles are home="json", so they persist to config.json -- and the
    .env, which holds the Pushover credentials, is not touched at all."""
    json_path = tmp_path / "config.json"
    json_path.write_text(json.dumps(_post_split_config(notify_enabled=False), indent=2))
    env_path = tmp_path / ".env"
    write_env(str(env_path), {})
    env_before = env_path.read_bytes()

    config = load_config(
        env_path=str(env_path), legacy_json_path=str(json_path), environ={}
    ).config
    notify.init(str(json_path), config)
    try:
        assert notify.toggle_enabled() is True
        assert notify.toggle_per_crack_enabled() is True
    finally:
        notify.clear_state_for_tests()

    reloaded = load_config(
        env_path=str(env_path), legacy_json_path=str(json_path), environ={}
    ).config
    assert reloaded["notify_enabled"] is True
    assert reloaded["notify_per_crack_enabled"] is True

    # The .env was neither created nor modified by a toggle.
    assert env_path.read_bytes() == env_before

    # Every unrelated key survived the read-modify-write.
    unrelated = {k: v for k, v in reloaded.items() if not k.startswith("notify_")}
    assert unrelated == {
        k: v
        for k, v in load_config(env_path=str(env_path), environ={}).config.items()
        if not k.startswith("notify_")
    }


def test_notify_toggle_does_not_create_an_env_file(tmp_path):
    """Regression guard for the reversal: the write-back used to go through
    dotenv.set_key(), so a toggle against a directory holding only a
    config.json must not resurrect a .env."""
    json_path = tmp_path / "config.json"
    json_path.write_text(json.dumps(_post_split_config()))

    notify.init(str(json_path), load_config(legacy_json_path=str(json_path)).config)
    try:
        assert notify.toggle_enabled() is True
    finally:
        notify.clear_state_for_tests()

    assert sorted(p.name for p in tmp_path.iterdir()) == ["config.json"]


def test_notify_write_back_does_not_use_dotenv_at_all(tmp_path):
    """The import is gone, not merely unused: settings.py writes JSON now."""
    from hate_crack.notify import settings as notify_settings

    source = Path(notify_settings.__file__).read_text()
    assert "set_key" not in source
    assert "from dotenv" not in source


def test_notify_toggle_without_a_config_file_stays_in_memory(tmp_path, caplog):
    """init() gets None when SKIP_INIT found nothing to load; the toggle must
    still work and must not create a config file behind the user's back."""
    notify.init(None, {})
    try:
        assert notify.toggle_enabled() is True
    finally:
        notify.clear_state_for_tests()
    assert list(tmp_path.iterdir()) == []


def test_notify_settings_keys_are_all_json_homed(tmp_path):
    """Why the write-back target is config.json: if one of these ever moved to
    `.env`, a single write target would silently stop being correct."""
    from hate_crack.config_schema import BY_LEGACY

    for key in (
        "notify_enabled",
        "notify_per_crack_enabled",
        "notify_attack_allowlist",
    ):
        assert BY_LEGACY[key].home == "json"
    # And the credentials, which nothing writes from the menu, are .env-homed.
    env_homed = {entry.legacy for entry in ENV_KEYS}
    assert {"notify_pushover_token", "notify_pushover_user"} <= env_homed
