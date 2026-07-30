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
import logging
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


def test_case1_migrates_integration_keys_and_prunes_config_json(
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

    # The keys that moved are gone from config.json; the other 35 stay, and the
    # pre-migration file is recoverable.
    remaining = json.loads(legacy_path.read_text())
    assert not ({entry.legacy for entry in ENV_KEYS} & set(remaining))
    assert {entry.legacy for entry in JSON_KEYS} <= set(remaining)
    assert (tmp_path / "config.json.pre-split.bak").read_bytes() == legacy_bytes

    out = capsys.readouterr().out
    assert str(legacy_path) in out
    assert str(env_path) in out
    assert "ollamaModel" in out
    assert "hashmob_api_key" in out
    assert "Removed them from" in out
    # The bootstrap no longer prints its own "Config source/destination" block:
    # that is _print_config_sources()'s job now (#227).
    assert "Config source:" not in out
    assert "Config destination:" not in out
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


@pytest.mark.parametrize(
    "make_unusable",
    [
        lambda p: p.write_text("{not valid json"),
        lambda p: (p.write_text("{}"), p.chmod(0o000)),
    ],
    ids=["malformed-json", "unreadable"],
)
def test_unusable_config_json_writes_nothing_at_all(
    bootstrap, tmp_path, capsys, make_unusable
):
    """A config.json that cannot be read or parsed must not produce a stray
    .env on the way to the loader's fatal exit.

    Startup is about to exit(1) with the file-shaped diagnostic that names
    permissions and dangling symlinks, so a .env written here is a file left
    behind by a run that never got anywhere -- and because the write target is
    _resolve_config_destination() rather than the directory the bad file was
    found in, it lands somewhere the user is not even looking (typically
    ~/.hate_crack/.env while they are staring at a config.json in the repo,
    which is exactly how this went unnoticed).

    Nothing is diagnosed here either: load_config_or_exit() owns that message.
    """
    legacy_path = tmp_path / "config.json"
    make_unusable(legacy_path)
    try:
        env_path_result, json_path_result = bootstrap(None, str(legacy_path))

        assert env_path_result is None
        assert json_path_result == str(legacy_path)
        assert not (tmp_path / ".env").exists()
        assert sorted(p.name for p in tmp_path.iterdir()) == ["config.json"]
        assert capsys.readouterr().out == ""
    finally:
        legacy_path.chmod(0o600)


def test_unusable_config_json_still_exits_fatally_from_the_loader(tmp_path, capsys):
    """The other half of the contract above: writing nothing must not mean
    swallowing the problem. The loader is still the one that reports it."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text("{not valid json")

    with pytest.raises(SystemExit) as exc:
        config_loader.load_config_or_exit(
            env_path=None, legacy_json_path=str(legacy_path), environ={}
        )

    assert exc.value.code == 1
    assert "invalid JSON" in capsys.readouterr().out


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
    # Silent: the file it created is named once, by _print_config_sources (#227).
    # Nothing was migrated, so there is no cleanup instruction either.
    assert capsys.readouterr().out == ""
    assert hc_main._config_bootstrap_detail["env"] == "from built-in defaults"


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

    # Both files created, nothing printed here: the two _print_config_sources
    # lines carry the paths and their provenance (#227).
    assert capsys.readouterr().out == ""
    assert hc_main._config_bootstrap_detail["json"] == "from config.json.example"
    assert hc_main._config_bootstrap_detail["env"] == "from built-in defaults"

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
# Warnings reach the user exactly once
# ---------------------------------------------------------------------------


def _startup_warning_output(tmp_path, capsys, *, env_body=None, json_body=None):
    """Load a config pair and emit its warnings the way ``main.py`` does.

    Returns ``(warnings, combined_output)``. ``main.py``'s reporting block is
    module-level code that cannot be called directly, so it is reproduced here;
    ``test_main_py_is_the_channel_that_prints_the_warnings`` pins that the real
    one still matches.
    """
    env_path = json_path = None
    if env_body is not None:
        env_path = tmp_path / ".env"
        env_path.write_text(env_body)
        env_path = str(env_path)
    if json_body is not None:
        json_path = tmp_path / "config.json"
        json_path.write_text(json.dumps(json_body))
        json_path = str(json_path)

    result = config_loader.load_config_or_exit(
        env_path=env_path, legacy_json_path=json_path, environ={}
    )
    for warning in result.warnings:
        print(f"[!] {warning}")

    captured = capsys.readouterr()
    return result.warnings, captured.out + captured.err


def _assert_reported_once(combined, warnings, *must_name):
    """Every warning appears exactly once AND at least once, naming each key.

    The "exactly once" half alone passes trivially when a warning appears zero
    times, which is precisely how a dropped warning hides: the count is 0 == 0
    for a list that is itself empty. So this asserts the key names are present
    in the output first, then that nothing is doubled.
    """
    for name in must_name:
        assert any(name in w for w in warnings), (
            f"no warning mentions {name!r}; got {warnings}"
        )
        assert combined.count(name) >= 1, f"{name!r} never reached the user"
    assert warnings, "expected warnings, got none"
    for warning in warnings:
        assert combined.count(warning) == 1, (
            f"reported {combined.count(warning)}x: {warning}"
        )


def test_misplaced_config_json_key_warns_exactly_once(tmp_path, capsys):
    """Case 1: an integration key left in config.json."""
    warnings, combined = _startup_warning_output(
        tmp_path,
        capsys,
        json_body={"hcatBin": "hashcat", "hashmob_api_key": "placeholder"},
    )
    assert len(warnings) == 1
    _assert_reported_once(combined, warnings, "hashmob_api_key", "HASHMOB_API_KEY")


def test_misplaced_env_key_warns_exactly_once(tmp_path, capsys):
    """Case 2: a setting written into `.env`.

    This is the case that catches a dropped `.env`-side warning -- the most
    likely user mistake given the design just changed, and the exact thing the
    warnings exist to catch.
    """
    warnings, combined = _startup_warning_output(
        tmp_path, capsys, env_body="HCAT_TUNING=-w 1\n"
    )
    assert len(warnings) == 1
    _assert_reported_once(combined, warnings, "HCAT_TUNING", "hcatTuning")


def test_both_sides_misplaced_each_warn_exactly_once(tmp_path, capsys):
    """Case 3: both files hold a key belonging in the other, at once.

    Both lists feed one merged report, so neither may overwrite or filter the
    other.
    """
    warnings, combined = _startup_warning_output(
        tmp_path,
        capsys,
        env_body="HCAT_TUNING=-w 1\n",
        json_body={
            "hashmob_api_key": "placeholder",
            "pipal_count": 3,
            "ollamaModel": "synthetic-model",
        },
    )
    assert len(warnings) == 4
    _assert_reported_once(
        combined,
        warnings,
        "HCAT_TUNING",
        "hashmob_api_key",
        "pipal_count",
        "ollamaModel",
    )


def test_unrecognized_env_key_warns_exactly_once(tmp_path, capsys):
    """Case 4: a key in `.env` that the schema does not know at all."""
    warnings, combined = _startup_warning_output(
        tmp_path, capsys, env_body="BOGUS_KEY=x\n"
    )
    assert len(warnings) == 1
    _assert_reported_once(combined, warnings, "BOGUS_KEY")


def test_wrong_typed_config_json_value_warns_exactly_once(tmp_path, capsys):
    """The third warning source, for completeness: a badly-typed JSON value."""
    warnings, combined = _startup_warning_output(
        tmp_path, capsys, json_body={"bandrelmaxruntime": "not-an-int"}
    )
    assert len(warnings) == 1
    _assert_reported_once(combined, warnings, "bandrelmaxruntime")


def test_a_clean_pair_of_files_produces_no_warnings(tmp_path, capsys):
    """Case 5: correctly-placed keys are silent -- the warnings must not be so
    eager that users learn to ignore them."""
    write_env(str(tmp_path / ".env"), {"ollamaModel": "synthetic-model"})
    warnings, combined = _startup_warning_output(
        tmp_path,
        capsys,
        env_body=(tmp_path / ".env").read_text(),
        json_body=_post_split_config(hcatBin="hashcat-6.2.6"),
    )
    assert warnings == []
    assert combined == ""


def test_every_warning_reaches_the_user_exactly_once_at_scale(tmp_path, capsys):
    """A full pre-split config.json: one misplaced key, one line, each.

    Before the channel was consolidated this printed each warning twice --
    once from load_config_or_exit()'s logger, once from main.py's print of the
    same list -- which reads like a bug in the very messages that are the whole
    user-facing story for the split.

    Counted off ENV_KEYS rather than a literal so adding an integration key
    does not turn a real doubling regression into an off-by-one edit here.
    """
    warnings, combined = _startup_warning_output(
        tmp_path, capsys, json_body=_pre_split_config()
    )
    assert len(warnings) == len(ENV_KEYS)
    _assert_reported_once(combined, warnings, *[e.legacy for e in ENV_KEYS])
    assert combined.count("[!] ") == len(ENV_KEYS)


def test_load_config_or_exit_does_not_log_warnings(tmp_path, caplog):
    """Guard the choice of channel directly: re-adding a logging call in the
    loader without removing main.py's print silently doubles the output
    again."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps({"hashmob_api_key": "placeholder"}))

    with caplog.at_level(logging.DEBUG):
        result = config_loader.load_config_or_exit(
            env_path=None, legacy_json_path=str(legacy_path), environ={}
        )

    assert result.warnings
    assert caplog.records == []


def test_main_py_is_the_channel_that_prints_the_warnings():
    """The print must actually be there -- the logger-silence test above would
    pass just as happily if nobody reported the warnings at all."""
    source = Path(hc_main.__file__).read_text()
    assert 'print(f"[!] {_warning}")' in source


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


# ---------------------------------------------------------------------------
# The startup line naming the config files actually loaded.
#
# It exists because candidate_roots() searches a repo checkout before
# ~/.hate_crack (so a stray .env in a checkout silently outranks the real one)
# and because a .env in the current working directory is never read at all.
# Both traps are invisible without this output.
# ---------------------------------------------------------------------------


def _config_source_output(capsys, monkeypatch, *, skip_init, **kwargs):
    monkeypatch.setattr(hc_main, "SKIP_INIT", skip_init)
    hc_main._print_config_sources(**kwargs)
    return capsys.readouterr().out


def test_startup_names_both_resolved_config_paths(capsys, monkeypatch, tmp_path):
    env_path = str(tmp_path / ".env")
    json_path = str(tmp_path / "config.json")
    out = _config_source_output(
        capsys,
        monkeypatch,
        skip_init=False,
        env_path=env_path,
        legacy_json_path=json_path,
        env_created=False,
        json_created=False,
    )
    assert env_path in out
    assert json_path in out
    # Two lines, no more: this is orientation, not a report.
    assert len(out.strip().splitlines()) == 2


def test_startup_says_when_a_config_file_was_created_this_run(
    capsys, monkeypatch, tmp_path
):
    env_path = str(tmp_path / ".env")
    out = _config_source_output(
        capsys,
        monkeypatch,
        skip_init=False,
        env_path=env_path,
        legacy_json_path=str(tmp_path / "config.json"),
        env_created=True,
        json_created=False,
    )
    assert f"{env_path} (created this run)" in out
    # Still two lines -- creation is reported inline, not on a third line.
    assert len(out.strip().splitlines()) == 2


def test_startup_reports_a_missing_config_file_as_defaults(capsys, monkeypatch):
    out = _config_source_output(
        capsys,
        monkeypatch,
        skip_init=False,
        env_path=None,
        legacy_json_path=None,
        env_created=True,
        json_created=True,
    )
    assert out.count("not found -- using built-in defaults") == 2


def test_startup_says_how_a_created_file_was_created(capsys, monkeypatch, tmp_path):
    """The provenance the removed bootstrap prints used to carry (#227) rides
    on the same line as the path, so it is still said -- once."""
    env_path = str(tmp_path / ".env")
    json_path = str(tmp_path / "config.json")
    out = _config_source_output(
        capsys,
        monkeypatch,
        skip_init=False,
        env_path=env_path,
        legacy_json_path=json_path,
        env_created=True,
        json_created=True,
        env_detail="from built-in defaults",
        json_detail="from config.json.example",
    )
    assert f"{json_path} (created this run, from config.json.example)" in out
    assert f"{env_path} (created this run, from built-in defaults)" in out
    assert len(out.strip().splitlines()) == 2


# ---------------------------------------------------------------------------
# First-run output says each path once, not twice (#227 item 1)
# ---------------------------------------------------------------------------


def _first_run_output(bootstrap, monkeypatch, capsys, tmp_path, legacy_json_path):
    """Do what startup does -- bootstrap, then print the source lines -- and
    return the combined output plus the resolved paths."""
    env_missing = True
    json_missing = legacy_json_path is None
    env_path, json_path = bootstrap(None, legacy_json_path)
    monkeypatch.setattr(hc_main, "SKIP_INIT", False)
    hc_main._print_config_sources(
        env_path,
        json_path,
        env_created=env_missing,
        json_created=json_missing,
        env_detail=hc_main._config_bootstrap_detail.get("env"),
        json_detail=hc_main._config_bootstrap_detail.get("json"),
    )
    return capsys.readouterr().out, env_path, json_path


def _assert_named_once_in_the_source_lines(out, *paths):
    """Each path appears at least once overall AND exactly once among the
    ``[*]`` orientation lines.

    Both halves are needed: "exactly once" alone passes trivially when a path
    appears zero times, which is exactly how PR #222's dropped output hid.
    """
    source_lines = "\n".join(
        line for line in out.splitlines() if line.startswith("[*] ")
    )
    assert len(source_lines.splitlines()) == 2, out
    for path in paths:
        assert out.count(path) >= 1, f"{path!r} never reached the user:\n{out}"
        assert source_lines.count(path) == 1, (
            f"{path!r} named {source_lines.count(path)}x in the source lines:\n{out}"
        )


def test_first_run_from_scratch_names_each_path_once(
    bootstrap, monkeypatch, capsys, tmp_path
):
    out, env_path, json_path = _first_run_output(
        bootstrap, monkeypatch, capsys, tmp_path, None
    )
    _assert_named_once_in_the_source_lines(out, env_path, json_path)
    # And the whole first run is those two lines: no bootstrap chatter above.
    assert len(out.strip().splitlines()) == 2
    assert "config.json.example" in out


def test_first_run_migrating_names_each_path_once_and_keeps_the_source(
    bootstrap, monkeypatch, capsys, tmp_path
):
    """The migrated case is the one where the *source* path is real
    information -- the user needs to know their config.json was read."""
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_pre_split_config(ollamaModel="synthetic-model")))

    out, env_path, json_path = _first_run_output(
        bootstrap, monkeypatch, capsys, tmp_path, str(legacy_path)
    )

    _assert_named_once_in_the_source_lines(out, env_path, json_path)
    # The source is not lost: it is the config.json line directly above, which
    # the .env line points at rather than repeating the path.
    assert "migrated from the config.json above" in out
    assert f"[*] config.json: {json_path}" in out
    # The per-key cleanup notes are unique information and still print.
    assert "Delete them from" in out


def test_first_run_with_nothing_to_migrate_names_each_path_once(
    bootstrap, monkeypatch, capsys, tmp_path
):
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_post_split_config()))

    out, env_path, json_path = _first_run_output(
        bootstrap, monkeypatch, capsys, tmp_path, str(legacy_path)
    )

    _assert_named_once_in_the_source_lines(out, env_path, json_path)
    assert len(out.strip().splitlines()) == 2


def test_a_second_run_names_each_path_once_with_no_creation_claim(
    bootstrap, monkeypatch, capsys, tmp_path
):
    """Case 3: both files already exist. Nothing is created, so no line may
    claim otherwise -- and the paths are still named exactly once each."""
    env_path = tmp_path / ".env"
    write_env(str(env_path), {})
    legacy_path = tmp_path / "config.json"
    legacy_path.write_text(json.dumps(_post_split_config()))

    bootstrap(str(env_path), str(legacy_path))
    monkeypatch.setattr(hc_main, "SKIP_INIT", False)
    hc_main._print_config_sources(
        str(env_path),
        str(legacy_path),
        env_created=False,
        json_created=False,
        env_detail=hc_main._config_bootstrap_detail.get("env"),
        json_detail=hc_main._config_bootstrap_detail.get("json"),
    )
    out = capsys.readouterr().out

    _assert_named_once_in_the_source_lines(out, str(env_path), str(legacy_path))
    assert "created this run" not in out


# ---------------------------------------------------------------------------
# A dangling config symlink is fatal at startup, not silently ignored (#227)
# ---------------------------------------------------------------------------


def test_startup_routes_a_discovery_failure_to_the_fatal_diagnostic(capsys):
    """``main.py`` calls ``resolve_config_paths()`` before the loader, so the
    exception discovery now raises has to be handled there too -- otherwise a
    dangling `.env` symlink trades a silent wrong-config run for a traceback."""
    source = Path(hc_main.__file__).read_text()
    assert "except _config_loader.ConfigFileUnreadableError as _exc:" in source
    assert "_config_loader.exit_unreadable_config(_exc)" in source

    exc = config_loader.ConfigFileUnreadableError(
        "/nonexistent/link/.env", FileNotFoundError(2, "No such file or directory")
    )
    with pytest.raises(SystemExit) as exc_info:
        config_loader.exit_unreadable_config(exc)

    assert exc_info.value.code == 1
    out = capsys.readouterr().out
    assert "/nonexistent/link/.env" in out
    assert "could not be read" in out


def test_startup_prints_nothing_under_skip_init(capsys, monkeypatch, tmp_path):
    out = _config_source_output(
        capsys,
        monkeypatch,
        skip_init=True,
        env_path=str(tmp_path / ".env"),
        legacy_json_path=str(tmp_path / "config.json"),
        env_created=False,
        json_created=False,
    )
    assert out == ""
