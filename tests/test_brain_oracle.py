import json

import pytest

from hate_crack import brain


@pytest.fixture(autouse=True)
def _clear_memo():
    """Clear the process-local memo before each test for independence."""
    brain._MEMO.clear()
    yield


SAMPLE = json.dumps(
    {
        "0": {"name": "MD5", "slow_hash": False},
        "1000": {"name": "NTLM", "slow_hash": False},
        "3200": {"name": "bcrypt", "slow_hash": True},
    }
)


def _fake_runner(version="v7.1.2", info=SAMPLE, rc=0):
    calls = []

    def run(args):
        calls.append(args)
        if "--version" in args:
            return 0, version
        return rc, info

    run.calls = calls
    return run


def test_slow_modes_parses_machine_readable_json(tmp_path, monkeypatch):
    monkeypatch.setattr(brain, "_run_hashcat", _fake_runner())
    assert brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path) == frozenset({3200})


def test_slow_modes_returns_none_when_output_is_not_json(tmp_path, monkeypatch):
    monkeypatch.setattr(brain, "_run_hashcat", _fake_runner(info="Hash mode #3200"))
    assert brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path) is None


def test_slow_modes_caches_by_version_and_skips_second_query(tmp_path, monkeypatch):
    runner = _fake_runner()
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path)
    brain._MEMO.clear()
    brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path)
    info_calls = [c for c in runner.calls if "--hash-info" in c]
    assert len(info_calls) == 1
    assert (tmp_path / brain.CACHE_FILENAME).is_file()


def test_slow_modes_requeries_after_hashcat_upgrade(tmp_path, monkeypatch):
    monkeypatch.setattr(brain, "_run_hashcat", _fake_runner(version="v7.1.2"))
    brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path)
    brain._MEMO.clear()
    newer = _fake_runner(
        version="v7.2.0",
        info=json.dumps({"3200": {"slow_hash": True}, "8900": {"slow_hash": True}}),
    )
    monkeypatch.setattr(brain, "_run_hashcat", newer)
    assert brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path) == frozenset(
        {3200, 8900}
    )


def test_slow_modes_returns_none_when_hashcat_not_found(tmp_path):
    """Mock-free test: real subprocess failure when binary doesn't exist."""
    assert brain.slow_modes("/nonexistent/hashcat", cache_dir=tmp_path) is None


def test_slow_modes_returns_none_for_empty_result_and_does_not_cache(
    tmp_path, monkeypatch
):
    """Empty slow-mode lists are treated as unknown, not cached."""
    # Valid JSON with no slow modes
    runner = _fake_runner(info=json.dumps({"0": {"slow_hash": False}}))
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    assert brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path) is None
    # Verify cache file was not written
    assert not (tmp_path / brain.CACHE_FILENAME).is_file()


def test_slow_modes_ignores_empty_cache_and_requeries(tmp_path, monkeypatch):
    """Empty modes list in cache is treated as unknown; fresh query happens."""
    # Pre-seed cache with empty modes for current version
    (tmp_path / brain.CACHE_FILENAME).write_text(
        json.dumps({"version": "v7.1.2", "modes": []})
    )

    # Mock hashcat to return one slow mode
    runner = _fake_runner(info=json.dumps({"3200": {"slow_hash": True}}))
    monkeypatch.setattr(brain, "_run_hashcat", runner)

    # Should query despite cache having empty modes
    result = brain.slow_modes("/usr/bin/hashcat", cache_dir=tmp_path)
    assert result == frozenset({3200})

    # Verify it actually queried (called --hash-info)
    info_calls = [c for c in runner.calls if "--hash-info" in c]
    assert len(info_calls) == 1


# --- hashcat 8 renumbered recipes -------------------------------------------

LIST_8 = json.dumps(
    {
        "0": {"name": "MD5", "slow_hash": False},
        "3200": {"name": "bcrypt", "slow_hash": True},
    }
)
PER_MODE_12100 = json.dumps(
    {"12100": {"name": "PBKDF2-HMAC-SHA512", "slow_hash": True}}
)


def _per_mode_runner(version="v8.0.0", listing=LIST_8, per_mode=None):
    per_mode = per_mode or {}
    calls = []

    def run(args):
        calls.append(args)
        if "--version" in args:
            return 0, version
        if "-m" in args:
            mode = args[args.index("-m") + 1]
            return (0, "banner\n" + per_mode[mode]) if mode in per_mode else (1, "")
        return 0, listing

    run.calls = calls
    return run


def _per_mode_calls(runner):
    return [c for c in runner.calls if "-m" in c]


def test_unlisted_mode_is_resolved_with_a_per_mode_query(tmp_path, monkeypatch):
    runner = _per_mode_runner(per_mode={"12100": PER_MODE_12100})
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    assert brain.is_slow(12100, {}, hcat_bin="hashcat") is True
    assert _per_mode_calls(runner) == [
        ["hashcat", "-m", "12100", "--hash-info", "--machine-readable"]
    ]


def test_per_mode_result_is_memoized(tmp_path, monkeypatch):
    runner = _per_mode_runner(per_mode={"12100": PER_MODE_12100})
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    brain.is_slow(12100, {}, hcat_bin="hashcat")
    brain.is_slow(12100, {}, hcat_bin="hashcat")
    assert len(_per_mode_calls(runner)) == 1


def test_listed_fast_mode_never_triggers_a_per_mode_query(tmp_path, monkeypatch):
    runner = _per_mode_runner()
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    assert brain.is_slow(0, {}, hcat_bin="hashcat") is False
    assert _per_mode_calls(runner) == []


def test_failed_per_mode_query_is_not_slow_and_never_raises(tmp_path, monkeypatch):
    runner = _per_mode_runner()
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    assert brain.is_slow(99999, {}, hcat_bin="hashcat") is False


def test_cache_records_all_modes(tmp_path, monkeypatch):
    monkeypatch.setattr(brain, "_run_hashcat", _per_mode_runner())
    brain.slow_modes("hashcat", cache_dir=tmp_path)
    cached = json.loads((tmp_path / brain.CACHE_FILENAME).read_text())
    assert cached["all_modes"] == [0, 3200]


def test_old_cache_without_all_modes_requeries_once(tmp_path, monkeypatch):
    (tmp_path / brain.CACHE_FILENAME).write_text(
        json.dumps({"version": "v8.0.0", "modes": [3200]})
    )
    runner = _per_mode_runner()
    monkeypatch.setattr(brain, "_run_hashcat", runner)
    assert brain.slow_modes("hashcat", cache_dir=tmp_path) == frozenset({3200})
    assert any("--hash-info" in c and "-m" not in c for c in runner.calls)
    assert "all_modes" in json.loads((tmp_path / brain.CACHE_FILENAME).read_text())


def test_old_cache_is_kept_as_fallback_when_requery_fails(tmp_path, monkeypatch):
    (tmp_path / brain.CACHE_FILENAME).write_text(
        json.dumps({"version": "v8.0.0", "modes": [3200]})
    )
    monkeypatch.setattr(brain, "_run_hashcat", _per_mode_runner(listing="garbage"))
    assert brain.slow_modes("hashcat", cache_dir=tmp_path) == frozenset({3200})
