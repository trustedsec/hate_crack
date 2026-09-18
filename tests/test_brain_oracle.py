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
