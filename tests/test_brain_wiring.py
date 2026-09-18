import pytest

from hate_crack import brain


@pytest.fixture
def wired(hc_module, monkeypatch, tmp_path):
    # hc_module is the root hate_crack.py proxy; `._main` is the real module
    # whose globals the wiring reads. This is the pattern
    # tests/test_coverage_wiring.py already uses -- setting an attribute on
    # the proxy would not reach main's globals.
    main = hc_module._main
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("$2a$05$abc\n")
    monkeypatch.setattr(
        brain,
        "ensure_server",
        lambda cfg, **kw: brain.BrainServer("127.0.0.1", 6863, "pw", True),
    )
    monkeypatch.setattr(brain, "is_slow", lambda mode, cfg, **kw: mode == 3200)
    monkeypatch.setattr(main, "_brain_enabled", True)
    return main, str(hash_file)


def test_brain_flags_added_for_a_slow_mode(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert "-z" in cmd
    assert cmd[cmd.index("--brain-host") + 1] == "127.0.0.1"


def test_no_brain_flags_for_a_fast_mode(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "1000")
    assert "-z" not in main._maybe_add_brain(["hashcat", "-m", "1000"], hash_file, None)


def test_no_brain_for_a_piped_generator(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, object())
    assert "-z" not in cmd


def test_no_brain_when_potfile_disable_is_present(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(
        ["hashcat", "-m", "3200", "--potfile-disable"], hash_file, None
    )
    assert "-z" not in cmd


def test_operator_brain_flags_in_tuning_are_left_alone(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(
        ["hashcat", "-m", "3200", "--brain-host", "10.0.0.9"], hash_file, None
    )
    assert cmd.count("--brain-host") == 1
    assert "-z" not in cmd


def test_disabled_globally_adds_nothing(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    monkeypatch.setattr(main, "_brain_enabled", False)
    assert "-z" not in main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)


def test_unreachable_server_degrades_to_no_brain(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    monkeypatch.setattr(brain, "ensure_server", lambda cfg, **kw: None)
    assert "-z" not in main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)


def test_non_numeric_hash_type_degrades_to_no_brain(wired, monkeypatch):
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", None)
    assert "-z" not in main._maybe_add_brain(["hashcat"], hash_file, None)
