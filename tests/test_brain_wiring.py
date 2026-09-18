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


@pytest.mark.parametrize("a_value", ["0", "1", "3"])
def test_brain_engages_for_attack_modes_hashcat_accepts(wired, monkeypatch, a_value):
    # hashcat v7.1.2, verified empirically: -a 0, 1 and 3 accept --brain-client.
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(
        ["hashcat", "-m", "3200", "-a", a_value], hash_file, None
    )
    assert "-z" in cmd


@pytest.mark.parametrize("a_value", ["6", "7"])
def test_brain_refused_for_hybrid_attack_modes(wired, monkeypatch, a_value):
    # hashcat v7.1.2, verified empirically: -a 6 and -a 7 (hybrid) refuse
    # --brain-client outright ("Invalid attack mode (-a) value specified in
    # brain-client mode.", exit 255). Hybrid, Smart Mask hybrid groups,
    # Fingerprint and extensive_crack's hybrid phases all use these modes
    # against slow hashes, so this guard is what keeps them from failing
    # outright when brain_enabled is the default true.
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(
        ["hashcat", "-m", "3200", "-a", a_value], hash_file, None
    )
    assert "-z" not in cmd
    assert cmd == ["hashcat", "-m", "3200", "-a", a_value]


def test_brain_engages_when_no_attack_mode_operand_is_present(wired, monkeypatch):
    # No `-a` in the command at all: hashcat defaults to straight mode (0),
    # which accepts brain-client, so this must not be treated as a refusal.
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    cmd = main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert "-z" in cmd


def test_notices_delatch_on_each_state_transition(wired, monkeypatch, capsys):
    # A single shared latch would let whichever notice fired first
    # permanently suppress the other for the rest of the process. With
    # ensure_server revalidating on every call, brain can flip between
    # reachable and unreachable within one session, and the operator must
    # be told on every such transition, not just the first one ever.
    main, hash_file = wired
    monkeypatch.setattr(main, "hcatHashType", "3200")
    monkeypatch.setattr(main, "_brain_notice_ok_printed", False)
    monkeypatch.setattr(main, "_brain_notice_fail_printed", False)

    monkeypatch.setattr(
        brain,
        "ensure_server",
        lambda cfg, **kw: brain.BrainServer("127.0.0.1", 6863, "pw", True),
    )
    main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert "Brain enabled" in capsys.readouterr().out

    # Still reachable: no repeat notice.
    main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert capsys.readouterr().out == ""

    # Server drops.
    monkeypatch.setattr(brain, "ensure_server", lambda cfg, **kw: None)
    main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert "no brain server could be" in capsys.readouterr().out

    # Still down: no repeat notice.
    main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert capsys.readouterr().out == ""

    # Recovers: the operator must be told again.
    monkeypatch.setattr(
        brain,
        "ensure_server",
        lambda cfg, **kw: brain.BrainServer("127.0.0.1", 6863, "pw", True),
    )
    main._maybe_add_brain(["hashcat", "-m", "3200"], hash_file, None)
    assert "Brain enabled" in capsys.readouterr().out
