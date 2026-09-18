from hate_crack import brain

BASE = {
    "brain_enabled": True,
    "brain_modes_force": [],
    "brain_modes_exclude": [],
}


def _patch_oracle(monkeypatch, modes=frozenset({3200})):
    monkeypatch.setattr(brain, "slow_modes", lambda _bin, **kw: modes)


def test_slow_mode_is_slow(monkeypatch):
    _patch_oracle(monkeypatch)
    assert brain.is_slow(3200, BASE, hcat_bin="hashcat") is True


def test_fast_mode_is_not_slow(monkeypatch):
    _patch_oracle(monkeypatch)
    assert brain.is_slow(1000, BASE, hcat_bin="hashcat") is False


def test_force_overrides_a_false_oracle(monkeypatch):
    _patch_oracle(monkeypatch)
    cfg = {**BASE, "brain_modes_force": ["1000"]}
    assert brain.is_slow(1000, cfg, hcat_bin="hashcat") is True


def test_exclude_overrides_a_true_oracle(monkeypatch):
    _patch_oracle(monkeypatch)
    cfg = {**BASE, "brain_modes_exclude": ["3200"]}
    assert brain.is_slow(3200, cfg, hcat_bin="hashcat") is False


def test_exclude_wins_over_force(monkeypatch):
    _patch_oracle(monkeypatch)
    cfg = {**BASE, "brain_modes_force": ["3200"], "brain_modes_exclude": ["3200"]}
    assert brain.is_slow(3200, cfg, hcat_bin="hashcat") is False


def test_unknown_oracle_without_override_is_not_slow(monkeypatch):
    _patch_oracle(monkeypatch, modes=None)
    assert brain.is_slow(3200, BASE, hcat_bin="hashcat") is False


def test_unknown_oracle_still_honours_force(monkeypatch):
    _patch_oracle(monkeypatch, modes=None)
    cfg = {**BASE, "brain_modes_force": ["3200"]}
    assert brain.is_slow(3200, cfg, hcat_bin="hashcat") is True


def test_junk_in_a_mode_override_is_ignored_not_fatal(monkeypatch):
    _patch_oracle(monkeypatch)
    cfg = {**BASE, "brain_modes_force": ["not-a-mode", "1000"]}
    assert brain.is_slow(1000, cfg, hcat_bin="hashcat") is True
