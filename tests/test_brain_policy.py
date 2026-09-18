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


def test_scalar_mode_override_does_not_raise(monkeypatch):
    """A scalar config value (e.g., 3200 instead of [3200]) is silently ignored, not fatal."""
    _patch_oracle(monkeypatch)
    cfg = {**BASE, "brain_modes_exclude": 3200}
    # Should not raise; should use the oracle verdict
    assert brain.is_slow(3200, cfg, hcat_bin="hashcat") is True


def test_bare_string_mode_override_does_not_misread(monkeypatch):
    """A bare string (e.g., "3200" instead of ["3200"]) is rejected, not iterated character-by-character."""
    _patch_oracle(monkeypatch)
    cfg = {**BASE, "brain_modes_force": "3200"}
    # If misread, would iterate "3200" as characters and force modes 0, 2, 3.
    # Correctly rejecting the string, mode 0 should not be forced.
    assert brain.is_slow(0, cfg, hcat_bin="hashcat") is False


def test_mode_coercion_handles_string_mode_defensively(monkeypatch):
    """A string mode argument is coerced to int, not silently failing membership tests."""
    _patch_oracle(monkeypatch)
    # Pass mode as a string; should be coerced to int
    assert brain.is_slow("3200", BASE, hcat_bin="hashcat") is True


def test_mode_coercion_handles_junk_defensively(monkeypatch):
    """A non-numeric mode argument returns False rather than raising."""
    _patch_oracle(monkeypatch)
    # Pass mode as something non-numeric; should return False, not raise
    assert brain.is_slow("not-a-mode", BASE, hcat_bin="hashcat") is False
