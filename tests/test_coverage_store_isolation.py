"""The coverage store must never resolve to the operator's real file in tests."""

from pathlib import Path

import pytest

from hate_crack import attack_coverage as ac


def test_get_store_never_resolves_under_real_home():
    store = ac.get_store()
    resolved = Path(store.path).resolve()
    forbidden = (Path.home() / ".hate_crack" / "coverage").resolve()
    assert resolved != forbidden and forbidden not in resolved.parents, (
        f"get_store() resolved to {resolved}, inside the operator's real "
        "coverage directory. A test or agent command that calls get_store() "
        "would write to a multi-gigabyte store holding many engagements."
    )


def test_store_path_is_redirected_by_the_autouse_fixture(tmp_path):
    store = ac.get_store()
    assert Path(store.path).is_relative_to(tmp_path / "coverage"), (
        f"get_store() resolved to {store.path}, expected under {tmp_path}/coverage"
    )


def test_coverage_dir_default_uses_home(monkeypatch, tmp_path):
    """Test that _coverage_dir() uses HOME when no override is set."""
    monkeypatch.delenv("HATE_CRACK_COVERAGE_DIR", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    result = ac._coverage_dir()
    assert result == tmp_path / ".hate_crack" / "coverage"


def test_coverage_dir_expands_tilde_in_override(monkeypatch, tmp_path):
    """Test that _coverage_dir() expands ~ in the override path."""
    # Point ~ to our tmp_path via HOME
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HATE_CRACK_COVERAGE_DIR", "~/test_coverage")
    result = ac._coverage_dir()
    assert result == tmp_path / "test_coverage"


def test_coverage_dir_raises_on_empty_override(monkeypatch):
    """Test that an empty HATE_CRACK_COVERAGE_DIR raises ValueError."""
    monkeypatch.setenv("HATE_CRACK_COVERAGE_DIR", "")
    with pytest.raises(ValueError, match="empty"):
        ac._coverage_dir()


def test_coverage_dir_raises_on_whitespace_override(monkeypatch):
    """Test that whitespace-only HATE_CRACK_COVERAGE_DIR raises ValueError."""
    monkeypatch.setenv("HATE_CRACK_COVERAGE_DIR", "   \t  ")
    with pytest.raises(ValueError, match="empty"):
        ac._coverage_dir()


def test_get_store_never_raises_on_empty_override(monkeypatch, capsys):
    """Test that get_store() with empty HATE_CRACK_COVERAGE_DIR falls back.

    Does not raise, does not use the operator's real store, and prints a
    warning to stderr naming the variable.
    """
    # Reset the process-wide store first
    ac.reset_store()
    # Set empty override and get store
    monkeypatch.setenv("HATE_CRACK_COVERAGE_DIR", "")
    store = ac.get_store()  # Must not raise
    # Verify it's not the real store
    resolved = Path(store.path).resolve()
    forbidden = (Path.home() / ".hate_crack" / "coverage").resolve()
    assert resolved != forbidden and forbidden not in resolved.parents, (
        f"Fallback store resolved to {resolved}, inside the operator's real store"
    )
    # Verify warning was printed
    captured = capsys.readouterr()
    assert "HATE_CRACK_COVERAGE_DIR" in captured.err, (
        "Warning must name the problematic variable"
    )
    assert (
        "temporary directory" in captured.err
        or "Coverage will not persist" in captured.err
    )


def test_get_store_fallback_is_usable(monkeypatch):
    """Test that the fallback store actually works and persists coverage."""
    # Reset the process-wide store first
    ac.reset_store()
    # Set empty override
    monkeypatch.setenv("HATE_CRACK_COVERAGE_DIR", "")
    store = ac.get_store()
    # Intern a target
    target_id = store.intern_target("a" * 64)
    assert target_id is not None
    # Intern entries and verify we get IDs back
    ids = store.intern_entries("rule", ["$1", "c"])
    assert ids is not None
    assert len(ids) == 2
    assert all(isinstance(id_val, int) for id_val in ids)
