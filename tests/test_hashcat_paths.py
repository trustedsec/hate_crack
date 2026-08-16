"""hashcat 7 moved per-user state out of ``~/.hashcat``.

hate_crack used to hardcode the pre-7 potfile path *and* recreate its directory
on every hashcat invocation, so hashcat's "delete the old directory" notice
could never be cleared and ``--potfile-path`` pointed at an empty file while
the real potfile sat in the new location.
"""

import os

import pytest

from hate_crack import hashcat_paths
from hate_crack.config_schema import CONFIG_SCHEMA


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """Give every test its own HOME and no inherited XDG overrides."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    hashcat_paths.reset_version_cache()
    yield home
    hashcat_paths.reset_version_cache()


def _pin_version(monkeypatch, major):
    monkeypatch.setattr(
        hashcat_paths, "hashcat_major_version", lambda _bin="hashcat": major
    )


# --- directory resolution ---------------------------------------------------


def test_hashcat_7_uses_the_xdg_data_directory(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    assert hashcat_paths.hashcat_data_dir() == str(
        _clean_env / ".local" / "share" / "hashcat"
    )


def test_hashcat_6_still_uses_the_legacy_directory(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 6)
    assert hashcat_paths.hashcat_data_dir() == str(_clean_env / ".hashcat")


def test_xdg_data_home_is_honored(monkeypatch, tmp_path):
    """hashcat itself honors XDG_DATA_HOME; hardcoding ~/.local/share would
    point hate_crack at a different potfile than hashcat writes."""
    _pin_version(monkeypatch, 7)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert hashcat_paths.hashcat_data_dir() == str(tmp_path / "xdg" / "hashcat")


def test_relative_xdg_data_home_follows_hashcat_not_the_spec(
    monkeypatch, tmp_path, _clean_env
):
    """A relative XDG_DATA_HOME is invalid per the XDG spec, but hashcat uses
    it verbatim and lands in a cwd-relative directory (verified against
    v7.1.2). Treating it as invalid and falling back to ~/.local/share would
    point hate_crack at a directory hashcat is not using."""
    _pin_version(monkeypatch, 7)
    monkeypatch.setenv("XDG_DATA_HOME", "relative/path")
    monkeypatch.chdir(tmp_path)
    assert hashcat_paths.hashcat_data_dir() == str(
        tmp_path / "relative" / "path" / "hashcat"
    )


def test_empty_xdg_data_home_matches_hashcats_getenv_semantics(monkeypatch, _clean_env):
    """hashcat branches on the pointer, not the contents, so an exported but
    empty XDG_DATA_HOME sends it to /hashcat rather than the fallback."""
    _pin_version(monkeypatch, 7)
    monkeypatch.setenv("XDG_DATA_HOME", "")
    assert hashcat_paths.hashcat_data_dir() == "/hashcat"


def test_unknown_version_prefers_the_modern_directory(monkeypatch, _clean_env):
    """When hashcat cannot be run, an already-migrated machine must not be
    dragged back to the legacy layout."""
    _pin_version(monkeypatch, None)
    (_clean_env / ".local" / "share" / "hashcat").mkdir(parents=True)
    (_clean_env / ".hashcat").mkdir()
    assert hashcat_paths.hashcat_data_dir() == str(
        _clean_env / ".local" / "share" / "hashcat"
    )


def test_unknown_version_falls_back_to_legacy_when_only_it_exists(
    monkeypatch, _clean_env
):
    _pin_version(monkeypatch, None)
    (_clean_env / ".hashcat").mkdir()
    assert hashcat_paths.hashcat_data_dir() == str(_clean_env / ".hashcat")


def test_version_lookup_survives_a_missing_binary(_clean_env):
    assert hashcat_paths.hashcat_major_version("definitely-not-a-real-binary") is None


# --- the config setting -----------------------------------------------------


def test_empty_setting_still_means_pass_no_potfile_flag(_clean_env):
    assert hashcat_paths.resolve_potfile_setting("", base_dir="/base") == ""
    assert hashcat_paths.resolve_potfile_setting("   ", base_dir="/base") == ""


def test_auto_resolves_to_hashcats_own_potfile(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    assert hashcat_paths.resolve_potfile_setting("auto", base_dir="/base") == str(
        _clean_env / ".local" / "share" / "hashcat" / "hashcat.potfile"
    )


def test_auto_is_case_insensitive(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    assert hashcat_paths.resolve_potfile_setting(
        "AUTO", base_dir="/base"
    ) == hashcat_paths.resolve_potfile_setting("auto", base_dir="/base")


def test_explicit_paths_are_untouched(_clean_env):
    assert (
        hashcat_paths.resolve_potfile_setting("/tmp/custom.pot", base_dir="/base")
        == "/tmp/custom.pot"
    )


def test_relative_paths_anchor_to_base_dir(_clean_env):
    assert (
        hashcat_paths.resolve_potfile_setting("custom.pot", base_dir="/base")
        == "/base/custom.pot"
    )


def test_tilde_paths_expand(_clean_env):
    assert hashcat_paths.resolve_potfile_setting("~/x.pot", base_dir="/base") == str(
        _clean_env / "x.pot"
    )


def test_shipped_default_is_not_the_legacy_literal():
    """Regression guard for the bug this module exists to fix."""
    entry = next(k for k in CONFIG_SCHEMA if k.legacy == "hcatPotfilePath")
    assert entry.default == hashcat_paths.AUTO
    assert ".hashcat/" not in entry.default


# --- detecting the stranded directory ---------------------------------------


def test_no_warning_when_there_is_no_legacy_directory(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    assert hashcat_paths.legacy_home_warning() is None


def test_no_warning_for_an_empty_legacy_directory(monkeypatch, _clean_env):
    """hashcat nags about the bare directory; hate_crack should only speak up
    when something is actually stranded in it."""
    _pin_version(monkeypatch, 7)
    (_clean_env / ".hashcat").mkdir()
    assert hashcat_paths.legacy_home_warning() is None


def test_no_warning_on_hashcat_6_where_legacy_is_still_current(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 6)
    legacy = _clean_env / ".hashcat"
    legacy.mkdir()
    (legacy / "hashcat.potfile").write_text("hash:plain\n")
    assert hashcat_paths.legacy_home_warning() is None


def test_warning_reports_what_is_stranded(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    legacy = _clean_env / ".hashcat"
    (legacy / "sessions").mkdir(parents=True)
    (legacy / "sessions" / "a.restore").write_text("x")
    (legacy / "hashcat.potfile").write_text("hash:plain\n")
    (legacy / "hashcat.dictstat2").write_text("x")

    message = hashcat_paths.legacy_home_warning()
    assert message is not None
    assert str(legacy) in message
    assert "1 session(s)" in message
    assert "1 other file(s)" in message
    assert "--migrate-hashcat-home" in message


def test_inspect_returns_none_without_the_directory(_clean_env):
    assert hashcat_paths.inspect_legacy_home() is None


# --- migration --------------------------------------------------------------


def test_migration_copies_without_deleting_the_source(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    legacy = _clean_env / ".hashcat"
    (legacy / "sessions").mkdir(parents=True)
    (legacy / "sessions" / "a.restore").write_text("session")
    (legacy / "hashcat.potfile").write_text("hash:plain\n")

    result = hashcat_paths.migrate_legacy_home()

    modern = _clean_env / ".local" / "share" / "hashcat"
    assert (modern / "hashcat.potfile").read_text() == "hash:plain\n"
    assert (modern / "sessions" / "a.restore").read_text() == "session"
    assert sorted(result.copied) == ["hashcat.potfile", "sessions"]
    # Nothing is destroyed: removing the old directory stays the operator's call.
    assert (legacy / "hashcat.potfile").exists()


def test_migration_never_overwrites_an_existing_potfile(monkeypatch, _clean_env):
    """The destination potfile is the live one. Clobbering it would destroy
    real cracks; merging two potfiles is the operator's judgement call."""
    _pin_version(monkeypatch, 7)
    legacy = _clean_env / ".hashcat"
    legacy.mkdir()
    (legacy / "hashcat.potfile").write_text("old\n")
    modern = _clean_env / ".local" / "share" / "hashcat"
    modern.mkdir(parents=True)
    (modern / "hashcat.potfile").write_text("live\n")

    hashcat_paths.migrate_legacy_home()

    assert (modern / "hashcat.potfile").read_text() == "live\n"
    assert (modern / "hashcat.potfile.from-legacy").read_text() == "old\n"


def test_migration_dry_run_writes_nothing(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    legacy = _clean_env / ".hashcat"
    legacy.mkdir()
    (legacy / "hashcat.potfile").write_text("old\n")

    result = hashcat_paths.migrate_legacy_home(dry_run=True)

    assert result.copied == ["hashcat.potfile"]
    assert not (_clean_env / ".local" / "share" / "hashcat").exists()


def test_migration_is_a_noop_on_hashcat_6(monkeypatch, _clean_env):
    """Source and destination are the same directory there."""
    _pin_version(monkeypatch, 6)
    legacy = _clean_env / ".hashcat"
    legacy.mkdir()
    (legacy / "hashcat.potfile").write_text("old\n")

    result = hashcat_paths.migrate_legacy_home()

    assert result.copied == []
    assert result.source == result.destination
    assert not (legacy / "hashcat.potfile.from-legacy").exists()


def test_migration_without_a_legacy_directory_is_harmless(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    result = hashcat_paths.migrate_legacy_home()
    assert result.copied == [] and result.skipped == []


def test_migration_skips_a_name_that_collides_twice(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    legacy = _clean_env / ".hashcat"
    legacy.mkdir()
    (legacy / "hashcat.potfile").write_text("old\n")
    modern = _clean_env / ".local" / "share" / "hashcat"
    modern.mkdir(parents=True)
    (modern / "hashcat.potfile").write_text("live\n")
    (modern / "hashcat.potfile.from-legacy").write_text("previous\n")

    result = hashcat_paths.migrate_legacy_home()

    assert result.skipped == ["hashcat.potfile"]
    assert (modern / "hashcat.potfile.from-legacy").read_text() == "previous\n"


def test_a_symlinked_legacy_home_is_not_reported_as_stranded(monkeypatch, _clean_env):
    """Hand-migrating with `ln -s` is reasonable. Following the link would
    report the live, in-use potfile as stranded and tell the operator to
    delete it."""
    _pin_version(monkeypatch, 7)
    modern = _clean_env / ".local" / "share" / "hashcat"
    modern.mkdir(parents=True)
    (modern / "hashcat.potfile").write_text("live\n")
    (_clean_env / ".hashcat").symlink_to(modern)

    assert hashcat_paths.inspect_legacy_home() is None
    assert hashcat_paths.legacy_home_warning() is None


def test_migration_does_not_duplicate_a_symlinked_legacy_home(monkeypatch, _clean_env):
    """Under abspath the symlink compares unequal, and every entry collides
    with itself and gets copied as `<name>.from-legacy` inside the live
    directory -- duplicating the whole potfile onto itself."""
    _pin_version(monkeypatch, 7)
    modern = _clean_env / ".local" / "share" / "hashcat"
    modern.mkdir(parents=True)
    (modern / "hashcat.potfile").write_text("live\n")
    (_clean_env / ".hashcat").symlink_to(modern)

    result = hashcat_paths.migrate_legacy_home()

    assert result.copied == [] and result.skipped == []
    assert not (modern / "hashcat.potfile.from-legacy").exists()
    assert sorted(p.name for p in modern.iterdir()) == ["hashcat.potfile"]


def test_a_failed_copy_leaves_no_truncated_file_at_the_destination(
    monkeypatch, _clean_env
):
    """A part-written potfile at the destination would become hashcat's live
    one, silently truncated, while the run reported only "skipped"."""
    _pin_version(monkeypatch, 7)
    legacy = _clean_env / ".hashcat"
    legacy.mkdir()
    (legacy / "hashcat.potfile").write_text("hash:plain\n" * 100)

    real_copy2 = hashcat_paths.shutil.copy2

    def _die_partway(src, dst, *a, **kw):
        real_copy2(src, dst)  # leave a real, complete-looking staged file
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(hashcat_paths.shutil, "copy2", _die_partway)

    result = hashcat_paths.migrate_legacy_home()

    modern = _clean_env / ".local" / "share" / "hashcat"
    assert result.skipped == ["hashcat.potfile"]
    assert result.copied == []
    # Neither the destination name nor the staging name may survive.
    assert list(modern.iterdir()) == []


def test_cache_dir_follows_xdg(monkeypatch, tmp_path, _clean_env):
    assert hashcat_paths.modern_cache_dir() == str(_clean_env / ".cache" / "hashcat")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "c"))
    assert hashcat_paths.modern_cache_dir() == str(tmp_path / "c" / "hashcat")


def test_default_potfile_path_sits_in_the_data_dir(monkeypatch, _clean_env):
    _pin_version(monkeypatch, 7)
    assert hashcat_paths.default_potfile_path() == os.path.join(
        hashcat_paths.hashcat_data_dir(), "hashcat.potfile"
    )
