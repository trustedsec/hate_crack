"""hate_crack.session_log: reading bypass status out of hashcat session logs."""

import os

from hate_crack import session_log as sl

EXHAUSTED = "TOP.1\tSUB.1\tstatus-after-work\t5\n"
BYPASSED = "TOP.1\tSUB.2\tstatus-after-work\t9\n"
OTHER = "TOP.1\tSUB.3\tstatus-before-work\t9\n"


def test_session_name_separate_argument():
    assert sl.session_name(["hashcat", "--session", "t_Dict", "h"]) == "t_Dict"


def test_session_name_equals_form():
    assert sl.session_name(["hashcat", "--session=t_Dict"]) == "t_Dict"


def test_session_name_last_separate_value_wins():
    cmd = ["hashcat", "--session", "first", "--session", "last"]
    assert sl.session_name(cmd) == "last"


def test_session_name_last_wins_across_mixed_forms():
    cmd = ["hashcat", "--session", "a", "--session=b"]
    assert sl.session_name(cmd) == "b"


def test_session_name_absent():
    assert sl.session_name(["hashcat", "-a", "0", "h", "w"]) is None


def test_session_name_trailing_flag_without_value():
    assert sl.session_name(["hashcat", "--session"]) is None


def test_candidate_paths_cover_xdg_legacy_and_binary_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    binary = tmp_path / "hc" / "hashcat"
    binary.parent.mkdir()
    binary.write_text("")
    paths = sl.candidate_log_paths("s1", str(binary))
    assert str(tmp_path / "xdg" / "hashcat" / "sessions" / "s1.log") in paths
    assert str(tmp_path / "home" / ".hashcat" / "sessions" / "s1.log") in paths
    assert str(tmp_path / "hc" / "sessions" / "s1.log") in paths
    assert len(paths) == len(set(paths))


def test_snapshot_records_size_or_zero(tmp_path):
    present = tmp_path / "a.log"
    present.write_text(EXHAUSTED)
    missing = tmp_path / "b.log"
    snap = sl.snapshot([str(present), str(missing)])
    assert snap == {str(present): len(EXHAUSTED), str(missing): 0}


def test_bypass_written_after_offset_is_detected(tmp_path):
    log = tmp_path / "s.log"
    log.write_text(EXHAUSTED)
    snap = sl.snapshot([str(log)])
    with open(log, "a") as fh:
        fh.write(EXHAUSTED + BYPASSED)
    assert sl.bypassed_since(snap) is True


def test_bypass_before_offset_is_ignored(tmp_path):
    """The log is appended across runs that share a session name; a bypass
    from an earlier run must not poison this one."""
    log = tmp_path / "s.log"
    log.write_text(BYPASSED)
    snap = sl.snapshot([str(log)])
    with open(log, "a") as fh:
        fh.write(EXHAUSTED)
    assert sl.bypassed_since(snap) is False


def test_status_nine_on_another_key_is_not_a_bypass(tmp_path):
    log = tmp_path / "s.log"
    snap = sl.snapshot([str(log)])
    log.write_text(OTHER)
    assert sl.bypassed_since(snap) is False


def test_log_created_during_run_is_read_from_start(tmp_path):
    log = tmp_path / "s.log"
    snap = sl.snapshot([str(log)])
    log.write_text(BYPASSED)
    assert sl.bypassed_since(snap) is True


def test_truncated_log_is_read_from_start(tmp_path):
    log = tmp_path / "s.log"
    log.write_text(EXHAUSTED * 10)
    snap = sl.snapshot([str(log)])
    log.write_text(BYPASSED)
    assert sl.bypassed_since(snap) is True


def test_no_readable_log_is_unknown(tmp_path):
    snap = sl.snapshot([str(tmp_path / "nope.log")])
    assert sl.bypassed_since(snap) is None


def test_any_candidate_with_a_bypass_wins(tmp_path):
    quiet = tmp_path / "q.log"
    loud = tmp_path / "l.log"
    snap = sl.snapshot([str(quiet), str(loud)])
    quiet.write_text(EXHAUSTED)
    loud.write_text(BYPASSED)
    assert sl.bypassed_since(snap) is True


def test_unwritable_path_does_not_raise(tmp_path):
    directory = tmp_path / "is_a_dir.log"
    directory.mkdir()
    snap = sl.snapshot([str(directory)])
    assert sl.bypassed_since(snap) is None
    assert os.path.isdir(directory)
