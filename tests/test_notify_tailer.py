"""Unit tests for the CrackTailer polling thread and username extractor."""
import time
from pathlib import Path
from unittest.mock import MagicMock

from hate_crack.notify.settings import NotifySettings
from hate_crack.notify.tailer import CrackTailer, extract_username_from_out_line


def _settings(**overrides) -> NotifySettings:
    defaults = {
        "enabled": True,
        "per_crack_enabled": True,
        "max_cracks_per_burst": 5,
        # Short poll so tests don't hang.
        "poll_interval_seconds": 0.05,
    }
    defaults.update(overrides)
    return NotifySettings(**defaults)


def _make_tailer(out_path: Path, **overrides):
    notify = MagicMock(name="notify_callback")
    aggregate = MagicMock(name="aggregate_callback")
    settings = _settings(**overrides)
    tailer = CrackTailer(
        out_path=str(out_path),
        attack_name="Brute Force",
        settings=settings,
        notify_callback=notify,
        aggregate_callback=aggregate,
    )
    return tailer, notify, aggregate


def _wait_until(predicate, timeout=2.0):
    """Spin until predicate() or timeout; returns whether it passed."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class TestExtractUsername:
    def test_bare_hash_returns_none(self) -> None:
        assert extract_username_from_out_line("5f4dcc3b5aa10b0be:secret") is None

    def test_user_hash_plain(self) -> None:
        assert extract_username_from_out_line("alice:5f4dcc:secret") == "alice"

    def test_pwdump(self) -> None:
        assert (
            extract_username_from_out_line("alice:1001:aad3b435:31d6cfe:::secret")
            == "alice"
        )

    def test_netntlmv2(self) -> None:
        line = "alice::DOMAIN:1122334455667788:resp:resp2:secret"
        assert extract_username_from_out_line(line) == "alice"

    def test_empty_line(self) -> None:
        assert extract_username_from_out_line("") is None

    def test_whitespace_only(self) -> None:
        assert extract_username_from_out_line("\n") is None

    def test_line_with_trailing_newline(self) -> None:
        assert extract_username_from_out_line("alice:hash:plain\n") == "alice"

    def test_does_not_leak_plaintext(self) -> None:
        # No matter the format, the return value must never equal the
        # plaintext password. Paranoid test; relies on us knowing where
        # the plaintext sits in each format.
        for line, plain in [
            ("bob:1000:aa:bb:::s3cret", "s3cret"),
            ("bob:hash:s3cret", "s3cret"),
            ("bob::DOM:chal:resp:resp2:s3cret", "s3cret"),
        ]:
            assert extract_username_from_out_line(line) != plain


class TestCrackTailerStart:
    def test_daemon_is_true(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, _, _ = _make_tailer(out)
        assert tailer.daemon is True

    def test_seeks_to_eof_on_start(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("alice:hash:plain\nbob:hash:plain\n")
        tailer, notify, aggregate = _make_tailer(out)
        tailer.start()
        try:
            # Allow at least one poll interval; no new lines were added, so
            # no notifications should fire.
            time.sleep(0.2)
            assert notify.call_count == 0
            assert aggregate.call_count == 0
        finally:
            tailer.stop()

    def test_new_lines_fire_notify(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, notify, aggregate = _make_tailer(out)
        tailer.start()
        try:
            with open(out, "a") as f:
                f.write("alice:hash:plain\n")
                f.write("bob:hash:plain\n")
            assert _wait_until(lambda: notify.call_count >= 2)
            assert aggregate.call_count == 0
            labels = [call.args[0] for call in notify.call_args_list]
            assert "alice" in labels
            assert "bob" in labels
        finally:
            tailer.stop()

    def test_no_username_falls_back_to_attack_name(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, notify, aggregate = _make_tailer(out)
        tailer.start()
        try:
            with open(out, "a") as f:
                # Bare-hash format -> extractor returns None -> fallback.
                f.write("5f4dcc3b5:plain\n")
            assert _wait_until(lambda: notify.call_count >= 1)
            assert notify.call_args.args[0] == "Brute Force"
        finally:
            tailer.stop()


class TestCrackTailerBurstCap:
    def test_burst_cap_fires_aggregate(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, notify, aggregate = _make_tailer(out, max_cracks_per_burst=3)
        tailer.start()
        try:
            # Write 10 lines in one shot; a single poll tick must see them
            # all and collapse into one aggregate call.
            with open(out, "a") as f:
                for i in range(10):
                    f.write(f"user{i}:hash:plain\n")
            assert _wait_until(lambda: aggregate.call_count >= 1)
            # Per-crack path must NOT have fired for this burst.
            assert notify.call_count == 0
            args = aggregate.call_args.args
            assert args[0] == 10
            assert args[1] == "Brute Force"
        finally:
            tailer.stop()

    def test_under_cap_fires_per_crack(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, notify, aggregate = _make_tailer(out, max_cracks_per_burst=10)
        tailer.start()
        try:
            with open(out, "a") as f:
                for i in range(3):
                    f.write(f"user{i}:hash:plain\n")
            assert _wait_until(lambda: notify.call_count >= 3)
            assert aggregate.call_count == 0
        finally:
            tailer.stop()


class TestCrackTailerStop:
    def test_stop_joins_within_timeout(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, _, _ = _make_tailer(out)
        tailer.start()
        start = time.time()
        tailer.stop()
        elapsed = time.time() - start
        assert not tailer.is_alive()
        assert elapsed < 5.0

    def test_stop_is_safe_without_start(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("")
        tailer, _, _ = _make_tailer(out)
        # Calling stop on a never-started thread should not raise.
        tailer.stop()


class TestCrackTailerFileHandling:
    def test_missing_file_then_appearing(self, tmp_path: Path) -> None:
        out = tmp_path / "missing.out"
        tailer, notify, _ = _make_tailer(out)
        tailer.start()
        try:
            time.sleep(0.15)
            out.write_text("alice:hash:plain\n")
            assert _wait_until(lambda: notify.call_count >= 1)
        finally:
            tailer.stop()

    def test_truncation_resets_position(self, tmp_path: Path) -> None:
        out = tmp_path / "hashes.out"
        out.write_text("alice:hash:plain\nbob:hash:plain\n")
        tailer, notify, _ = _make_tailer(out)
        tailer.start()
        try:
            time.sleep(0.15)
            # Truncate the file and write a fresh line; tailer should reset
            # its file position and see the new line.
            out.write_text("charlie:hash:plain\n")
            assert _wait_until(lambda: notify.call_count >= 1)
            labels = [call.args[0] for call in notify.call_args_list]
            assert "charlie" in labels
        finally:
            tailer.stop()
