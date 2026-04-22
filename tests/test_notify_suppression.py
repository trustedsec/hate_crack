"""Unit tests for hate_crack.notify._suppress."""
import threading
import time

from hate_crack.notify._suppress import is_suppressed, suppressed_notifications


class TestSuppressionContextManager:
    def test_default_is_not_suppressed(self) -> None:
        assert is_suppressed() is False

    def test_inside_context_is_suppressed(self) -> None:
        assert is_suppressed() is False
        with suppressed_notifications():
            assert is_suppressed() is True
        assert is_suppressed() is False

    def test_nested_restores_outer_state(self) -> None:
        with suppressed_notifications():
            assert is_suppressed() is True
            with suppressed_notifications():
                assert is_suppressed() is True
            # Leaving inner context must still leave us suppressed.
            assert is_suppressed() is True
        assert is_suppressed() is False

    def test_exception_restores_state(self) -> None:
        try:
            with suppressed_notifications():
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        assert is_suppressed() is False


class TestSuppressionThreadLocal:
    def test_other_thread_not_suppressed_by_us(self) -> None:
        seen: list[bool] = []
        ready = threading.Event()
        done = threading.Event()

        def worker() -> None:
            # Wait until main thread has entered its suppression context,
            # then sample our own state.
            ready.wait(timeout=2.0)
            seen.append(is_suppressed())
            done.set()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        with suppressed_notifications():
            assert is_suppressed() is True
            ready.set()
            done.wait(timeout=2.0)
        t.join(timeout=2.0)
        assert seen == [False], f"worker thread saw suppression state: {seen}"

    def test_worker_thread_suppression_does_not_leak(self) -> None:
        worker_done = threading.Event()

        def worker() -> None:
            with suppressed_notifications():
                assert is_suppressed() is True
                # Hold long enough that the main thread can sample.
                time.sleep(0.05)
            worker_done.set()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        # Main thread should never observe the worker's suppression.
        assert is_suppressed() is False
        t.join(timeout=2.0)
        assert worker_done.is_set()
        assert is_suppressed() is False
