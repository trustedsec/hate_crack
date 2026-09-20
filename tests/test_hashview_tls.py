"""TLS verification behavior for HashviewAPI (#329).

Before this fix, HashviewAPI unconditionally set ``self.session.verify =
False`` and called ``urllib3.disable_warnings(...)`` in its constructor,
silently disabling certificate verification for every Hashview request and
leaking the warning suppression process-wide to Weakpass and Hashmob traffic
that never asked for it.

``HashviewAPI`` now takes a ``verify_tls`` keyword (default ``True``) that
maps straight onto ``self.session.verify``. Only when verification is
disabled does the constructor print an operator-facing warning naming the
host and call ``urllib3.disable_warnings`` -- and it does so at most once per
host per process, via the module-level ``_TLS_WARNING_EMITTED`` set.
"""

import pytest

from hate_crack import api as api_module
from hate_crack.api import HashviewAPI


@pytest.fixture(autouse=True)
def _reset_tls_warning_state():
    """Isolate the once-per-process dedup set between tests."""
    saved = set(api_module._TLS_WARNING_EMITTED)
    api_module._TLS_WARNING_EMITTED.clear()
    yield
    api_module._TLS_WARNING_EMITTED.clear()
    api_module._TLS_WARNING_EMITTED.update(saved)


def test_default_verify_tls_is_true():
    """Constructing HashviewAPI with no verify_tls argument leaves
    verification on -- the approved behavior change for #329."""
    hv = HashviewAPI("https://hashview.example.com", "dummy-key")
    assert hv.session.verify is True


def test_verify_tls_false_disables_session_verification():
    hv = HashviewAPI("https://hashview.example.com", "dummy-key", verify_tls=False)
    assert hv.session.verify is False


def test_default_does_not_call_disable_warnings(monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module.urllib3, "disable_warnings", lambda *a, **k: calls.append((a, k))
    )
    HashviewAPI("https://hashview.example.com", "dummy-key")
    assert calls == []


def test_verify_false_calls_disable_warnings(monkeypatch):
    calls = []
    monkeypatch.setattr(
        api_module.urllib3, "disable_warnings", lambda *a, **k: calls.append((a, k))
    )
    HashviewAPI("https://hashview.example.com", "dummy-key", verify_tls=False)
    assert len(calls) == 1


def test_default_prints_no_warning(capsys):
    HashviewAPI("https://hashview.example.com", "dummy-key")
    out = capsys.readouterr().out
    assert out == ""


def test_verify_false_prints_warning_naming_the_host(capsys):
    HashviewAPI("https://hashview.example.com", "dummy-key", verify_tls=False)
    out = capsys.readouterr().out
    assert "hashview.example.com" in out
    assert "HASHVIEW_VERIFY_TLS" in out


def test_verify_false_warns_only_once_per_host(capsys):
    HashviewAPI("https://hashview.example.com", "dummy-key", verify_tls=False)
    HashviewAPI("https://hashview.example.com", "dummy-key", verify_tls=False)
    out = capsys.readouterr().out
    assert out.count("hashview.example.com") == 1


def test_verify_false_warns_again_for_a_different_host(capsys):
    HashviewAPI("https://hashview-a.example.com", "dummy-key", verify_tls=False)
    HashviewAPI("https://hashview-b.example.com", "dummy-key", verify_tls=False)
    out = capsys.readouterr().out
    assert "hashview-a.example.com" in out
    assert "hashview-b.example.com" in out


def test_download_hashes_from_hashview_threads_verify_tls(monkeypatch):
    """download_hashes_from_hashview must pass verify_tls through to the
    HashviewAPI it constructs rather than hardcoding it."""
    captured = {}

    class _FakeAPI:
        def __init__(self, base_url, api_key, debug=False, verify_tls=True):
            captured["verify_tls"] = verify_tls

        def list_customers(self):
            return {"customers": []}

    class _FakeStdin:
        def isatty(self):
            return True

    monkeypatch.setattr(api_module, "HashviewAPI", _FakeAPI)
    monkeypatch.setattr(api_module.sys, "stdin", _FakeStdin())

    def fake_input(_prompt):
        raise ValueError("stop after customer construction")

    with pytest.raises(ValueError):
        api_module.download_hashes_from_hashview(
            "https://hashview.example.com",
            "dummy-key",
            debug_mode=False,
            input_fn=fake_input,
            verify_tls=False,
        )
    assert captured["verify_tls"] is False
