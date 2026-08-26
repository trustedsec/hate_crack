"""Tests for the customer-hashfile listing step of the Hashview download menu.

Background. Listing a customer's hashfiles has two possible routes:

* ``GET /v1/customers/<id>/hashfiles`` -- one request, filtered server-side,
  covers every hash type. Added in Hashview v0.8.3-dev.
* ``GET /v1/hashfiles/hash_type/<t>`` -- returns every hashfile of that type
  server-wide, filtered client-side. Costs O(hashes of that type) on the
  server, so on a populated instance the busiest type is measured in minutes.

Servers predating the first route 404 it, and the client then swept all 26
:attr:`HashviewAPI.COMMON_HASH_TYPES` unconditionally. That is what these tests
pin down: the sweep must be a deliberate choice, one type by default, and a
timed-out type must be reported rather than read as "this customer has none".
"""

import sys

import pytest
import requests

import hate_crack.main as hc_main


def _http_error(status):
    resp = requests.Response()
    resp.status_code = status
    return requests.exceptions.HTTPError(f"{status}", response=resp)


class FakeAPI:
    """Stand-in for HashviewAPI's two listing routes."""

    COMMON_HASH_TYPES = hc_main.HashviewAPI.COMMON_HASH_TYPES

    def __init__(self, direct=None, direct_error=None, per_type=None, timeouts=()):
        self._direct = direct or []
        self._direct_error = direct_error
        self._per_type = per_type or {}
        self.last_listing_timeouts = list(timeouts)
        self.sweeps = []

    def list_customer_hashfiles(self, customer_id):
        if self._direct_error is not None:
            raise self._direct_error
        return self._direct

    def get_all_customer_hashfiles(self, customer_id, hash_types=None):
        self.sweeps.append(tuple(hash_types) if hash_types else None)
        files = []
        for ht in hash_types or ():
            files.extend(self._per_type.get(int(ht), []))
        return files


def _inputs(monkeypatch, answers):
    """Feed ``answers`` to input(); fail loudly on an unexpected extra prompt."""
    queue = list(answers)

    def _fake_input(prompt=""):
        if not queue:
            raise AssertionError(f"unexpected extra prompt: {prompt!r}")
        return queue.pop(0)

    monkeypatch.setattr("builtins.input", _fake_input)
    return queue


def test_uses_customer_scoped_route_without_prompting(monkeypatch):
    """When the one-request route answers, no hash-type prompt appears."""
    files = [{"id": 1, "customer_id": 3, "name": "a", "hash_type": 1000}]
    api = FakeAPI(direct=files)
    _inputs(monkeypatch, [])  # any prompt at all is a failure

    result, _ = hc_main._list_hashfiles_for_customer(api, 3)

    assert result == files
    assert api.sweeps == []


def test_prompts_for_one_hash_type_when_route_absent(monkeypatch, capsys):
    """A 404 means the sweep is the only route; ask for ONE type, not all 26."""
    ntlm = [{"id": 7, "customer_id": 3, "name": "ntds", "hash_type": 1000}]
    api = FakeAPI(direct_error=_http_error(404), per_type={1000: ntlm})
    _inputs(monkeypatch, ["1000"])

    result, _ = hc_main._list_hashfiles_for_customer(api, 3)

    assert result == ntlm
    assert api.sweeps == [(1000,)]


def test_default_hash_type_is_ntlm(monkeypatch):
    """Bare Enter picks 1000 -- the type engagement data almost always lands in."""
    api = FakeAPI(direct_error=_http_error(404), per_type={1000: []})
    _inputs(monkeypatch, [""])

    hc_main._list_hashfiles_for_customer(api, 3)

    assert api.sweeps == [(1000,)]


def test_all_types_is_opt_in(monkeypatch, capsys):
    """Answering A still sweeps every common type, and warns that it is slow."""
    api = FakeAPI(direct_error=_http_error(404))
    _inputs(monkeypatch, ["a"])

    hc_main._list_hashfiles_for_customer(api, 3)

    assert api.sweeps == [tuple(FakeAPI.COMMON_HASH_TYPES)]
    out = capsys.readouterr().out.lower()
    assert "slow" in out or "minutes" in out


def test_skip_listing_returns_empty_without_requests(monkeypatch):
    """Answering S skips enumeration for operators who know the hashfile ID."""
    api = FakeAPI(direct_error=_http_error(404))
    _inputs(monkeypatch, ["s"])

    assert hc_main._list_hashfiles_for_customer(api, 3)[0] == []
    assert api.sweeps == []


def test_reprompts_on_non_numeric_hash_type(monkeypatch):
    api = FakeAPI(direct_error=_http_error(404), per_type={1000: []})
    _inputs(monkeypatch, ["not-a-mode", "1000"])

    hc_main._list_hashfiles_for_customer(api, 3)

    assert api.sweeps == [(1000,)]


def test_timed_out_type_is_reported_to_the_operator(monkeypatch, capsys):
    """An incomplete listing must say so; an empty table otherwise reads as
    "this customer has no hashfiles", which is a silent wrong answer."""
    api = FakeAPI(direct_error=_http_error(404), timeouts=[1000])
    _inputs(monkeypatch, ["1000"])

    result, _ = hc_main._list_hashfiles_for_customer(api, 3)

    assert result == []
    out = capsys.readouterr().out
    assert "1000" in out
    assert "incomplete" in out.lower() or "timed out" in out.lower()


def test_non_404_from_direct_route_is_surfaced_not_swept(monkeypatch, capsys):
    """A 500 is a broken server, not an absent route: report it, do not sweep."""
    api = FakeAPI(direct_error=_http_error(500))
    _inputs(monkeypatch, [])

    assert hc_main._list_hashfiles_for_customer(api, 3)[0] == []
    assert api.sweeps == []
    assert "500" in capsys.readouterr().out


def test_connection_error_from_direct_route_does_not_sweep(monkeypatch, capsys):
    """No response at all is not a 404 either."""
    api = FakeAPI(direct_error=requests.exceptions.ConnectionError("refused"))
    _inputs(monkeypatch, [])

    assert hc_main._list_hashfiles_for_customer(api, 3)[0] == []
    assert api.sweeps == []


def test_non_interactive_never_prompts(monkeypatch):
    """Scripted runs cannot answer a prompt; they get the NTLM default."""
    api = FakeAPI(direct_error=_http_error(404), per_type={1000: []})
    monkeypatch.setattr(hc_main, "non_interactive", True, raising=False)
    _inputs(monkeypatch, [])

    hc_main._list_hashfiles_for_customer(api, 3)

    assert api.sweeps == [(1000,)]


def test_keyboard_interrupt_at_prompt_returns_empty(monkeypatch):
    """Ctrl-C at the type prompt backs out of listing, it does not kill the menu."""
    api = FakeAPI(direct_error=_http_error(404))

    def _boom(prompt=""):
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", _boom)

    assert hc_main._list_hashfiles_for_customer(api, 3)[0] == []
    assert api.sweeps == []


class TestListingExhaustiveness:
    """Only the customer-scoped route yields a complete list of a customer's files.

    This matters because the menu validates a typed hashfile ID against the
    listing. A per-type sweep lists ONE hash type, so an ID the operator read
    off the web UI is routinely absent from it, and rejecting that ID leaves no
    way to proceed. The flag is what lets the caller tell the two apart.
    """

    def test_customer_scoped_route_is_exhaustive(self, monkeypatch):
        files = [{"id": 1, "customer_id": 3, "name": "a", "hash_type": 1000}]
        api = FakeAPI(direct=files)
        _inputs(monkeypatch, [])

        result, exhaustive = hc_main._list_hashfiles_for_customer(api, 3)

        assert result == files
        assert exhaustive is True

    def test_single_type_sweep_is_not_exhaustive(self, monkeypatch):
        """The listed type is complete; the customer's other types are absent."""
        ntlm = [{"id": 7, "customer_id": 3, "name": "ntds", "hash_type": 1000}]
        api = FakeAPI(direct_error=_http_error(404), per_type={1000: ntlm})
        _inputs(monkeypatch, ["1000"])

        result, exhaustive = hc_main._list_hashfiles_for_customer(api, 3)

        assert result == ntlm
        assert exhaustive is False

    def test_all_types_sweep_is_not_exhaustive_either(self, monkeypatch):
        """COMMON_HASH_TYPES is 26 curated modes, not every mode that exists."""
        api = FakeAPI(direct_error=_http_error(404))
        _inputs(monkeypatch, ["a"])

        _, exhaustive = hc_main._list_hashfiles_for_customer(api, 3)

        assert exhaustive is False

    def test_failures_are_not_exhaustive(self, monkeypatch):
        api = FakeAPI(direct_error=_http_error(500))
        _inputs(monkeypatch, [])

        assert hc_main._list_hashfiles_for_customer(api, 3) == ([], False)


class TestPromptHashfileId:
    def test_accepts_a_listed_id(self, monkeypatch):
        _inputs(monkeypatch, ["7"])
        assert hc_main._prompt_hashfile_id({7: "1000"}, True) == 7

    def test_rejects_unlisted_id_only_when_listing_is_exhaustive(self, monkeypatch):
        _inputs(monkeypatch, ["9", "7"])
        assert hc_main._prompt_hashfile_id({7: "1000"}, True) == 7

    def test_accepts_unlisted_id_when_listing_is_partial(self, monkeypatch):
        """The regression this class exists for.

        A per-type sweep that listed NetNTLMv2 files leaves a non-empty map
        that contains none of the customer's NTLM files. Refusing the NTLM ID
        the operator just read off the web UI makes the menu unusable on
        exactly the servers that need the sweep.
        """
        _inputs(monkeypatch, ["4242"])
        assert hc_main._prompt_hashfile_id({7: "5600"}, False) == 4242

    def test_accepts_any_id_when_nothing_was_listed(self, monkeypatch):
        _inputs(monkeypatch, ["4242"])
        assert hc_main._prompt_hashfile_id({}, True) == 4242

    def test_reprompts_on_non_numeric(self, monkeypatch):
        _inputs(monkeypatch, ["abc", "7"])
        assert hc_main._prompt_hashfile_id({}, False) == 7

    def test_q_cancels(self, monkeypatch):
        _inputs(monkeypatch, ["Q"])
        assert hc_main._prompt_hashfile_id({7: "1000"}, True) is None

    def test_keyboard_interrupt_cancels(self, monkeypatch):
        def _boom(prompt=""):
            raise KeyboardInterrupt

        monkeypatch.setattr("builtins.input", _boom)
        assert hc_main._prompt_hashfile_id({}, False) is None


def test_helper_does_not_touch_the_sweep_when_the_direct_route_answers():
    """Behavioural counterpart to the source guard below.

    The source assertion catches the sweep creeping back into the menu; this
    catches it creeping back into the helper, where a source check would not
    look.
    """
    files = [{"id": 1, "customer_id": 3, "name": "a", "hash_type": 1000}]
    api = FakeAPI(direct=files)

    result, exhaustive = hc_main._list_hashfiles_for_customer(api, 3)

    assert (result, exhaustive) == (files, True)
    assert api.sweeps == []


def test_menu_calls_the_helper(monkeypatch):
    """The download-hashes menu branch must go through the helper, so the
    26-type sweep cannot creep back into the interactive path."""
    import inspect

    src = inspect.getsource(hc_main.hashview_api)
    assert "_list_hashfiles_for_customer" in src
    assert "_prompt_hashfile_id" in src
    # The unconditional 26-type sweep, and the ID validation that refused any
    # ID outside a partial listing, must not reappear inline.
    assert "get_all_customer_hashfiles" not in src
    assert "not in hashfile_map" not in src


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
