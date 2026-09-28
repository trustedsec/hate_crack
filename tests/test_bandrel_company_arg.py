"""hcatBandrel's company name becomes a parameter (issue #340).

The attack previously read the company name from a blocking `while True:
input(...)` loop, which is why it could not be driven non-interactively: a
scripted run raises EOFError inside the loop rather than taking a default.
Adding the parameter must not change what an operator at the menu sees, so
both halves are pinned here.
"""

import subprocess
from unittest.mock import patch

import pytest

import hate_crack.main as hc_main


@pytest.fixture
def stub_hashcat(monkeypatch, tmp_path):
    """Capture the hashcat argv lists without launching anything."""
    launched = []

    class _Proc:
        """Stands in for a Popen object.

        It carries `args` and the context-manager protocol because some call
        sites reach hashcat through subprocess.run(), which builds on Popen and
        touches both -- and which of those paths hcatBandrel takes depends on
        module globals an earlier test may have left set. Being complete here
        is what keeps this file order-independent.
        """

        returncode = 0
        stdout = None
        stderr = None

        def __init__(self, cmd=None):
            self.args = cmd

        def communicate(self, *a, **k):
            return (b"", b"")

        def wait(self, *a, **k):
            return 0

        def poll(self):
            return 0

        def kill(self):
            return None

        # subprocess.run() and some call sites use Popen as a context manager,
        # and which branch hcatBandrel takes depends on module globals an
        # earlier test may have left set -- so support both shapes rather than
        # being correct only in the order this file happens to run in.
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def _popen(cmd, *a, **k):
        launched.append(cmd)
        return _Proc(cmd)

    monkeypatch.setattr(subprocess, "Popen", _popen)
    monkeypatch.setattr(hc_main, "bandrelbasewords", "summer,winter")
    # hcatBandrel finishes by calling pipal(), which reads the module-level
    # hcatHashFile global. hate_crack.main is shared across the session, so
    # whatever an earlier test left there would leak in here -- and pipal is
    # a reporting step, not part of what these tests pin.
    monkeypatch.setattr(hc_main, "hcatHashFile", str(tmp_path / "hashes.txt"))
    monkeypatch.setattr(hc_main, "pipal", lambda *a, **k: [])
    return launched


def test_company_name_argument_skips_the_prompt(stub_hashcat, tmp_path):
    hashfile = str(tmp_path / "hashes.txt")
    with patch(
        "builtins.input", side_effect=AssertionError("prompted despite company_name")
    ):
        hc_main.hcatBandrel("1000", hashfile, company_name="Acme")
    assert stub_hashcat, "no hashcat invocation was built"


def _mask_tokens(launched):
    """The per-baseword custom charset, e.g. "-1aA" for "Acme" -- one argv
    token, not a flag/value pair."""
    return {t for cmd in launched for t in cmd if str(t).startswith("-1")}


def test_company_name_is_split_on_commas(stub_hashcat, tmp_path):
    hashfile = str(tmp_path / "hashes.txt")
    with patch("builtins.input", side_effect=AssertionError("prompted")):
        hc_main.hcatBandrel("1000", hashfile, company_name="Acme,Globex")
    # Two companies plus the two stubbed static basewords.
    assert _mask_tokens(stub_hashcat) == {"-1aA", "-1gG", "-1sS", "-1wW"}


def test_interactive_path_still_prompts(stub_hashcat, tmp_path):
    """Regression guard: the menu handler calls hcatBandrel with no company,
    and must still get the prompt."""
    hashfile = str(tmp_path / "hashes.txt")
    with patch("builtins.input", return_value="Acme") as mock_input:
        hc_main.hcatBandrel("1000", hashfile)
    assert mock_input.called


def test_interactive_prompt_still_rejects_an_empty_answer(stub_hashcat, tmp_path):
    """The original loop re-asked until the answer was non-empty."""
    hashfile = str(tmp_path / "hashes.txt")
    with patch("builtins.input", side_effect=["", "  ", "Acme"]) as mock_input:
        hc_main.hcatBandrel("1000", hashfile)
    assert mock_input.call_count == 3


def test_comma_separated_names_are_stripped(stub_hashcat, tmp_path):
    """ "Acme, Globex" must not build a mask from a leading space --
    the masks are derived from name[0] and name[1:]."""
    hashfile = str(tmp_path / "hashes.txt")
    with patch("builtins.input", side_effect=AssertionError("prompted")):
        hc_main.hcatBandrel("1000", hashfile, company_name="Acme, Globex")
    masks = _mask_tokens(stub_hashcat)
    assert not any(m.startswith("-1 ") for m in masks), masks
    assert "-1gG" in masks
