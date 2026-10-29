"""hcatBandrel's pipal feedback pass runs one mask per pipal baseword (#357).

After the company-name pass, hcatBandrel asks pipal for basewords from what has
cracked so far and is meant to run a mask attack for each. The command-building
block sat under an ``else: pass`` instead of inside the loop, so the pass was
dead in both directions: with basewords it built masks and discarded them
without launching hashcat, and with none it launched a stray run from the last
company name's leftover masks, six ``?a`` longer than intended.

The pipal masks also carried ``-1=xX``. hashcat takes everything after ``-1``
as the charset, so that defined the charset as ``=``, ``x`` and ``X`` -- a
third of every first-position candidate wasted on a literal ``=``.
"""

from unittest.mock import patch

import pytest

import hate_crack.main as hc_main


@pytest.fixture
def runs(monkeypatch, tmp_path):
    """Capture every hashcat argv hcatBandrel hands to _run_hcat_cmd."""
    launched = []
    monkeypatch.setattr(
        hc_main, "_run_hcat_cmd", lambda cmd, *a, **k: launched.append(list(cmd))
    )
    monkeypatch.setattr(hc_main, "bandrelbasewords", "summer")
    monkeypatch.setattr(hc_main, "hcatHashFile", str(tmp_path / "hashes.txt"))
    return launched


def _bandrel(tmp_path, pipal_words):
    with (
        patch.object(hc_main, "pipal", return_value=pipal_words),
        patch("builtins.input", side_effect=AssertionError("prompted")),
    ):
        hc_main.hcatBandrel("1000", str(tmp_path / "hashes.txt"), company_name="Acme")


def _pipal_runs(launched):
    return [cmd for cmd in launched if any("Bandrel_Pipal" in str(t) for t in cmd)]


def _charset_and_mask(cmd):
    # -i <charset> <hashfile> <mask>; tuning and potfile args follow the mask.
    i = cmd.index("-i")
    return cmd[i + 1], cmd[i + 3]


def test_each_pipal_baseword_gets_its_own_run(runs, tmp_path):
    _bandrel(tmp_path, ["password", "welcome"])
    pipal = _pipal_runs(runs)
    assert [_charset_and_mask(cmd) for cmd in pipal] == [
        ("-1pP", "?1assword?a?a?a?a?a?a"),
        ("-1wW", "?1elcome?a?a?a?a?a?a"),
    ]


def test_no_pipal_basewords_means_no_pipal_run(runs, tmp_path):
    _bandrel(tmp_path, [])
    assert _pipal_runs(runs) == []
    # Only the company name and the one static baseword.
    assert len(runs) == 2


def test_pipal_returning_none_means_no_pipal_run(runs, tmp_path):
    _bandrel(tmp_path, None)
    assert _pipal_runs(runs) == []


def test_empty_pipal_entries_are_skipped(runs, tmp_path):
    _bandrel(tmp_path, ["", "dragon"])
    assert [_charset_and_mask(cmd) for cmd in _pipal_runs(runs)] == [
        ("-1dD", "?1ragon?a?a?a?a?a?a"),
    ]


def test_no_charset_carries_a_literal_equals(runs, tmp_path):
    _bandrel(tmp_path, ["password"])
    charsets = [t for cmd in runs for t in cmd if str(t).startswith("-1")]
    assert charsets, "no custom charset was built"
    assert not any(t.startswith("-1=") for t in charsets), charsets
