"""Validate ``rulegen.derive()``'s emitted rules against hashcat itself.

Every other test of the derivation asserts against `apply_rule`, which is our
own reference implementation of the op subset -- so the two can agree perfectly
while both being wrong about what hashcat does. hashcat is the authority on its
own rule language, so ask hashcat: hand it the baseword and the rule and see
whether the candidate it generates is the original password, byte for byte.

This matters most for a password holding a literal CR or LF. Such a byte cannot
be written raw into a line-based rule file -- an LF ends the rule wherever it
falls, and a raw CR makes hashcat reject the line outright -- so `derive()`
spells it `\\x0a`/`\\x0d` instead. That escape is a claim about hashcat's
behaviour, and only hashcat can confirm it. The negative control below pins the
other half: the raw form really is broken, so the escape is load-bearing rather
than decorative.

`--stdout` is the whole harness here. No hash, no attack, no session state: it
prints the candidates a rule file produces over a wordlist and exits, which is
exactly the question being asked and costs one process start per case.
"""

import shutil
import subprocess

import pytest

from hate_crack import rulegen

_requires_hashcat = pytest.mark.skipif(
    shutil.which("hashcat") is None, reason="hashcat not available in PATH"
)

# Each is a password derive() must be able to round-trip through real hashcat.
# The line-break cases are the point; the rest are controls, so a regression in
# the escape cannot hide behind a suite that only ever tries exotic input.
_CASES = [
    "zorptangle",
    "Zorptangle1",
    "zorptangle ",
    " zorptangle",
    "zorp.tangle9",
    "zorptangle\n",
    "zorptangle\r",
    "\nzorptangle",
    "zorp\ntangle",
    "Zorptangle12\n",
    "12\n34",
]


def _candidates(tmp_path, baseword, rule, name="case"):
    """Return the raw bytes hashcat emits for one baseword under one rule."""
    words = tmp_path / f"{name}.words"
    rules = tmp_path / f"{name}.rule"
    # latin-1 so a high byte round-trips as itself rather than as UTF-8, the
    # same convention rulegen writes its output files with.
    words.write_bytes(baseword.encode("latin-1") + b"\n")
    rules.write_bytes(rule.encode("latin-1") + b"\n")
    proc = subprocess.run(
        ["hashcat", "--stdout", "-r", str(rules), str(words)],
        capture_output=True,
        timeout=60,
        check=False,
    )
    return proc.stdout


@_requires_hashcat
@pytest.mark.parametrize("pw", _CASES)
def test_hashcat_reproduces_the_password_from_the_derived_pair(tmp_path, pw):
    baseword, rule = rulegen.derive(pw)
    out = _candidates(tmp_path, baseword, rule)
    # hashcat terminates each candidate with a newline of its own, so the
    # expected stream is the password plus that terminator. Compared as bytes:
    # a candidate that legitimately ends in 0x0a is indistinguishable from a
    # short one under any line-splitting comparison.
    assert out == pw.encode("latin-1") + b"\n", (
        f"derive({pw!r}) -> ({baseword!r}, {rule!r}) did not round-trip"
    )


@_requires_hashcat
@pytest.mark.parametrize("pw", _CASES)
def test_every_derived_rule_survives_a_rule_file(tmp_path, pw):
    """A rule hashcat drops produces no candidate at all, and it says nothing
    about it when other rules in the file are valid. Empty output is the tell."""
    baseword, rule = rulegen.derive(pw)
    assert _candidates(tmp_path, baseword, rule) != b"", (
        f"hashcat rejected {rule!r} outright"
    )


@_requires_hashcat
def test_a_raw_line_break_argument_really_is_broken(tmp_path):
    """Negative control for the escape. Written raw, an LF argument splits the
    rule and hashcat sees a truncated `$`; a raw CR argument it rejects. If
    either of these ever starts working, the escape is no longer needed and this
    test should be the thing that says so."""
    assert _candidates(tmp_path, "zorptangle", "$\n", name="rawlf") != (
        "zorptangle\n".encode("latin-1") + b"\n"
    )
    assert _candidates(tmp_path, "zorptangle", "$\r", name="rawcr") == b""


@_requires_hashcat
def test_the_escape_is_what_hashcat_decodes_it_to(tmp_path):
    """Pin the mechanism rather than just the outcome: hashcat turns \\xNN into
    one byte, which is the only reason a line break is expressible."""
    assert _candidates(tmp_path, "zorptangle", "$\\x0a") == b"zorptangle\n\n"
    assert _candidates(tmp_path, "zorptangle", "$\\x0d") == b"zorptangle\r\n"
    # And an ordinary byte spelled the same way, to show the decode is general.
    assert _candidates(tmp_path, "zorptangle", "$\\x41") == b"zorptangleA\n"
