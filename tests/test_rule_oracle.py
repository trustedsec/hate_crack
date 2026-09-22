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

Its framing is version dependent, so read it through `_decode_candidate` rather
than comparing the raw stream (#337). hashcat 7.1.2-754 and later wrap a
candidate in ``$HEX[...]`` when it holds a byte that would otherwise break the
line, earlier versions emit it raw, and both are accepted here.
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
    # #295 residual-gap cases: derive() bails out (case-encoding past position
    # 35, and more interior ops than MAX_RULE_FUNCTIONS, respectively) but the
    # embedded break is at an addressable position, so it must still come back
    # lifted into an insert op rather than left in an unwritable baseword.
    "\n" + "z" * 36 + "Z" + "w",
    "a" + "1" * 15 + "\n" + "1" * 17 + "b",
    # #295 positional gap, closed by reversing the word: a break past
    # addressable position 35 counting from the left is addressable counting
    # from the right, so the rule is `r i{p}\xNN r`. hashcat is the only
    # authority on whether inserting into a reversed word and reversing back
    # lands the byte where we think it does.
    "z" * 36 + "Z" + "\n",
    "z" * 40 + "\n" + "w",
    "z" * 38 + "\n" + "z" * 3 + "\r" + "z",
    # The function-cap boundary for the reversed form: 29 inserts plus the two
    # `r` ops is exactly MAX_RULE_FUNCTIONS. Asked of the binary because "the
    # two reverses count against the cap" is otherwise only our own assumption,
    # and one function over, hashcat drops the rule without saying so.
    "z" * 40 + "\n" * 29,
]


def _decode_candidate(line):
    """Decode one ``--stdout`` line, undoing hashcat's ``$HEX[...]`` framing.

    hashcat 7.1.2-754 (upstream 836f11de1, 2026-09-20) made ``--stdout`` wrap a
    candidate in ``$HEX[...]`` whenever ``need_hexify()`` asks for it, matching
    what the outfile has always done. Before that commit the candidate went out
    raw, which turned one candidate holding an LF into two lines that no reader
    could put back together -- the exact ambiguity this file cares about.

    Both framings are accepted on purpose. Pinning only the new one would go red
    against hashcat <= 7.1.2 release, and pinning only the old one is what broke
    here. There is no flag to choose: ``--outfile-autohex-disable`` does not
    reach this path, because the new writer takes its ``always_ascii`` from the
    hash mode's ``OPTS_TYPE_PT_ALWAYS_ASCII`` rather than from that option.

    The decode cannot misfire on a candidate that merely looks hex-wrapped:
    ``need_hexify()`` calls ``is_hexify()`` first, so hashcat wraps a literal
    ``$HEX[41]`` as ``$HEX[244845585b34315d]``. Verified against the binary.
    """
    if line.startswith(b"$HEX[") and line.endswith(b"]"):
        return bytes.fromhex(line[5:-1].decode("ascii"))
    return line


def _candidates(tmp_path, baseword, rule, name="case"):
    """Return the candidates hashcat emits for one baseword under one rule.

    A list of decoded candidates, not the raw stream: splitting the stream is
    only safe because any candidate containing a line break now arrives hex
    wrapped, so one candidate really is one line.
    """
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
    out = proc.stdout
    if out == b"":
        return []
    # hashcat terminates every candidate, including the last, so the split
    # leaves one trailing empty element that is framing rather than a candidate.
    lines = out.split(b"\n")
    assert lines[-1] == b"", f"unterminated --stdout stream: {out!r}"
    return [_decode_candidate(line) for line in lines[:-1]]


def _one_candidate(tmp_path, baseword, rule, name="case"):
    """The single candidate the one-word, one-rule harness must produce."""
    got = _candidates(tmp_path, baseword, rule, name=name)
    assert len(got) == 1, f"expected exactly one candidate, got {got!r}"
    return got[0]


@_requires_hashcat
@pytest.mark.parametrize("pw", _CASES)
def test_hashcat_reproduces_the_password_from_the_derived_pair(tmp_path, pw):
    baseword, rule = rulegen.derive(pw)
    # Compared as bytes, against the one decoded candidate. A password that
    # legitimately ends in 0x0a is the case this file exists for, and it is
    # distinguishable from a shorter one only because the framing is undone
    # before the comparison rather than after a naive line split.
    assert _one_candidate(tmp_path, baseword, rule) == pw.encode("latin-1"), (
        f"derive({pw!r}) -> ({baseword!r}, {rule!r}) did not round-trip"
    )


@_requires_hashcat
@pytest.mark.parametrize("pw", _CASES)
def test_every_derived_rule_survives_a_rule_file(tmp_path, pw):
    """A rule hashcat drops produces no candidate at all, and it says nothing
    about it when other rules in the file are valid. Empty output is the tell."""
    baseword, rule = rulegen.derive(pw)
    assert _candidates(tmp_path, baseword, rule) != [], (
        f"hashcat rejected {rule!r} outright"
    )


@_requires_hashcat
def test_a_raw_line_break_argument_really_is_broken(tmp_path):
    """Negative control for the escape. Written raw, an LF argument splits the
    rule and hashcat sees a truncated `$`; a raw CR argument it rejects. If
    either of these ever starts working, the escape is no longer needed and this
    test should be the thing that says so."""
    assert _candidates(tmp_path, "zorptangle", "$\n", name="rawlf") != [
        "zorptangle\n".encode("latin-1")
    ]
    assert _candidates(tmp_path, "zorptangle", "$\r", name="rawcr") == []


@_requires_hashcat
def test_a_blank_wordlist_line_still_yields_a_candidate(tmp_path):
    """#304: a pure-CR/LF password derives to an empty baseword, i.e. a blank
    line in basewords.txt. That line is the defect -- but pin what hashcat
    actually does with it, rather than assume: a blank line is not skipped,
    it yields a zero-length candidate, and with the derived rule the original
    password really is produced. So the fix is to stop writing the blank line
    (it is still wrong to emit), not to worry about silently losing coverage
    for the password it would have produced."""
    baseword, rule = rulegen.derive("\n")
    assert (baseword, rule) == ("", "i0\\x0a")
    assert _one_candidate(tmp_path, baseword, rule, name="emptybase") == b"\n"


@_requires_hashcat
def test_the_escape_is_what_hashcat_decodes_it_to(tmp_path):
    """Pin the mechanism rather than just the outcome: hashcat turns \\xNN into
    one byte, which is the only reason a line break is expressible."""
    assert _one_candidate(tmp_path, "zorptangle", "$\\x0a") == b"zorptangle\n"
    assert _one_candidate(tmp_path, "zorptangle", "$\\x0d") == b"zorptangle\r"
    # And an ordinary byte spelled the same way, to show the decode is general.
    # This one also stays unwrapped on the wire, which is the control showing
    # the $HEX[...] framing above is driven by the byte and not applied blanket.
    assert _one_candidate(tmp_path, "zorptangle", "$\\x41") == b"zorptangleA"


# --- the decoder itself, without hashcat -------------------------------------
#
# Everything above needs hashcat on PATH, and CI has none -- the whole file is
# skipped there. So the framing decode, which is the part that broke, had no
# automated cover at all on the machine that gates merges. These run anywhere.


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        # Unwrapped: what hashcat emits for a candidate needing no framing, and
        # what every hashcat before 836f11de1 emitted for all of them.
        (b"zorptangle", b"zorptangle"),
        (b"", b""),
        # Wrapped, which is the whole point: the payload holds the line break
        # that cannot survive the stream any other way.
        (b"$HEX[7a6f727074616e676c650a]", b"zorptangle\n"),
        (b"$HEX[0a]", b"\n"),
        (b"$HEX[]", b""),
        # A candidate that is itself literally "$HEX[41]" arrives double
        # wrapped, so decoding once yields the literal rather than "A".
        # hashcat guarantees this by calling is_hexify() inside need_hexify().
        (b"$HEX[244845585b34315d]", b"$HEX[41]"),
        # Near misses stay verbatim -- a decode keyed on a loose prefix match
        # would corrupt these into something that never appeared on the wire.
        (b"$HEX[41", b"$HEX[41"),
        (b"HEX[41]", b"HEX[41]"),
        (b"x$HEX[41]", b"x$HEX[41]"),
    ],
)
def test_decode_candidate_accepts_both_framings(line, expected):
    assert _decode_candidate(line) == expected
