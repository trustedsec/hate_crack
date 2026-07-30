"""Validate ``corpus_stats._mask()`` against hashcat itself.

Every other test of `_mask` asserts against a hand-written expected string,
which only proves the function is self-consistent -- it re-encodes our belief
about what `?l`/`?d`/`?s` mean rather than checking it. hashcat is the authority
on its own mask language, so ask hashcat: hash a short synthetic plaintext, hand
hashcat the mask `_mask()` produced, and see whether it recovers the plaintext.

This is how #230 was found. `_mask()` was emitting `?s` for non-ASCII characters
and hashcat exhausted the whole keyspace without a hit, because every hashcat
built-in charset is ASCII-only (`?a` is exactly 95 candidates) and because
hashcat masks are byte-oriented while `_mask()` is character-oriented.

Scope is therefore deliberately ASCII. Non-ASCII masks are known-broken and
tracked in #230; asserting the current broken behaviour here would lock it in.
"""

import hashlib
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

from hate_crack.corpus_stats import _mask


# Short on purpose. `?l?l?d?l` is 175,760 candidates and exhausts in under a
# second; a 6-character all-`?a` mask would be 7e11 and never finish.
# Three is enough to cover the three ASCII classes `_mask` distinguishes
# (?l/?u/?d) in more than one position each. Each case costs a hashcat process
# start, and these tests are local-only -- CI does not install hashcat, so they
# skip there -- which makes wall-clock a real cost with no CI benefit to offset
# it.
_ASCII_CASES = [
    "ab2x",
    "Qz7",
    "kk90",
]

# A mask that is the right LENGTH but the wrong CHARSET for "ab2x": position 3
# is a digit, not a lowercase letter. hashcat must exhaust rather than crack.
# Without this control the positive cases could pass for the wrong reason -- a
# potfile hit, or a `--quiet` output format change making the "cracked" check
# match nothing at all and the assertion vacuous.
_NEGATIVE_CASE = ("ab2x", "?l?l?l?l")


def _hashcat_available() -> bool:
    return shutil.which("hashcat") is not None


def _sessions_writable() -> bool:
    """hashcat writes session state under ~/.hashcat/sessions.

    Unwritable under some sandbox/MDM configurations, where hashcat emits
    errors unrelated to anything being tested.
    """
    sessions_dir = Path.home() / ".hashcat" / "sessions"
    try:
        sessions_dir.mkdir(parents=True, exist_ok=True)
        probe = sessions_dir / ".hate_crack_mask_oracle_probe"
        probe.write_text("")
        probe.unlink()
    except OSError:
        return False
    return True


_requires_hashcat = pytest.mark.skipif(
    not _hashcat_available(), reason="hashcat not available in PATH"
)


def _run_mask(md5_hash: str, mask: str, session: str) -> subprocess.CompletedProcess:
    cmd = [
        "hashcat",
        "-m",
        "0",
        "-a",
        "3",
        # Without this a previous run's crack is served from the potfile and
        # every assertion below passes without hashcat generating anything.
        "--potfile-disable",
        "--quiet",
        # Unique per invocation: concurrent or back-to-back runs otherwise share
        # ~/.hashcat/sessions state and race (see #226).
        "--session",
        session,
        md5_hash,
        mask,
    ]
    try:
        return subprocess.run(
            cmd, capture_output=True, text=True, timeout=180, check=False
        )
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"hashcat timed out on {shlex.join(cmd)} -- the mask keyspace is "
            "probably far larger than intended for this test"
        )


def _md5(plaintext: str) -> str:
    return hashlib.md5(plaintext.encode()).hexdigest()


@_requires_hashcat
@pytest.mark.parametrize("plaintext", _ASCII_CASES)
def test_generated_mask_actually_generates_the_password(plaintext, request):
    """hashcat must recover the plaintext from the mask `_mask()` produced."""
    if not _sessions_writable():
        pytest.skip("hashcat session directory (~/.hashcat/sessions) is not writable")

    mask = _mask(plaintext)
    md5_hash = _md5(plaintext)
    result = _run_mask(md5_hash, mask, session=f"maskoracle_{request.node.name}")
    combined = result.stdout + result.stderr

    assert f"{md5_hash}:{plaintext}" in combined, (
        f"hashcat did not recover {plaintext!r} from the mask _mask() produced "
        f"({mask!r}). Either the mask is not a valid description of the "
        f"plaintext, or it is the wrong length. exit={result.returncode} "
        f"output={combined!r}"
    )


@_requires_hashcat
def test_a_wrong_mask_is_not_cracked():
    """Negative control: the oracle must be able to fail.

    If hashcat "cracked" the hash under a mask that cannot produce the
    plaintext, every positive assertion above would be meaningless -- most
    likely a potfile hit rather than real candidate generation.
    """
    if not _sessions_writable():
        pytest.skip("hashcat session directory (~/.hashcat/sessions) is not writable")

    plaintext, wrong_mask = _NEGATIVE_CASE
    md5_hash = _md5(plaintext)
    result = _run_mask(md5_hash, wrong_mask, session="maskoracle_negative")
    combined = result.stdout + result.stderr

    assert f"{md5_hash}:{plaintext}" not in combined, (
        f"hashcat reported {plaintext!r} cracked under {wrong_mask!r}, which "
        "cannot generate it. The oracle is not measuring candidate generation "
        f"-- check --potfile-disable. output={combined!r}"
    )


@_requires_hashcat
def test_every_builtin_charset_is_ascii_only():
    """Pin the fact #230 rests on: no built-in charset reaches beyond ASCII.

    `?a` is the union of `?l?u?d?s`. If it ever covered more than the 95
    printable ASCII characters, the non-ASCII mask problem would change shape
    and #230 would need revisiting.
    """
    # `?a` is the union and therefore the load-bearing one; `?d` is checked too
    # because #229 turned on what it does and does not contain. The other three
    # are implied by ?a's total and are not worth a process start each.
    counts = {}
    for charset in ("d", "a"):
        result = subprocess.run(
            ["hashcat", "--stdout", "-a", "3", f"?{charset}"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        counts[charset] = len([line for line in result.stdout.splitlines() if line])

    assert counts == {"d": 10, "a": 95}, (
        f"hashcat built-in charset sizes changed: {counts}. ?a covering exactly "
        "95 is the printable-ASCII set; a different total means masks can now "
        "describe non-ASCII input and #230's analysis needs redoing."
    )
