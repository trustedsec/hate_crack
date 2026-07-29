"""Shared fixtures for the real-hashcat, real-subprocess CLI e2e suite.

Gated entirely behind HATE_CRACK_HASHCAT_REAL=1 — see the module-level
pytestmark in each tests/e2e/test_e2e_*.py file. Never runs in standard CI
(ubuntu-latest CI runners have no hashcat installed).
"""
import json
import os
import shutil
import struct

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

E2E_PLAINTEXTS = ("changeme123", "e2e2026", "notarealpassword")

# The adhoc_mask_crack test targets exactly "changeme123": 8 lowercase
# letters ("changeme") + 3 digits ("123") = 11 mask positions.
E2E_MASK = "?l?l?l?l?l?l?l?l?d?d?d"


def _md4(data: bytes) -> bytes:
    """Pure-Python MD4 (RFC 1320). No external dependency, works regardless
    of whether the platform's OpenSSL build exposes MD4 (OpenSSL 3.x's
    default provider does not — only the legacy provider does, and
    hashlib.new("md4", ...) raises ValueError/UnsupportedDigestmodError on
    such builds, which this suite hit on real developer hardware)."""

    def left_rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def F(x, y, z):
        return (x & y) | (~x & z)

    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)

    def H(x, y, z):
        return x ^ y ^ z

    msg = bytearray(data)
    orig_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len_bits)

    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for chunk_offset in range(0, len(msg), 64):
        chunk = msg[chunk_offset:chunk_offset + 64]
        X = list(struct.unpack("<16I", chunk))
        A, B, C, D = a0, b0, c0, d0

        # Round 1
        s = [3, 7, 11, 19]
        for i in range(16):
            k = i
            if i % 4 == 0:
                A = left_rotate((A + F(B, C, D) + X[k]) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                D = left_rotate((D + F(A, B, C) + X[k]) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                C = left_rotate((C + F(D, A, B) + X[k]) & 0xFFFFFFFF, s[2])
            else:
                B = left_rotate((B + F(C, D, A) + X[k]) & 0xFFFFFFFF, s[3])

        # Round 2
        s = [3, 5, 9, 13]
        order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i, k in enumerate(order):
            if i % 4 == 0:
                A = left_rotate((A + G(B, C, D) + X[k] + 0x5A827999) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                D = left_rotate((D + G(A, B, C) + X[k] + 0x5A827999) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                C = left_rotate((C + G(D, A, B) + X[k] + 0x5A827999) & 0xFFFFFFFF, s[2])
            else:
                B = left_rotate((B + G(C, D, A) + X[k] + 0x5A827999) & 0xFFFFFFFF, s[3])

        # Round 3
        s = [3, 9, 11, 15]
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i, k in enumerate(order):
            if i % 4 == 0:
                A = left_rotate((A + H(B, C, D) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[0])
            elif i % 4 == 1:
                D = left_rotate((D + H(A, B, C) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[1])
            elif i % 4 == 2:
                C = left_rotate((C + H(D, A, B) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[2])
            else:
                B = left_rotate((B + H(C, D, A) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[3])

        a0 = (a0 + A) & 0xFFFFFFFF
        b0 = (b0 + B) & 0xFFFFFFFF
        c0 = (c0 + C) & 0xFFFFFFFF
        d0 = (d0 + D) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def _ntlm(password: str) -> str:
    return _md4(password.encode("utf-16-le")).hex()


def _missing_required_binaries() -> list[str]:
    missing = []
    if not shutil.which("hashcat"):
        missing.append("hashcat (not on PATH)")
    hate_path_candidates = [
        os.path.join(REPO_ROOT, "hate_crack"),
        REPO_ROOT,
    ]
    hashcat_utils_ok = any(
        os.path.isdir(os.path.join(c, "hashcat-utils", "bin")) for c in hate_path_candidates
    )
    if not hashcat_utils_ok:
        missing.append("hashcat-utils/bin (run `make submodules`)")
    pcfg_ok = any(
        os.path.isfile(os.path.join(c, "pcfg_cracker", "pcfg_guesser.py"))
        for c in hate_path_candidates
    )
    if not pcfg_ok:
        missing.append("pcfg_cracker/pcfg_guesser.py (run `make submodules`)")
    return missing


def _isolation_hazard() -> str | None:
    for candidate in (REPO_ROOT, os.path.join(REPO_ROOT, "hate_crack")):
        if os.path.isfile(os.path.join(candidate, "config.json")):
            return (
                f"a config.json exists at {candidate}; move it aside before "
                "running HATE_CRACK_HASHCAT_REAL tests — these tests set HOME "
                "to isolate config resolution, but _candidate_roots() checks "
                "the repo root and package directory before ~/.hate_crack, so "
                "a config.json there always wins regardless of HOME."
            )
    return None


@pytest.fixture(scope="session", autouse=True)
def _e2e_preflight():
    if os.environ.get("HATE_CRACK_HASHCAT_REAL") != "1":
        yield
        return
    hazard = _isolation_hazard()
    if hazard:
        pytest.skip(hazard)
    missing = _missing_required_binaries()
    if missing:
        pytest.skip("Missing required e2e binaries: " + "; ".join(missing))
    yield


@pytest.fixture
def e2e_home(tmp_path):
    """Fresh HOME dir with ~/.hate_crack/config.json isolating config
    resolution for the subprocess (see Global Constraints: _candidate_roots()
    doesn't search cwd, only repo paths then ~/.hate_crack)."""
    home_dir = tmp_path / "home"
    hate_crack_dir = home_dir / ".hate_crack"
    hate_crack_dir.mkdir(parents=True)

    with open(os.path.join(REPO_ROOT, "config.json.example")) as f:
        config = json.load(f)

    wordlists_dir = tmp_path / "wordlists"
    optimized_dir = tmp_path / "optimized_wordlists"
    rules_dir = tmp_path / "rules"
    wordlists_dir.mkdir()
    optimized_dir.mkdir()
    rules_dir.mkdir()

    config["notify_enabled"] = False
    config["check_for_updates"] = False
    config["hcatWordlists"] = str(wordlists_dir)
    config["hcatOptimizedWordlists"] = str(optimized_dir)
    config["rules_directory"] = str(rules_dir)

    (hate_crack_dir / "config.json").write_text(json.dumps(config))
    return home_dir


@pytest.fixture
def e2e_hash_file(tmp_path):
    lines = [
        f"user{i}:{_ntlm(pw)}" for i, pw in enumerate(E2E_PLAINTEXTS, start=1)
    ]
    hash_file = tmp_path / "hashes.ntlm"
    hash_file.write_text("\n".join(lines) + "\n")
    return hash_file


@pytest.fixture
def e2e_wordlist(e2e_home):
    """~30-line wordlist containing all three E2E_PLAINTEXTS plus decoys,
    placed under e2e_home's configured wordlists dir."""
    wordlists_dir = json.loads(
        (e2e_home / ".hate_crack" / "config.json").read_text()
    )["hcatWordlists"]
    decoys = [
        "password", "letmein", "qwerty123", "dragon", "monkey", "football",
        "baseball", "sunshine", "princess", "welcome", "shadow", "master",
        "abc123", "trustno1", "iloveyou", "starwars", "whatever", "freedom",
        "hunter2", "cheese", "computer", "internet", "superman", "batman",
        "flower", "hockey", "soccer", "tiger",
    ]
    lines = list(E2E_PLAINTEXTS) + decoys
    wordlist_path = os.path.join(wordlists_dir, "e2e.txt")
    with open(wordlist_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return wordlist_path


@pytest.fixture
def e2e_wordlist_no_target(e2e_home):
    """A wordlist deliberately NOT containing any E2E_PLAINTEXTS, for the
    harness smoke test (proves 'ran clean, zero cracks' is distinguishable
    from 'actually cracked something')."""
    wordlists_dir = json.loads(
        (e2e_home / ".hate_crack" / "config.json").read_text()
    )["hcatWordlists"]
    decoys = ["nope1", "nope2", "wrongpassword", "notitherer"]
    wordlist_path = os.path.join(wordlists_dir, "no_target.txt")
    with open(wordlist_path, "w") as f:
        f.write("\n".join(decoys) + "\n")
    return wordlist_path


@pytest.fixture
def e2e_rules_dir(e2e_home):
    rules_dir = json.loads(
        (e2e_home / ".hate_crack" / "config.json").read_text()
    )["rules_directory"]
    rule_path = os.path.join(rules_dir, "e2e.rule")
    with open(rule_path, "w") as f:
        f.write(":\n")
    return rules_dir
