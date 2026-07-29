"""Real-subprocess, real-hashcat e2e tests for the 4 non-interactive CLI
subcommands: quick, dict, brute, topmask.
"""
import json
import os

import pytest

from tests.e2e.conftest import E2E_PLAINTEXTS, _ntlm
from tests.e2e.noninteractive_harness import run_noninteractive

pytestmark = pytest.mark.skipif(
    os.environ.get("HATE_CRACK_HASHCAT_REAL") != "1",
    reason="Set HATE_CRACK_HASHCAT_REAL=1 to run real-hashcat e2e tests.",
)

# hcatDictionary() (the "dict" methodology) hard-codes 3 rule filenames that
# ship with neither this repo nor Task 1's e2e_home fixture: best66.rule,
# d3ad0ne.rule, T0XlC.rule (see hate_crack/main.py's hcatDictionary). A real
# run against a bare e2e_home fixture fails with FileNotFoundError before
# hashcat is even invoked. This fixture is scoped to this test file (not
# conftest.py, which belongs to Task 1) and drops in trivial identity rules
# (":") under the same names so "dict" can run end-to-end without needing
# the real community rule files installed.
_DICT_REQUIRED_RULES = ("best66.rule", "d3ad0ne.rule", "T0XlC.rule")


@pytest.fixture
def e2e_dict_rules(e2e_home):
    rules_dir = json.loads(
        (e2e_home / ".hate_crack" / "config.json").read_text()
    )["rules_directory"]
    for name in _DICT_REQUIRED_RULES:
        with open(os.path.join(rules_dir, name), "w") as f:
            f.write(":\n")
    return rules_dir


def _read_cracked(out_path):
    if not os.path.isfile(out_path):
        return ""
    with open(out_path) as f:
        return f.read()


def test_quick_cracks_all_plaintexts(e2e_home, e2e_hash_file, e2e_wordlist):
    result = run_noninteractive(
        ["quick", str(e2e_hash_file), "1000", "--wordlist", str(e2e_wordlist)],
        home_dir=e2e_home,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    cracked = _read_cracked(f"{e2e_hash_file}.nt.out")
    for plaintext in E2E_PLAINTEXTS:
        assert plaintext in cracked


def test_dict_cracks_all_plaintexts(
    e2e_home, e2e_hash_file, e2e_wordlist, e2e_dict_rules
):
    # "dict" uses the configured wordlists dir (e2e_home's config.json
    # points hcatWordlists at the same dir e2e_wordlist writes into), no
    # --wordlist flag.
    result = run_noninteractive(
        ["dict", str(e2e_hash_file), "1000"],
        home_dir=e2e_home,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    cracked = _read_cracked(f"{e2e_hash_file}.nt.out")
    for plaintext in E2E_PLAINTEXTS:
        assert plaintext in cracked


_BRUTE_PLAINTEXT = "hc2026"  # 6 chars — see fixture below for why.


@pytest.fixture
def e2e_brute_hash_file(tmp_path):
    """Dedicated single-hash file for the brute test, deliberately NOT using
    e2e_hash_file/E2E_PLAINTEXTS (Task 1's shared fixtures — see conftest.py).

    hcatBruteForce() hard-codes the full ?a charset (?l?u?d?s, 95 chars) at
    every mask position, so keyspace is 95**N regardless of what --min/--max
    is passed. None of E2E_PLAINTEXTS is short enough for that to be a fast,
    *deterministic* test: measured live on this hardware (Apple M3 Max,
    OpenCL backend, hashcat -b -m 1000 -> ~14 GH/s), 95**7 (e2e2026's length)
    is a ~70 trillion-key space taking ~77 minutes to exhaust, and hashcat's
    GPU candidate-generator does not enumerate in simple first-character
    order, so there is no reliable early-exit fraction to bound wall time by
    — a live run got to 5% progress in ~4 minutes with no crack yet. A
    6-char password bounds the keyspace to 95**6 (~7.35e11 keys), which at
    the same measured throughput exhausts in ~52 seconds *even in the
    worst case* (full keyspace scan, no lucky early hit needed) — the
    property this test actually needs is a guaranteed upper bound, not an
    expected-value guess about candidate ordering.
    """
    hash_file = tmp_path / "hashes_brute.ntlm"
    hash_file.write_text(f"user1:{_ntlm(_BRUTE_PLAINTEXT)}\n")
    return hash_file


def test_brute_cracks_single_length_target(e2e_home, e2e_brute_hash_file):
    result = run_noninteractive(
        ["brute", str(e2e_brute_hash_file), "1000", "--min", "6", "--max", "6"],
        home_dir=e2e_home,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    cracked = _read_cracked(f"{e2e_brute_hash_file}.nt.out")
    assert _BRUTE_PLAINTEXT in cracked


def test_topmask_cracks_with_zero_target_time(e2e_home, e2e_hash_file):
    result = run_noninteractive(
        ["topmask", str(e2e_hash_file), "1000", "--target-time", "0"],
        home_dir=e2e_home,
        timeout=180,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    # Observed on a live run: with no optimized-wordlist stats available,
    # --target-time 0 drives PACK/maskgen.py's mask selection down to zero
    # candidate masks (it hits a ZeroDivisionError internally computing mask
    # coverage %, which hate_crack does not propagate as a failure), so
    # hashcat receives an empty mask list, logs "Invalid mask.", and exits
    # cleanly. hate_crack still creates the (empty) `.nt.out` file via
    # `-o` before hashcat gives up, so its existence is the correct
    # observable signal here, not zero-byte content or any specific crack.
    assert os.path.isfile(f"{e2e_hash_file}.nt.out")


def test_harness_smoke_no_crack_when_wordlist_lacks_target(
    e2e_home, e2e_hash_file, e2e_wordlist_no_target
):
    """Proves the harness distinguishes 'ran clean, zero cracks' from
    'actually cracked something' — every other test's positive assertion
    depends on this being true."""
    result = run_noninteractive(
        [
            "quick", str(e2e_hash_file), "1000",
            "--wordlist", str(e2e_wordlist_no_target),
        ],
        home_dir=e2e_home,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    cracked = _read_cracked(f"{e2e_hash_file}.nt.out")
    for plaintext in E2E_PLAINTEXTS:
        assert plaintext not in cracked
