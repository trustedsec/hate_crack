"""Guard: no coverage-bearing command may combine ``--runtime`` with increment.

On hashcat 8.0.0-73, ``--runtime`` combined with ``-i`` is a whole-run deadline
shared across the increment lengths, and an aborted increment run still exits 1
(Exhausted). ``_run_hcat_cmd`` reads exit 1 as "keyspace exhausted" and records
coverage, so such a command would bank ground that was never enumerated. No
attack combines the two today; this test fails if one starts to.

It is enforced at the ``_run_hcat_cmd`` seam: the real wrappers are driven with
``_run_hcat_cmd`` replaced by a recorder, and every captured (cmd, coverage)
pair is inspected.
"""

from unittest.mock import patch

import pytest

INCREMENT_FLAGS = ("-i", "--increment", "--increment-min", "--increment-max")


def _has_increment(cmd):
    return any(
        str(a) in INCREMENT_FLAGS
        or str(a).startswith(("--increment-min=", "--increment-max="))
        for a in cmd
    )


def _violations(calls):
    return [
        cmd
        for cmd, coverage in calls
        if coverage is not None and "--runtime" in cmd and _has_increment(cmd)
    ]


class _Stop(Exception):
    pass


@pytest.fixture
def m(hc_module):
    return hc_module._main


@pytest.fixture
def env(tmp_path):
    hashes = tmp_path / "target.txt"
    hashes.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    (tmp_path / "target.txt.out").write_text("")
    wl = tmp_path / "wl.txt"
    wl.write_text("alpha\n")
    return {"hashes": str(hashes), "wl": str(wl), "tmp": tmp_path}


def _drive(m, env, fn, stop_after_first=False):
    calls = []

    def recorder(cmd, *args, coverage=None, **kwargs):
        calls.append((list(cmd), coverage))
        if stop_after_first:
            raise _Stop

    with (
        patch.object(m, "_run_hcat_cmd", side_effect=recorder),
        patch.object(m, "hcatBin", "hashcat"),
        patch.object(m, "hcatTuning", ""),
        patch.object(m, "hcatPotfilePath", ""),
        patch.object(m, "hcatWordlists", str(env["tmp"])),
        patch.object(m, "hcatHashCracked", 0),
        patch.object(m, "_optimized_kernel_disabled", True),
        patch.object(m, "generate_session_id", return_value="s"),
        patch.object(m, "hcatHybridMaxRuntime", 3600),
        patch.object(m, "maxruntime", 3600),
        patch.object(m, "bandrelbasewords", ""),
        patch.object(m, "pipal", return_value=[]),
        patch.object(m, "_run_hashcat_show"),
    ):
        try:
            fn()
        except _Stop:
            pass
    return calls


def test_detector_flags_the_forbidden_combination():
    bad = ["hashcat", "--runtime", "60", "-i", "?a?a"]
    assert _violations([(bad, object())]) == [bad]
    assert _violations([(bad, None)]) == []
    assert _violations([(["hashcat", "--runtime", "60"], object())]) == []
    assert _violations([(["hashcat", "--increment-max=4"], object())]) == []


def test_hybrid_never_pairs_runtime_with_increment(m, env):
    calls = _drive(m, env, lambda: m.hcatHybrid("1000", env["hashes"], [env["wl"]]))
    assert any("--runtime" in cmd for cmd, _ in calls)
    assert _violations(calls) == []


def test_bandrel_carries_runtime_and_increment_but_no_coverage(m, env):
    calls = _drive(m, env, lambda: m.hcatBandrel("1000", env["hashes"], "Acme"))
    assert calls
    assert any("--runtime" in c and _has_increment(c) for c, _ in calls)
    assert all(cov is None for _, cov in calls)
    assert _violations(calls) == []


def test_adhoc_mask_increment_carries_no_runtime_with_coverage(m, env):
    calls = _drive(
        m,
        env,
        lambda: m.hcatAdHocMask(
            "1000", env["hashes"], "?a?a?a", increment=True, increment_min="1"
        ),
    )
    assert calls
    assert _violations(calls) == []


def test_brute_force_and_markov_never_pair_runtime_with_increment(m, env):
    calls = _drive(m, env, lambda: m.hcatBruteForce("1000", env["hashes"], 1, 4))
    calls += _drive(m, env, lambda: m.hcatMarkovBruteForce("1000", env["hashes"], 1, 4))
    assert any(_has_increment(c) for c, _ in calls)
    assert _violations(calls) == []


def test_lm_phase_never_pairs_runtime_with_increment(m, env):
    calls = _drive(m, env, m.hcatLMtoNT, stop_after_first=True)
    assert any(_has_increment(c) for c, _ in calls)
    assert _violations(calls) == []
