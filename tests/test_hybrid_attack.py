"""Tests for main.hcatHybrid -- menu option 7.

The handler layer (attacks.hybrid_crack, wordlist selection) is covered in
test_attacks_behavior.py::TestHybridCrack. What is pinned here is the driver
itself: the mask/mode matrix it builds, ctrl-C teardown, glob expansion, and
the coverage spec each pass declares.
"""

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


@pytest.fixture
def env(tmp_path):
    hashes = tmp_path / "target.txt"
    hashes.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    (tmp_path / "target.txt.out").write_text("")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text("alpha\nbravo\n")
    return {
        "hashes": str(hashes),
        "wordlist": str(wordlist),
        "tmp": tmp_path,
    }


@contextmanager
def _patched(main_module, tmp_path):
    """Patch the module globals hcatHybrid reads.

    ``patch.object`` rather than raw assignment: ``hate_crack.main`` is shared
    across the session, so anything set here has to be restored afterwards.

    ``generate_session_id`` is stubbed because it reads the *module-global*
    ``hcatHashFile`` rather than the argument hcatHybrid was called with, so it
    otherwise depends on whatever an earlier test left there.
    """
    with (
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "hcatWordlists", str(tmp_path)),
        patch.object(main_module, "hcatHashCracked", 0),
        patch.object(main_module, "_optimized_kernel_disabled", True),
        patch.object(main_module, "generate_session_id", return_value="test_session"),
    ):
        yield


def _passes(runner):
    """The (mode, mask, wordlist) triples handed to hashcat, in order."""
    triples = []
    for call in runner.call_args_list:
        cmd = call[0][0]
        mode = cmd[cmd.index("-a") + 1]
        # ``-1 <charset>`` is followed by the two positionals, mask-last for
        # mode 6 and mask-first for mode 7.
        left, right = cmd[cmd.index("-1") + 2 : cmd.index("-1") + 4]
        mask, wordlist = (right, left) if mode == "6" else (left, right)
        triples.append((mode, mask, wordlist))
    return triples


class TestMaskMatrix:
    def test_runs_lengths_one_to_four_appended_then_prepended(self, main_module, env):
        """Eight passes per wordlist: -a 6 then -a 7, each over ?1 to ?1?1?1?1."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        wl = env["wordlist"]
        assert _passes(runner) == [
            ("6", "?1", wl),
            ("6", "?1?1", wl),
            ("6", "?1?1?1", wl),
            ("6", "?1?1?1?1", wl),
            ("7", "?1", wl),
            ("7", "?1?1", wl),
            ("7", "?1?1?1", wl),
            ("7", "?1?1?1?1", wl),
        ]

    def test_single_character_mask_is_included(self, main_module, env):
        """A one-position mask is the cheapest pass and must not be skipped."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        masks = {mask for _, mask, _ in _passes(runner)}
        assert "?1" in masks

    def test_charset_is_declared_for_every_pass(self, main_module, env):
        """?1 means nothing to hashcat without its -1 definition."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        for call in runner.call_args_list:
            cmd = call[0][0]
            assert cmd[cmd.index("-1") + 1] == "?s?d"


class TestInterrupt:
    def test_first_interrupt_abandons_the_whole_attack(self, main_module, env):
        """One ctrl-C ends hybrid -- not just the pass that was running."""
        runner = MagicMock(side_effect=KeyboardInterrupt)

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd", runner),
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert runner.call_count == 1

    def test_every_pass_asks_for_the_interrupt_to_propagate(self, main_module, env):
        """Without reraise_interrupt the funnel swallows ctrl-C and loops on."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert runner.call_args_list
        for call in runner.call_args_list:
            assert call.kwargs["reraise_interrupt"] is True

    def test_interrupt_through_the_real_funnel_stops_after_one_pass(
        self, main_module, env, tmp_path, monkeypatch
    ):
        """End-to-end: a killed hashcat tears down hybrid, not just the pass.

        Goes through the real _run_hcat_cmd rather than a mock, so the test
        fails if either hcatHybrid stops asking for the re-raise or the funnel
        stops honouring it.
        """
        store = ac.CoverageStore(tmp_path / "cov.sqlite3")
        monkeypatch.setattr(ac, "get_store", lambda: store)

        class InterruptingPopen:
            calls = 0

            def __init__(self, cmd, **kwargs):
                type(self).calls += 1
                self.pid = 4242
                self.returncode = 1

            def wait(self):
                raise KeyboardInterrupt

            def kill(self):
                pass

        try:
            with (
                _patched(main_module, env["tmp"]),
                patch("hate_crack.main.subprocess.Popen", InterruptingPopen),
            ):
                main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])
        finally:
            store.close()

        assert InterruptingPopen.calls == 1


class TestWordlistResolution:
    def test_glob_pattern_expands_to_matching_files(self, main_module, env):
        """A pattern reaches Popen as a list with no shell, so we expand it."""
        for name in ("a_one.txt", "a_two.txt"):
            (env["tmp"] / name).write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], ["a_*.txt"])

        used = {wordlist for _, _, wordlist in _passes(runner)}
        assert used == {
            str(env["tmp"] / "a_one.txt"),
            str(env["tmp"] / "a_two.txt"),
        }
        assert not any("*" in wordlist for wordlist in used)

    def test_glob_matching_nothing_aborts(self, main_module, env, capsys):
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], ["nothing_*.txt"])

        runner.assert_not_called()
        assert "matched nothing" in capsys.readouterr().out

    def test_duplicate_wordlists_run_once(self, main_module, env):
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid(
                "1000", env["hashes"], [env["wordlist"], env["wordlist"]]
            )

        assert runner.call_count == 8

    def test_missing_wordlist_aborts(self, main_module, env, capsys):
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], ["absent.txt"])

        runner.assert_not_called()
        assert "No valid wordlists found" in capsys.readouterr().out


class TestHybridCount:
    def test_abort_resets_the_count_instead_of_keeping_a_stale_one(
        self, main_module, env
    ):
        """extensive_crack feeds this straight to hcatRecycle."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "hcatHybridCount", 41),
            patch.object(main_module, "_run_hcat_cmd"),
        ):
            main_module.hcatHybrid("1000", env["hashes"], ["absent.txt"])
            assert main_module.hcatHybridCount == 0

    def test_count_is_the_delta_of_newly_cracked_lines(self, main_module, env):
        out_path = env["hashes"] + ".out"

        def crack_two(cmd, **kwargs):
            with open(out_path, "a") as handle:
                handle.write("hash:plain\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd", side_effect=crack_two),
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert main_module.hcatHybridCount == 8


class TestCoverageSpec:
    def test_every_pass_declares_its_wordlist_and_mask(self, main_module, env):
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        specs = [call.kwargs["coverage"] for call in runner.call_args_list]
        assert len(specs) == 8
        for spec in specs:
            assert spec.wordlists == (env["wordlist"],)
            assert spec.hash_file == env["hashes"]
            assert len(spec.masks) == 1

    def test_mask_carries_its_custom_charset_definition(self, main_module, env):
        """A bare ?1?1 key would collide with any other -1 spelling."""
        spec = main_module._hybrid_coverage(env["hashes"], env["wordlist"], "6", "?1?1")

        assert spec.masks == ("?s?d,?1?1",)

    def test_append_and_prepend_do_not_share_a_key(self, main_module, env):
        """Mode 6 and mode 7 enumerate disjoint candidate sets."""
        append = main_module._hybrid_coverage(
            env["hashes"], env["wordlist"], "6", "?1?1"
        )
        prepend = main_module._hybrid_coverage(
            env["hashes"], env["wordlist"], "7", "?1?1"
        )

        assert append.variant != prepend.variant
        target = ac.target_id(env["hashes"])
        assert target is not None
        keys = {
            ac.entry_key(target, "mask", "fp", spec.masks[0], spec.variant)
            for spec in (append, prepend)
        }
        assert len(keys) == 2

    def test_a_repeat_run_is_recognised_as_covered(
        self, main_module, env, tmp_path, monkeypatch
    ):
        """The whole point: the second hybrid over the same target is a repeat."""
        store = ac.CoverageStore(tmp_path / "cov.sqlite3")
        monkeypatch.setattr(ac, "get_store", lambda: store)
        try:
            spec = main_module._hybrid_coverage(
                env["hashes"], env["wordlist"], "6", "?1?1"
            )
            first = ac.plan_run(spec, ac.set_lookup(set()), store=store)
            assert not first.is_inert
            assert not first.skip

            store.record(
                first.record_keys,
                target=first.target,
                kind=first.kind,
                attack="Hybrid",
            )
            covered = store.covered(first.record_keys)
            second = ac.plan_run(spec, ac.set_lookup(covered), store=store)
            assert second.skip
        finally:
            store.close()


def test_expanded_fingerprint_candidates_still_reach_hybrid(main_module, env):
    """hcatFingerprint passes a generated file; it must survive resolution."""
    expanded = env["tmp"] / "expanded.txt"
    expanded.write_text("candidate\n")

    with (
        _patched(main_module, env["tmp"]),
        patch.object(main_module, "_run_hcat_cmd") as runner,
    ):
        main_module.hcatHybrid("1000", env["hashes"], [str(expanded)])

    assert runner.call_count == 8
    assert {wordlist for _, _, wordlist in _passes(runner)} == {str(expanded)}
