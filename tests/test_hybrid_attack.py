"""Tests for main.hcatHybrid -- menu option 7.

The handler layer (attacks.hybrid_crack, wordlist selection) is covered in
test_attacks_behavior.py::TestHybridCrack. What is pinned here is the driver
itself: the mask/mode matrix it builds, ctrl-C teardown, glob expansion, and
the coverage spec each pass declares.
"""

import re
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
def _patched(main_module, tmp_path, max_runtime=0):
    """Patch the module globals hcatHybrid reads.

    ``patch.object`` rather than raw assignment: ``hate_crack.main`` is shared
    across the session, so anything set here has to be restored afterwards.

    ``generate_session_id`` is stubbed so the asserted commands carry one fixed
    session name; what it builds from the hash file and attack label is covered
    in test_main_utils.py::TestGenerateSessionId.

    ``max_runtime`` defaults to 0, which is "no time limit": every pass runs
    and none carries a ``--runtime``, which is what the structural assertions
    below want. TestTimeBudget sets a budget.
    """
    with (
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "hcatWordlists", str(tmp_path)),
        patch.object(main_module, "hcatHashCracked", 0),
        patch.object(main_module, "_optimized_kernel_disabled", True),
        patch.object(main_module, "generate_session_id", return_value="test_session"),
        patch.object(main_module, "hcatHybridMaxRuntime", max_runtime),
    ):
        yield


def _fixed(runner):
    """Just the ?s?d passes."""
    return [p for p in _passes(runner) if "?1" in p[1]]


def _sweep(runner):
    """Just the ?a passes."""
    return [p for p in _passes(runner) if "?a" in p[1]]


def _passes(runner):
    """The (mode, mask, wordlist) triples handed to hashcat, in order.

    The mask is located by shape rather than by position: a ?1 pass carries a
    ``-1`` charset definition and a sweep pass does not, so counting from a
    fixed flag would only work for one of them. Its neighbour is the wordlist --
    mask-last for mode 6, mask-first for mode 7.
    """
    triples = []
    for call in runner.call_args_list:
        cmd = call[0][0]
        mode = cmd[cmd.index("-a") + 1]
        index = next(
            i for i, arg in enumerate(cmd) if re.fullmatch(r"(\?[1a])+", str(arg))
        )
        mask = cmd[index]
        wordlist = cmd[index - 1] if mode == "6" else cmd[index + 1]
        triples.append((mode, mask, wordlist))
    return triples


def _runtimes(runner):
    """The --runtime value of each pass, None where the flag is absent."""
    values = []
    for call in runner.call_args_list:
        cmd = call[0][0]
        values.append(
            int(cmd[cmd.index("--runtime") + 1]) if "--runtime" in cmd else None
        )
    return values


class TestMaskMatrix:
    def test_runs_lengths_one_to_four_appended_then_prepended(self, main_module, env):
        """Eight passes per wordlist: -a 6 then -a 7, each over ?1 to ?1?1?1?1."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        wl = env["wordlist"]
        # Length-major, both directions per length -- the order the shared
        # budget needs (see _hybrid_passes).
        assert _fixed(runner) == [
            ("6", "?1", wl),
            ("7", "?1", wl),
            ("6", "?1?1", wl),
            ("7", "?1?1", wl),
            ("6", "?1?1?1", wl),
            ("7", "?1?1?1", wl),
            ("6", "?1?1?1?1", wl),
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

    def test_charset_is_declared_for_every_slot_pass(self, main_module, env):
        """?1 means nothing to hashcat without its -1 definition."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        checked = 0
        for call in runner.call_args_list:
            cmd = call[0][0]
            if not any(re.fullmatch(r"(\?1)+", str(arg)) for arg in cmd):
                continue
            checked += 1
            assert cmd[cmd.index("-1") + 1] == "?s?d"
        assert checked == 8


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

        assert runner.call_count == 16

    def test_directory_expands_to_the_files_inside(self, main_module, env):
        """hashcat takes a directory in the dictionary position, but expanding
        it here is what keeps one coverage key per wordlist file."""
        collection = env["tmp"] / "collection"
        collection.mkdir()
        for name in ("one.txt", "two.txt"):
            (collection / name).write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection)])

        used = {wordlist for _, _, wordlist in _passes(runner)}
        assert used == {
            str(collection / "one.txt"),
            str(collection / "two.txt"),
        }
        # Every expanded file gets the whole matrix, not one pass apiece.
        assert runner.call_count == 32

    def test_directory_is_expanded_one_level_like_hashcat(self, main_module, env):
        """hashcat does not descend into subdirectories, so neither do we."""
        collection = env["tmp"] / "collection"
        (collection / "nested").mkdir(parents=True)
        (collection / "top.txt").write_text("word\n")
        (collection / "nested" / "deep.txt").write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection)])

        used = {wordlist for _, _, wordlist in _passes(runner)}
        assert used == {str(collection / "top.txt")}

    def test_directory_named_by_its_relative_name_resolves(self, main_module, env):
        """A directory under the wordlists dir is named the way a file is."""
        collection = env["tmp"] / "collection"
        collection.mkdir()
        (collection / "one.txt").write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], ["collection"])

        used = {wordlist for _, _, wordlist in _passes(runner)}
        assert used == {str(collection / "one.txt")}

    def test_a_glob_matching_a_directory_expands_it_too(self, main_module, env):
        """A directory reached by pattern must not stay a directory: hashcat
        would read it, but the coverage store cannot fingerprint one, so those
        passes would be recorded nowhere and never skipped on a repeat."""
        collections = env["tmp"] / "collections"
        (collections / "corp").mkdir(parents=True)
        (collections / "corp" / "one.txt").write_text("word\n")
        (collections / "loose.txt").write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collections / "*")])

        used = {wordlist for _, _, wordlist in _passes(runner)}
        assert used == {
            str(collections / "corp" / "one.txt"),
            str(collections / "loose.txt"),
        }

    def test_archives_and_dot_files_in_a_directory_are_skipped(self, main_module, env):
        """A Weakpass download leaves .7z and .torrent next to the wordlists."""
        collection = env["tmp"] / "collection"
        collection.mkdir()
        (collection / "one.txt").write_text("word\n")
        for name in ("big.7z", "big.torrent", "cracked.out", ".DS_Store"):
            (collection / name).write_text("not a wordlist\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection)])

        used = {wordlist for _, _, wordlist in _passes(runner)}
        assert used == {str(collection / "one.txt")}

    def test_expansion_announces_how_many_passes_it_became(
        self, main_module, env, capsys
    ):
        """One selected entry can be hundreds of lists, and the whole matrix
        runs against each: a different order of magnitude from the count the
        handler announced before expansion. The total is counted off the pass
        generator, so it tracks the matrix rather than a hardcoded multiple."""
        collection = env["tmp"] / "collection"
        collection.mkdir()
        for name in ("one.txt", "two.txt", "three.txt"):
            (collection / name).write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection)])

        out = capsys.readouterr().out
        assert f"3 wordlist(s): {runner.call_count} passes." in out

    def test_a_single_file_is_not_announced_as_an_expansion(
        self, main_module, env, capsys
    ):
        """Nothing expanded, so there is nothing to warn about."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd"),
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert "expanded to" not in capsys.readouterr().out

    def test_a_directory_and_a_file_inside_it_run_once(self, main_module, env):
        """The dedupe has to survive expansion, or the overlap runs twice."""
        collection = env["tmp"] / "collection"
        collection.mkdir()
        inner = collection / "one.txt"
        inner.write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection), str(inner)])

        assert runner.call_count == 16

    def test_empty_directory_aborts_and_says_which_one(self, main_module, env, capsys):
        collection = env["tmp"] / "empty"
        collection.mkdir()

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection)])

        runner.assert_not_called()
        out = capsys.readouterr().out
        assert "No wordlists directly inside" in out
        assert str(collection) in out

    def test_a_directory_of_only_subdirectories_says_why_it_is_unusable(
        self, main_module, env, capsys
    ):
        """ "Empty" would be a lie -- the wordlists are one level too deep."""
        collection = env["tmp"] / "nested_only"
        (collection / "inner").mkdir(parents=True)
        (collection / "inner" / "one.txt").write_text("word\n")

        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [str(collection)])

        runner.assert_not_called()
        assert "subdirectories are not searched" in capsys.readouterr().out

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

        assert main_module.hcatHybridCount == 16


class TestCoverageSpec:
    def test_every_pass_declares_its_wordlist_and_mask(self, main_module, env):
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        specs = [call.kwargs["coverage"] for call in runner.call_args_list]
        assert len(specs) == 16
        for spec in specs:
            assert spec.wordlists == (env["wordlist"],)
            assert spec.hash_file == env["hashes"]
            assert len(spec.masks) == 1

    def test_mask_carries_its_custom_charset_definition(self, main_module, env):
        """A bare ?1?1 key would collide with any other -1 spelling."""
        spec = main_module._hybrid_coverage(
            env["hashes"], env["wordlist"], "6", "?1?1", "?s?d"
        )

        assert spec.masks == ("?s?d,?1?1",)

    def test_a_builtin_charset_mask_is_keyed_as_written(self, main_module, env):
        """?a needs no -1, so there is nothing to prefix and no ambiguity."""
        spec = main_module._hybrid_coverage(env["hashes"], env["wordlist"], "6", "?a?a")

        assert spec.masks == ("?a?a",)

    def test_the_two_charsets_do_not_share_a_key(self, main_module, env):
        """?1?1 over ?s?d and ?a?a are different candidate sets."""
        target = ac.target_id(env["hashes"])
        assert target is not None
        keys = set()
        for mask, charset in (("?1?1", "?s?d"), ("?a?a", "")):
            spec = main_module._hybrid_coverage(
                env["hashes"], env["wordlist"], "6", mask, charset
            )
            keys.add(ac.entry_key(target, "mask", "fp", spec.masks[0], spec.variant))
        assert len(keys) == 2

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


class TestFullCharsetSweep:
    """The ?a passes that follow the ?s?d ones."""

    def test_sweep_runs_each_length_in_both_directions(self, main_module, env):
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        wl = env["wordlist"]
        assert _sweep(runner) == [
            ("6", "?a", wl),
            ("7", "?a", wl),
            ("6", "?a?a", wl),
            ("7", "?a?a", wl),
            ("6", "?a?a?a", wl),
            ("7", "?a?a?a", wl),
            ("6", "?a?a?a?a", wl),
            ("7", "?a?a?a?a", wl),
        ]

    def test_sweep_runs_after_the_cheap_fixed_length_passes(self, main_module, env):
        """?a is a superset of ?s?d, so the cheap subset should crack first."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        masks = [mask for _, mask, _ in _passes(runner)]
        assert masks.index("?a") > masks.index("?1?1?1?1")

    def test_sweep_carries_no_custom_charset(self, main_module, env):
        """?a is a hashcat builtin; a -1 definition would be meaningless."""
        with (
            _patched(main_module, env["tmp"]),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        checked = 0
        for call in runner.call_args_list:
            cmd = call[0][0]
            if not any(re.fullmatch(r"(\?a)+", str(arg)) for arg in cmd):
                continue
            checked += 1
            assert "-1" not in cmd
        assert checked == 8


class TestTimeBudget:
    """hcatHybridMaxRuntime bounds the attack, not one pass of it."""

    def test_zero_means_no_limit_and_says_nothing(self, main_module, env, capsys):
        with (
            _patched(main_module, env["tmp"], max_runtime=0),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert len(_passes(runner)) == 16
        assert _runtimes(runner) == [None] * 16
        out = capsys.readouterr().out
        assert "budget" not in out.lower()

    def test_every_pass_is_capped_when_a_budget_is_set(self, main_module, env):
        """Including the ?s?d passes: the budget is the attack's, not the
        sweep's, and a length-4 ?s?d pass over a big list is not cheap either."""
        with (
            _patched(main_module, env["tmp"], max_runtime=3600),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        runtimes = _runtimes(runner)
        assert len(runtimes) == 16
        assert all(rt is not None for rt in runtimes)

    def test_each_pass_gets_what_remains_rather_than_the_full_cap(
        self, main_module, env
    ):
        """hashcat applies --runtime per invocation, so handing every pass the
        configured value would multiply the cap by sixteen."""
        clock = iter([1000.0] + [1000.0 + 100 * n for n in range(1, 40)])

        with (
            _patched(main_module, env["tmp"], max_runtime=500),
            patch.object(main_module.time, "monotonic", lambda: next(clock)),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert _runtimes(runner) == [400, 300, 200, 100]

    def test_the_budget_covers_the_whole_attack_not_each_pass(self, main_module, env):
        """The regression this replaces: sixteen passes each given the full
        3600s would have been a sixteen-hour "one hour" cap."""
        clock = iter([0.0] + [float(n) for n in range(1, 60)])

        with (
            _patched(main_module, env["tmp"], max_runtime=10),
            patch.object(main_module.time, "monotonic", lambda: next(clock)),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert sum(_runtimes(runner)) <= 10 * len(_runtimes(runner))
        assert max(_runtimes(runner)) <= 10

    def test_never_emits_runtime_zero(self, main_module, env):
        """hashcat rejects `--runtime 0` ("Invalid --runtime value specified",
        exit 255), so a budget rounding down to zero must skip the pass rather
        than pass the value through and fail it."""
        # Leaves 0.5s at the third pass, which truncates to 0.
        clock = iter([0.0, 0.1, 0.2, 4.5] + [4.6] * 40)

        with (
            _patched(main_module, env["tmp"], max_runtime=5),
            patch.object(main_module.time, "monotonic", lambda: next(clock)),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert _runtimes(runner) == [4, 4]
        for call in runner.call_args_list:
            cmd = call[0][0]
            assert "0" not in cmd[cmd.index("--runtime") + 1]

    def test_budget_exhaustion_stops_the_attack_and_says_so(
        self, main_module, env, capsys
    ):
        clock = iter([1000.0] + [9999.0] * 40)

        with (
            _patched(main_module, env["tmp"], max_runtime=60),
            patch.object(main_module.time, "monotonic", lambda: next(clock)),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert runner.call_count == 0
        out = capsys.readouterr().out
        assert "16 pass(es) not run" in out
        assert "hcatHybridMaxRuntime" in out

    def test_the_cheapest_passes_are_the_ones_that_survive_a_small_budget(
        self, main_module, env
    ):
        """A budget that only covers three passes should have spent them on the
        shortest masks, not on whatever happened to be first."""
        clock = iter([0.0, 1.0, 2.0, 3.0] + [999.0] * 40)

        with (
            _patched(main_module, env["tmp"], max_runtime=10),
            patch.object(main_module.time, "monotonic", lambda: next(clock)),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])

        assert [mask for _, mask, _ in _passes(runner)] == ["?1", "?1", "?1?1"]

    def test_length_major_order_so_a_shared_budget_reaches_every_wordlist(
        self, main_module, env
    ):
        """Length 4 over the first list would otherwise eat the whole hour."""
        second = env["tmp"] / "wl2.txt"
        second.write_text("charlie\n")

        with (
            _patched(main_module, env["tmp"], max_runtime=3600),
            patch.object(main_module, "_run_hcat_cmd") as runner,
        ):
            main_module.hcatHybrid(
                "1000", env["hashes"], [env["wordlist"], str(second)]
            )

        fixed = _fixed(runner)
        first_long = next(i for i, p in enumerate(fixed) if p[1] != "?1")
        assert {p[2] for p in fixed[:first_long]} == {env["wordlist"], str(second)}

    def test_a_truncated_pass_records_no_coverage(
        self, main_module, env, tmp_path, monkeypatch
    ):
        """hashcat exits 4 when --runtime cuts a mask short, and only exit 1
        may be recorded -- otherwise the store would claim ground never tried."""
        store = ac.CoverageStore(tmp_path / "cov.sqlite3")
        monkeypatch.setattr(ac, "get_store", lambda: store)

        class RuntimeAbortedPopen:
            def __init__(self, cmd, **kwargs):
                self.pid = 4242
                self.returncode = 4

            def wait(self):
                return 4

            def kill(self):
                pass

        try:
            with (
                _patched(main_module, env["tmp"], max_runtime=3600),
                patch("hate_crack.main.subprocess.Popen", RuntimeAbortedPopen),
            ):
                main_module.hcatHybrid("1000", env["hashes"], [env["wordlist"]])
            target = ac.target_id(env["hashes"])
            spec = main_module._hybrid_coverage(
                env["hashes"], env["wordlist"], "6", "?a?a?a?a"
            )
            key = ac.entry_key(
                target,
                "mask",
                store.wordlist_fingerprint(env["wordlist"]),
                spec.masks[0],
                spec.variant,
            )
            assert store.covered([key]) == set()
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

    assert runner.call_count == 16
    assert {wordlist for _, _, wordlist in _passes(runner)} == {str(expanded)}
