"""Coverage must be scoped to the wordlist that was actually run.

Two defects motivated this file, both reachable from Quick Crack's default
answer at the wordlist prompt -- the *optimized wordlist directory*:

- ``_prime_coverage_decision`` asked the store only whether anything named
  "Quick Crack" had ever run against this hash file, ignoring the wordlists it
  was handed. Selecting a brand-new corpus therefore produced the "has run
  against this hash file before" prompt with nothing recorded that could
  possibly be skipped.
- A directory has no content fingerprint, so a directory-valued wordlist made
  every plan inert: nothing was recorded and nothing was ever filterable, yet
  the run still landed in the history table -- which is what kept the first
  defect firing forever.

The store and planner halves live here together with the wiring, because the
bug only appears when all three agree on the wordlist.
"""

import os

from unittest.mock import patch

import pytest

from hate_crack import attack_coverage as ac


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def store(tmp_path, monkeypatch):
    s = ac.CoverageStore(tmp_path / "cov.sqlite3")
    monkeypatch.setattr(ac, "get_store", lambda: s)
    yield s
    s.close()


@pytest.fixture
def env(tmp_path):
    hashes = tmp_path / "target.txt"
    hashes.write_text("aad3b435b51404eeaad3b435b51404ee\n")
    rules = tmp_path / "r.rule"
    rules.write_text("c\n$1\nu\n")
    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "a.txt").write_text("alpha\n")
    (lists / "b.txt").write_text("bravo\n")
    fresh = tmp_path / "fresh.txt"
    fresh.write_text("charlie\n")
    return {
        "hashes": str(hashes),
        "rules": str(rules),
        "lists": str(lists),
        "fresh": str(fresh),
        "tmp": tmp_path,
    }


class FakePopen:
    def __init__(self, cmd, returncode=1, **kwargs):
        self.cmd = list(cmd)
        self.pid = 4242
        self.returncode = returncode

    def wait(self):
        return self.returncode

    def kill(self):
        pass


# --- expanding a wordlist directory ---------------------------------------


def test_expand_turns_a_directory_into_the_files_hashcat_would_read(
    main_module, env, capsys
):
    expanded = main_module._expand_wordlist_dirs(env["lists"])
    assert expanded == [
        os.path.join(env["lists"], "a.txt"),
        os.path.join(env["lists"], "b.txt"),
    ]
    assert "2 wordlist" in capsys.readouterr().out


def test_expand_stops_at_one_level_like_hashcat_does(main_module, env):
    """Verified against hashcat 7.1.2: a straight (-a 0) run given a directory
    reads the files directly inside it and ignores subdirectories."""
    nested = os.path.join(env["lists"], "sub")
    os.mkdir(nested)
    with open(os.path.join(nested, "deep.txt"), "w") as handle:
        handle.write("delta\n")

    expanded = main_module._expand_wordlist_dirs(env["lists"])

    assert nested not in expanded
    assert not any("deep.txt" in path for path in expanded)


def test_expand_drops_archives_and_dot_files(main_module, env):
    """A Weakpass download leaves .7z and .torrent files in the wordlists
    directory. hashcat would try to read them as wordlists; we do not."""
    for name in ("wl.7z", "wl.torrent", ".DS_Store"):
        with open(os.path.join(env["lists"], name), "w") as handle:
            handle.write("x\n")

    expanded = main_module._expand_wordlist_dirs(env["lists"])

    assert [os.path.basename(path) for path in expanded] == ["a.txt", "b.txt"]


def test_expand_leaves_a_plain_file_alone(main_module, env, capsys):
    assert main_module._expand_wordlist_dirs(env["fresh"]) == [env["fresh"]]
    assert capsys.readouterr().out == "", "no notice when nothing expanded"


def test_expand_is_idempotent(main_module, env):
    once = main_module._expand_wordlist_dirs(env["lists"])
    assert main_module._expand_wordlist_dirs(once) == once


def test_expand_keeps_a_missing_path_so_hashcat_reports_it(main_module, env):
    """Not our error to swallow: hashcat's own message names the file, and
    dropping it here would silently shrink the attack instead.

    Scoped to a path that does not exist. A directory that exists but cannot be
    listed is a different case and is *not* kept -- ``_visible_entries`` says
    "permission denied" and yields nothing, so the path is dropped after being
    reported. That is why the empty-expansion guard below has to abort rather
    than launch."""
    missing = os.path.join(env["tmp"], "nope.txt")
    assert main_module._expand_wordlist_dirs(missing) == [missing]


def test_expand_reports_a_directory_holding_only_subdirectories(
    main_module, env, capsys
):
    empty = env["tmp"] / "onlysubs"
    empty.mkdir()
    (empty / "inner").mkdir()

    assert main_module._expand_wordlist_dirs(str(empty)) == []
    assert "No wordlists directly inside" in capsys.readouterr().out


# --- an expansion that comes back empty must abort, not launch ------------


@pytest.mark.parametrize(
    "shape",
    ["only-subdirectories", "only-archives", "empty"],
)
def test_quick_dictionary_aborts_when_the_expansion_is_empty(
    main_module, store, env, capsys, shape
):
    """Launching with no dictionary operand puts hashcat in *stdin mode*.

    Verified against hashcat 7.1.2: ``-a 0`` with no wordlist argument is the
    documented ``generator | hashcat`` path, not an error. _run_hcat_cmd passes
    ``stdin=None``, so the child would inherit the menu's terminal and sit
    consuming the operator's keystrokes -- then report Exhausted on ctrl-D,
    which is exit 1, which would record every rule line as covered by a run
    that enumerated nothing. hcatHybrid already guards this; this must too.
    """
    directory = env["tmp"] / f"empty-{shape}"
    directory.mkdir()
    if shape == "only-subdirectories":
        (directory / "inner").mkdir()
    elif shape == "only-archives":
        (directory / "wl.7z").write_text("x\n")
        (directory / ".gitkeep").write_text("")

    launched = []
    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: (launched.append(list(cmd)), FakePopen(cmd))[1],
        ),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
    ):
        main_module.hcatQuickDictionary(
            "1000",
            env["hashes"],
            f"-r {env['rules']}",
            str(directory),
            attack_name="Quick Crack",
        )

    assert launched == [], "hashcat must not launch without a dictionary operand"
    assert "No valid wordlists" in capsys.readouterr().out


def test_an_aborted_empty_expansion_records_no_coverage(main_module, store, env):
    """The second half of the same defect: a stdin-mode run that the operator
    ends with ctrl-D exits 1, and exit 1 is what records coverage."""
    directory = env["tmp"] / "onlysubs"
    directory.mkdir()
    (directory / "inner").mkdir()

    with (
        patch.object(main_module.subprocess, "Popen", lambda cmd, **kw: FakePopen(cmd)),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
    ):
        main_module.hcatQuickDictionary(
            "1000",
            env["hashes"],
            f"-r {env['rules']}",
            str(directory),
            attack_name="Quick Crack",
        )

    assert store.summary(ac.target_id(env["hashes"]))["runs"] == 0, (
        "a run that enumerated nothing must claim no ground and no history"
    )


# --- a directory-valued wordlist must still be tracked --------------------


def test_quick_dictionary_expands_a_directory_before_hashcat_sees_it(
    main_module, store, env
):
    launched = []
    with (
        patch.object(
            main_module.subprocess,
            "Popen",
            lambda cmd, **kw: (launched.append(list(cmd)), FakePopen(cmd))[1],
        ),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
    ):
        main_module.hcatQuickDictionary(
            "1000",
            env["hashes"],
            f"-r {env['rules']}",
            env["lists"],
            attack_name="Quick Crack",
        )

    assert env["lists"] not in launched[0], "the directory must not reach hashcat"
    assert os.path.join(env["lists"], "a.txt") in launched[0]
    assert os.path.join(env["lists"], "b.txt") in launched[0]


def test_a_directory_wordlist_run_is_recorded_not_inert(main_module, store, env):
    """The regression that made the prompt permanent: the plan went inert, so
    a repeat of the very same directory and rule file was never recognised."""
    with (
        patch.object(main_module.subprocess, "Popen", lambda cmd, **kw: FakePopen(cmd)),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
    ):
        main_module.hcatQuickDictionary(
            "1000",
            env["hashes"],
            f"-r {env['rules']}",
            env["lists"],
            attack_name="Quick Crack",
        )

    spec = ac.CoverageSpec(
        hash_file=env["hashes"],
        wordlists=tuple(main_module._expand_wordlist_dirs(env["lists"])),
        rule_files=(env["rules"],),
    )
    plan = ac.plan_run(spec, store.covered, store=store)
    assert plan.skip is True, "the same directory and rules is a full repeat"


# --- the store's wordlist-scoped prior-run question ----------------------


def test_has_prior_run_is_scoped_to_the_wordlists(store, env):
    target = ac.target_id(env["hashes"])
    fp_a = store.wordlist_fingerprint(os.path.join(env["lists"], "a.txt"))
    fp_fresh = store.wordlist_fingerprint(env["fresh"])

    store.record(["k1"], target=target, attack="Quick Crack", wordlist_fps=[fp_a])

    assert store.has_prior_run(target, "Quick Crack", [fp_a]) is True
    assert store.has_prior_run(target, "Quick Crack", [fp_fresh]) is False
    assert store.has_prior_run(target, "Dictionary", [fp_a]) is False
    assert store.has_prior_run("other-target", "Quick Crack", [fp_a]) is False


def test_has_prior_run_matches_any_one_of_several_wordlists(store, env):
    """One overlapping corpus is enough for filtering to have something to do,
    so the question is "any", not "all"."""
    target = ac.target_id(env["hashes"])
    fp_a = store.wordlist_fingerprint(os.path.join(env["lists"], "a.txt"))
    fp_fresh = store.wordlist_fingerprint(env["fresh"])

    store.record(["k1"], target=target, attack="Quick Crack", wordlist_fps=[fp_a])

    assert store.has_prior_run(target, "Quick Crack", [fp_fresh, fp_a]) is True


def test_has_prior_run_falls_back_to_the_attack_name_without_wordlists(store, env):
    """A mask-only attack has no wordlist to scope by; the older, coarser
    question is the only one available and stays available."""
    target = ac.target_id(env["hashes"])
    store.log_run(target, attack="Top Mask")

    assert store.has_prior_run(target, "Top Mask", []) is True
    assert store.has_prior_run(target, "Quick Crack", []) is False


def test_has_prior_run_survives_a_pre_existing_store(tmp_path, env):
    """An existing engagement's database predates run_wordlists. It must open,
    gain the table, and answer "no" rather than raising or prompting."""
    path = tmp_path / "old.sqlite3"
    old = ac.CoverageStore(path)
    target = ac.target_id(env["hashes"])
    old.log_run(target, attack="Quick Crack", kind="history")
    old.close()

    new = ac.CoverageStore(path)
    fp = new.wordlist_fingerprint(env["fresh"])
    try:
        assert new.has_prior_run(target, "Quick Crack", [fp]) is False
    finally:
        new.close()


# --- the up-front batch prompt -------------------------------------------


def _prior_quick_crack(main_module, env, wordlists):
    with (
        patch.object(main_module.subprocess, "Popen", lambda cmd, **kw: FakePopen(cmd)),
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
    ):
        main_module.hcatQuickDictionary(
            "1000",
            env["hashes"],
            f"-r {env['rules']}",
            wordlists,
            attack_name="Quick Crack",
        )


def test_prime_does_not_prompt_for_a_wordlist_never_used_before(
    main_module, store, env
):
    """The reported bug: a new wordlist with previously-used rules was flagged
    because the prompt keyed on the attack name alone."""
    _prior_quick_crack(main_module, env, env["lists"])

    def refuse(*a, **kw):
        raise AssertionError("prompted about a wordlist that has never run")

    with (
        patch.object(main_module, "_coverage_enabled", True),
        patch("builtins.input", refuse),
    ):
        decision = main_module._prime_coverage_decision(
            env["hashes"], [f"-r {env['rules']}"], [env["fresh"]], "Quick Crack"
        )

    assert decision == {}


def test_prime_still_prompts_for_a_wordlist_that_has_run_before(
    main_module, store, env, capsys
):
    _prior_quick_crack(main_module, env, env["lists"])

    expanded = main_module._expand_wordlist_dirs(env["lists"])
    with (
        patch.object(main_module, "_coverage_enabled", True),
        patch("builtins.input", lambda *a: "y"),
    ):
        decision = main_module._prime_coverage_decision(
            env["hashes"], [f"-r {env['rules']}"], expanded, "Quick Crack"
        )

    assert decision.get("apply_filtering") is True
    assert "has run against this hash file before" in capsys.readouterr().out


def test_prime_stays_quiet_when_no_wordlist_can_be_fingerprinted(
    main_module, store, env
):
    """Nothing here can be fingerprinted, so every chain's plan will be inert
    and no filtering is possible. Asking anyway is the noise that made this
    prompt appear on every single run."""
    _prior_quick_crack(main_module, env, env["lists"])
    missing = str(env["tmp"] / "vanished.txt")

    def refuse(*a, **kw):
        raise AssertionError("prompted when no filtering is possible")

    with (
        patch.object(main_module, "_coverage_enabled", True),
        patch("builtins.input", refuse),
    ):
        decision = main_module._prime_coverage_decision(
            env["hashes"], [f"-r {env['rules']}"], [missing], "Quick Crack"
        )

    assert decision == {}


def test_prime_stays_quiet_when_the_selection_expands_to_nothing(
    main_module, store, env
):
    """The empty-selection sibling of the case above. Guarding on the expansion
    rather than on the argument let this short-circuit straight into
    has_prior_run's attack-name-only fallback -- the exact coarse question this
    fix exists to remove."""
    _prior_quick_crack(main_module, env, env["lists"])
    directory = env["tmp"] / "expands-to-nothing"
    directory.mkdir()
    (directory / "inner").mkdir()

    def refuse(*a, **kw):
        raise AssertionError("prompted on the attack name alone")

    with (
        patch.object(main_module, "_coverage_enabled", True),
        patch("builtins.input", refuse),
    ):
        decision = main_module._prime_coverage_decision(
            env["hashes"], [f"-r {env['rules']}"], str(directory), "Quick Crack"
        )

    assert decision == {}


def test_prime_does_not_diff_a_rule_file_to_answer(main_module, store, env):
    """Unchanged from before: the whole point of priming is that it decides
    without reading or hashing any selected rule file."""
    _prior_quick_crack(main_module, env, env["lists"])
    expanded = main_module._expand_wordlist_dirs(env["lists"])

    read = []
    real_read_entries = ac.read_entries

    with (
        patch.object(main_module, "_coverage_enabled", True),
        patch.object(
            main_module._coverage,
            "read_entries",
            lambda path: (read.append(path), real_read_entries(path))[1],
        ),
        patch("builtins.input", lambda *a: "y"),
    ):
        main_module._prime_coverage_decision(
            env["hashes"], [f"-r {env['rules']}"], expanded, "Quick Crack"
        )

    assert read == [], "priming must not read any rule file"
