import ast
import glob
import json
import os
import re

import pytest

from hate_crack.config_schema import ENV_KEYS
from tests._json_strict import DuplicateJSONKeyError, load_strict, loads_strict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_EXAMPLE = os.path.join(REPO_ROOT, "config.json.example")
PACKAGED_EXAMPLE = os.path.join(REPO_ROOT, "hate_crack", "config.json.example")

# Source of truth for config.json.example's key set: the 35 home="json" keys.
# The twelve home="env" integration keys are deliberately absent -- they live
# in `.env`, and the loader ignores them here (with a warning). Update this set
# whenever a config key is added, removed, or changes home — it's what would
# have caught the #150 drift (10 missing keys, 4 dead passgpt* keys shipped in
# a prior release) regardless of whether the packaged copy is a symlink, a
# dereferenced regular file (wheel/sdist builds), or a flattened copy
# (git-archive tarball, docker COPY of hate_crack/ alone).
EXPECTED_KEYS = {
    "hcatPath",
    "hcatBin",
    "hcatTuning",
    "hcatPotfilePath",
    "hcatDebugLogPath",
    "hcatWordlists",
    "hcatOptimizedWordlists",
    "rules_directory",
    "hcatDictionaryWordlist",
    "hcatCombinationWordlist",
    "hcatHybridlist",
    "hcatMiddleCombinatorMasks",
    "hcatMiddleBaseList",
    "hcatThoroughCombinatorMasks",
    "hcatThoroughBaseList",
    "hcatGoodMeasureBaseList",
    "hcatPrinceBaseList",
    "bandrelmaxruntime",
    "bandrel_common_basedwords",
    "hcatCorpusProfileMaxLines",
    "omenMaxCandidates",
    "pcfgRuleset",
    "pcfgMaxCandidates",
    "pcfgPrinceLingMaxCandidates",
    "check_for_updates",
    "optimizedKernelAttacks",
    "notify_enabled",
    "notify_per_crack_enabled",
    "notify_attack_allowlist",
    "notify_suppress_in_orchestrators",
    "notify_max_cracks_per_burst",
    "notify_poll_interval_seconds",
    "debug",
    "weakpass_min_rank",
    "update_channel",
    "restore_potfile_on_start",
    "rule_debug_mode_enabled",
}


def test_root_example_has_expected_keys():
    with open(ROOT_EXAMPLE) as f:
        root_config = json.load(f)
    assert set(root_config.keys()) == EXPECTED_KEYS


def test_packaged_example_matches_root_content():
    """The invariant that matters is content parity, not symlink-ness.

    In the source tree hate_crack/config.json.example is a symlink to the
    root copy (same inode) — comparing it to itself here is a no-op, and
    test_root_example_has_expected_keys is the substantive check for that
    environment. In any tree where the packaged copy is a distinct file
    (built wheel/sdist, git-archive tarball, docker COPY of hate_crack/
    alone) this comparison is the one that would actually catch drift.
    """
    if os.path.realpath(PACKAGED_EXAMPLE) == os.path.realpath(ROOT_EXAMPLE):
        return
    with open(ROOT_EXAMPLE) as f:
        root_config = json.load(f)
    with open(PACKAGED_EXAMPLE) as f:
        packaged_config = json.load(f)
    assert packaged_config == root_config


def test_optimized_kernel_attacks_matches_code_default(hc_module):
    """A user with no config.json must get the same -O behaviour as one who
    copied the example verbatim.

    These two lists drifted once already: the example shipped hcatPCFG while
    DEFAULT_OPTIMIZED_ATTACKS omitted it, so the same attack ran with -O or
    without depending only on whether a config file existed.
    """
    with open(ROOT_EXAMPLE) as f:
        example_attacks = set(json.load(f)["optimizedKernelAttacks"])
    assert example_attacks == set(hc_module.DEFAULT_OPTIMIZED_ATTACKS)


def _checked_attack_names():
    """Names actually passed to _should_use_optimized_kernel in main.py."""
    with open(os.path.join(REPO_ROOT, "hate_crack", "main.py")) as f:
        source = f.read()
    return set(re.findall(r'_should_use_optimized_kernel\("([A-Za-z0-9]+)"\)', source))


def test_every_recognized_attack_name_is_checked(hc_module):
    """No inert knobs: a recognized name must reach a real -O decision.

    hcatPrinceLing was recognized but never checked — PRINCE-LING delegates to
    hcatPrince, which tests its own name — so setting it did nothing at all.
    """
    assert set(hc_module.KNOWN_OPTIMIZABLE_ATTACKS) <= _checked_attack_names()


def test_every_checked_attack_name_is_recognized(hc_module):
    """No unreachable knobs: an attack that consults the setting must be a name
    the user can actually put in optimizedKernelAttacks."""
    assert _checked_attack_names() <= set(hc_module.KNOWN_OPTIMIZABLE_ATTACKS)


def test_default_optimized_attacks_are_recognized(hc_module):
    assert set(hc_module.DEFAULT_OPTIMIZED_ATTACKS) <= set(
        hc_module.KNOWN_OPTIMIZABLE_ATTACKS
    )


# ---------------------------------------------------------------------------
# Every documented config key must have a read site.
#
# EXPECTED_KEYS above pins the key SET, which catches a key vanishing or
# appearing unannounced. What it cannot catch is a key that is documented,
# loaded, and then never read by anything -- a knob the user can set with no
# effect. Three of those shipped before being found by hand: omenTrainingList,
# hcatCombinator3Wordlist, and hcatCombinatorXWordlist. A new key is added to
# both the example and EXPECTED_KEYS in the same commit, so the set test waves
# it through. This one does not.
# ---------------------------------------------------------------------------

MAIN_PY = os.path.join(REPO_ROOT, "hate_crack", "main.py")


def _package_files():
    paths = glob.glob(
        os.path.join(REPO_ROOT, "hate_crack", "**", "*.py"), recursive=True
    )
    paths.append(os.path.join(REPO_ROOT, "hate_crack.py"))
    return [p for p in paths if os.path.isfile(p)]


def _config_loads():
    """Map each config key to the module globals main.py loads it into.

    Also returns the line numbers those load statements occupy, so a later
    search can tell "this name is being loaded" from "this name is being used".
    """
    with open(MAIN_PY) as f:
        source = f.read()
    tree = ast.parse(source)
    loads: dict[str, set[str]] = {}
    load_lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        segment = ast.get_source_segment(source, node) or ""
        if "config_parser" not in segment:
            continue
        names = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if not names:
            # e.g. `config_parser[_key] = _value` in the defaults merge.
            continue
        for key in re.findall(
            r'config_parser(?:\.get)?\(?\[?\s*"([A-Za-z_0-9]+)"', segment
        ):
            loads.setdefault(key, set()).update(names)
        for line in range(node.lineno, (node.end_lineno or node.lineno) + 1):
            load_lines.add(line)
    return loads, load_lines


def _read_sites(name, load_lines):
    """Occurrences of `name` that are neither its load nor its self-normalize.

    Consumption through the root module's attribute proxy (`ctx.<name>` in
    attacks.py) counts, which is why this searches the whole package rather
    than main.py alone.
    """
    pattern = re.compile(r"\b" + re.escape(name) + r"\b")
    self_assign = re.compile(r"\s*" + re.escape(name) + r"\s*=\s*(_normalize|$)")
    hits = []
    for path in _package_files():
        with open(path) as f:
            for lineno, line in enumerate(f.read().splitlines(), start=1):
                if not pattern.search(line):
                    continue
                if path == MAIN_PY and lineno in load_lines:
                    continue
                if self_assign.match(line):
                    continue
                hits.append(f"{os.path.relpath(path, REPO_ROOT)}:{lineno}")
    return hits


def _literal_read_sites(key):
    """Keys read by literal name outside main.py, e.g. notify/settings.py."""
    hits = []
    for path in _package_files():
        if path == MAIN_PY:
            continue
        with open(path) as f:
            for lineno, line in enumerate(f.read().splitlines(), start=1):
                if f'"{key}"' in line:
                    hits.append(f"{os.path.relpath(path, REPO_ROOT)}:{lineno}")
    return hits


def test_every_documented_config_key_has_a_read_site():
    with open(ROOT_EXAMPLE) as f:
        keys = list(json.load(f).keys())
    loads, load_lines = _config_loads()

    dead = []
    for key in keys:
        globals_for_key = loads.get(key, set())
        if any(_read_sites(name, load_lines) for name in globals_for_key):
            continue
        if _literal_read_sites(key):
            continue
        dead.append(f"{key} (globals: {sorted(globals_for_key) or 'none'})")

    assert dead == [], (
        "config.json.example documents keys that nothing reads, so setting "
        "them has no effect. Either wire them up or remove them: " + "; ".join(dead)
    )


def test_every_env_homed_key_has_a_read_site():
    """The same guard, for the `.env` side of the split.

    The test above is driven by config.json.example, so it only ever covered
    the home="json" keys -- an integration key could be documented in
    .env.example, warned about if you put it in the wrong file, and still be
    read by nothing at all. That gap is not hypothetical: OLLAMA_HOST was a
    documented, user-set .env key that main.py read off os.environ instead, so
    the .env value was silently ignored on every run.
    """
    loads, load_lines = _config_loads()

    dead = []
    for entry in ENV_KEYS:
        globals_for_key = loads.get(entry.legacy, set())
        if any(_read_sites(name, load_lines) for name in globals_for_key):
            continue
        if _literal_read_sites(entry.legacy):
            continue
        dead.append(f"{entry.env} (globals: {sorted(globals_for_key) or 'none'})")

    assert dead == [], (
        ".env.example documents integration keys that nothing reads, so "
        "setting them has no effect. Either wire them up or remove them: "
        + "; ".join(dead)
    )


# ---------------------------------------------------------------------------
# Duplicate-key guard
# ---------------------------------------------------------------------------


def test_root_example_has_no_duplicate_keys():
    """config.json.example must define each key exactly once.

    json.load keeps the last of a duplicated pair, so a doubled line parses
    cleanly and every other guard here still passes: the key set collapses the
    pair, so counts and types all match. The file is malformed and the suite
    says nothing. Caught for real while adding hcatCorpusProfileMaxLines, where
    an edit written through both the root path and the package symlink that
    points at it produced two identical lines.
    """
    load_strict(ROOT_EXAMPLE)


def test_packaged_example_has_no_duplicate_keys():
    """Same guard through the packaged path.

    In the source tree that path is a symlink to the root copy, so this is the
    same bytes; in a wheel, an sdist, or a git-archive tarball it is a real
    file that could diverge.
    """
    load_strict(PACKAGED_EXAMPLE)


def test_duplicate_key_guard_actually_catches_a_duplicate():
    """Mutation test: the guard must fail on a file it is supposed to reject.

    Without this, test_root_example_has_no_duplicate_keys passes whether the
    check works or not — it has only ever seen a clean file. Duplicating a real
    line from the real example is exactly the malformation that shipped.
    """
    with open(ROOT_EXAMPLE) as fh:
        text = fh.read()

    # Duplicate the first "key": value line, reproducing the original defect.
    match = re.search(r'^(\s*"([A-Za-z_]+)":.*,)$', text, re.MULTILINE)
    assert match, "no simple scalar key line found to duplicate"
    line, key = match.group(1), match.group(2)
    mutated = text.replace(line, line + "\n" + line, 1)

    # Sanity: plain json.load accepts the mutation, which is the whole problem.
    assert json.loads(mutated), "mutation should still be syntactically valid JSON"

    with pytest.raises(DuplicateJSONKeyError) as excinfo:
        loads_strict(mutated)
    assert key in str(excinfo.value)


def test_duplicate_key_guard_catches_nested_duplicates():
    """A duplicate inside a nested object must be caught too.

    config.json.example is flat today, but object_pairs_hook sees every object
    in the document and a future nested section should not be a blind spot.
    """
    with pytest.raises(DuplicateJSONKeyError):
        loads_strict('{"outer": {"dup": 1, "dup": 2}}')
