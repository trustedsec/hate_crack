import json
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT_EXAMPLE = os.path.join(REPO_ROOT, "config.json.example")
PACKAGED_EXAMPLE = os.path.join(REPO_ROOT, "hate_crack", "config.json.example")

# Source of truth for config.json.example's key set. Update this set
# whenever a config key is added or removed — it's what would have caught
# the #150 drift (10 missing keys, 4 dead passgpt* keys shipped in a prior
# release) regardless of whether the packaged copy is a symlink, a
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
    "pipalPath",
    "pipal_count",
    "bandrelmaxruntime",
    "bandrel_common_basedwords",
    "hashview_url",
    "hashview_api_key",
    "hashmob_api_key",
    "ollamaModel",
    "ollamaNumCtx",
    "ollamaTimeout",
    "ollamaMaxSampleLines",
    "ollamaAutoResearch",
    "omenTrainingList",
    "omenMaxCandidates",
    "pcfgRuleset",
    "pcfgMaxCandidates",
    "pcfgPrinceLingMaxCandidates",
    "check_for_updates",
    "optimizedKernelAttacks",
    "notify_enabled",
    "notify_pushover_token",
    "notify_pushover_user",
    "notify_per_crack_enabled",
    "notify_attack_allowlist",
    "notify_suppress_in_orchestrators",
    "notify_max_cracks_per_burst",
    "notify_poll_interval_seconds",
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


def test_optimized_kernel_attack_names_are_honoured():
    """Every name in the list must reach _should_use_optimized_kernel.

    hcatPrinceLing used to be listed but was never checked — it delegates to
    hcatPrince, which tests its own name — so toggling it did nothing.
    """
    with open(os.path.join(REPO_ROOT, "hate_crack", "main.py")) as f:
        source = f.read()
    with open(ROOT_EXAMPLE) as f:
        listed = json.load(f)["optimizedKernelAttacks"]
    for name in listed:
        assert f'_should_use_optimized_kernel("{name}")' in source, name
