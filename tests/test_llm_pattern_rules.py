"""Tests for the LLM Pattern Rules attack (pattern inference is mocked).

Covers the three layers: the "pattern" prompt/request in hate_crack.llm, the
_clean_pattern filter and hcatOllamaPatterns orchestration in hate_crack.main,
and the mode-4 wiring in hate_crack.attacks.
"""

import os
import shlex
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import instructor
import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import attacks as hc_attacks  # noqa: E402
from hate_crack import llm  # noqa: E402
from hate_crack import main as hc_main  # noqa: E402

OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen2.5:32b"


# --------------------------------------------------------------------------
# Layer 1: hate_crack.llm
# --------------------------------------------------------------------------


def test_pattern_mode_has_a_prompt():
    assert "pattern" in llm._PROMPTS


def test_pattern_request_embeds_the_sample():
    request = llm._build_request("pattern", {"sample": "Delta2024!\nGamma99"})
    assert "Delta2024!" in request and "Gamma99" in request


def test_pattern_request_asks_for_undecorated_basewords():
    request = llm._build_request("pattern", {"sample": "x"})
    assert "lowercase" in request.lower()


def test_unknown_mode_still_rejected():
    with pytest.raises(ValueError):
        llm._build_request("patterns", {"sample": "x"})


# --------------------------------------------------------------------------
# Layer 2: _clean_pattern
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("alpha", "alpha"),
        ("Alpha2024!", "alpha"),
        ("DELTA", "delta"),
        ("delta gammas", "deltagammas"),
        ("s3cr3t", "scrt"),
        ("a1", ""),  # under MIN_PATTERN_LEN once digits are stripped
        ("123456", ""),
        ("", ""),
        ("   ", ""),
        (None, ""),
        (12345, ""),
    ],
)
def test_clean_pattern(raw, expected):
    assert hc_main._clean_pattern(raw) == expected


# --------------------------------------------------------------------------
# Layer 2: hcatOllamaPatterns orchestration
# --------------------------------------------------------------------------


@pytest.fixture
def pattern_env(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("Delta2024!\nAlpha99\nGamma1\n")
    return SimpleNamespace(
        tmp_path=tmp_path, hash_file=str(hash_file), corpus=str(corpus)
    )


@contextmanager
def pattern_globals(tmp_path):
    rules_dir = str(tmp_path / "rules")
    os.makedirs(rules_dir, exist_ok=True)
    with (
        mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL),
        mock.patch.object(hc_main, "ollamaModel", MODEL),
        mock.patch.object(hc_main, "ollamaNumCtx", 2048),
        mock.patch.object(hc_main, "ollamaTimeout", 300.0),
        mock.patch.object(hc_main, "ollamaMaxSampleLines", 500),
        mock.patch.object(hc_main, "rulesDirectory", rules_dir),
    ):
        yield


VALID_RULES = ["c$2$0$2$5", "$!", "u"]


def _paths(pattern_env):
    scratch = f"{pattern_env.hash_file}.llm_patterns"
    return (
        scratch,
        os.path.join(scratch, "basewords.txt"),
        os.path.join(scratch, "rules.rule"),
    )


def test_basewords_and_generated_rules_both_written(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            return_value=["Delta2024!", "gammas", "alpha"],
        ) as gen,
        mock.patch(
            "hate_crack.main.llm.generate_rules", return_value=VALID_RULES
        ) as gen_rules,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    assert gen.call_args[0][3] == "pattern"
    assert "Delta2024!" in gen.call_args[0][4]["sample"]
    # Both requests describe the same corpus, analyzed once.
    assert gen_rules.call_args[0][3] == gen.call_args[0][4]

    _, basewords_path, rules_path = _paths(pattern_env)
    assert open(basewords_path).read().split() == ["delta", "gammas", "alpha"]
    assert open(rules_path).read().split("\n")[:3] == VALID_RULES

    quick.assert_called_once()
    args = quick.call_args[0]
    assert args[2] == f"-r {rules_path}"
    assert args[3] == basewords_path
    assert quick.call_args[1]["attack_name"] == "LLM Patterns"


def test_operator_is_never_asked_for_a_rule_file(pattern_env):
    """The generated rules are the point of the mode; prompting defeats it."""
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch("hate_crack.main.llm.generate_rules", return_value=VALID_RULES),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
        mock.patch("builtins.input", side_effect=AssertionError("prompted")),
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    assert quick.call_count == 1


def test_invalid_rules_are_dropped_before_hashcat_sees_them(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch(
            "hate_crack.main.llm.generate_rules",
            # 'c$2' is valid; the rest use an op hashcat does not have, a
            # truncated argument, a bad position argument, and a comment line.
            return_value=["c$2", "QQQ", "$", "Ta", "# a comment", "c$2"],
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    _, _, rules_path = _paths(pattern_env)
    assert open(rules_path).read().split("\n")[:-1] == ["c$2"]
    assert quick.call_args[0][2] == f"-r {rules_path}"


def test_a_thin_rule_yield_is_asked_again(pattern_env):
    """A handful of rules wastes the pass, and the model is sampled, not fixed."""
    batches = [["c$1", "c$2"], ["c$2", "c$3"]]
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch(
            "hate_crack.main.llm.generate_rules", side_effect=batches
        ) as gen_rules,
        mock.patch("hate_crack.main.hcatQuickDictionary"),
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    assert gen_rules.call_count == hc_main.MAX_RULE_REQUESTS
    _, _, rules_path = _paths(pattern_env)
    # Deduped across attempts, and the earlier attempt's rules are kept.
    assert open(rules_path).read().split("\n")[:-1] == ["c$1", "c$2", "c$3"]


def test_a_full_rule_yield_is_not_asked_again(pattern_env):
    plenty = ["c" + "$1" * (i + 1) for i in range(hc_main.MIN_GENERATED_RULES)]
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch(
            "hate_crack.main.llm.generate_rules", return_value=plenty
        ) as gen_rules,
        mock.patch("hate_crack.main.hcatQuickDictionary"),
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    gen_rules.assert_called_once()


def test_a_retry_that_fails_keeps_the_rules_already_in_hand(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch(
            "hate_crack.main.llm.generate_rules",
            side_effect=[["c$1"], llm.LLMTimeoutError("boom")],
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    _, _, rules_path = _paths(pattern_env)
    assert open(rules_path).read().split("\n")[:-1] == ["c$1"]
    assert quick.call_args[0][2] == f"-r {rules_path}"


def test_no_valid_rules_falls_back_to_running_basewords_bare(pattern_env):
    """The expensive half already succeeded, so the run is not abandoned."""
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch("hate_crack.main.llm.generate_rules", return_value=["QQQ", ""]),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    _, basewords_path, rules_path = _paths(pattern_env)
    assert quick.call_args[0][2] == ""
    assert quick.call_args[0][3] == basewords_path
    assert not os.path.exists(rules_path)


def test_rule_request_failure_still_runs_the_basewords(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch(
            "hate_crack.main.llm.generate_rules",
            side_effect=llm.LLMTimeoutError("boom"),
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    assert quick.call_args[0][2] == ""


def test_rules_path_is_quoted_for_the_shell(pattern_env, tmp_path):
    """hcatQuickDictionary splits the chain with shlex, so a spacey path must hold."""
    spacey = tmp_path / "hash dir"
    spacey.mkdir()
    hash_file = spacey / "hashes.txt"
    hash_file.touch()
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch("hate_crack.main.llm.generate_rules", return_value=VALID_RULES),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", str(hash_file), pattern_env.corpus)

    chain = quick.call_args[0][2]
    expected = os.path.join(f"{hash_file}.llm_patterns", "rules.rule")
    assert shlex.split(chain) == ["-r", expected]


def test_duplicate_patterns_deduped_after_cleaning(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            # All three clean to "delta" — the model decorated its own output.
            return_value=["delta", "DELTA", "Delta2024"],
        ),
        mock.patch("hate_crack.main.llm.generate_rules", return_value=VALID_RULES),
        mock.patch("hate_crack.main.hcatQuickDictionary"),
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    _, basewords_path, _ = _paths(pattern_env)
    assert open(basewords_path).read().split() == ["delta"]


def test_missing_source_skips_the_model(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates") as gen,
        mock.patch("hate_crack.main.llm.generate_rules") as gen_rules,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, str(pattern_env.tmp_path / "nope.txt")
        )
    gen.assert_not_called()
    gen_rules.assert_not_called()
    quick.assert_not_called()


def test_all_output_filtered_out_skips_hashcat_and_the_rule_request(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["1", "22", "!!"]
        ),
        mock.patch("hate_crack.main.llm.generate_rules") as gen_rules,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    quick.assert_not_called()
    gen_rules.assert_not_called()
    assert not os.path.exists(f"{pattern_env.hash_file}.llm_patterns")


def test_baseword_timeout_skips_hashcat(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=llm.LLMTimeoutError("boom"),
        ),
        mock.patch("hate_crack.main.llm.generate_rules") as gen_rules,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    quick.assert_not_called()
    gen_rules.assert_not_called()


def test_connection_failure_skips_hashcat(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=RuntimeError("connection refused"),
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)
    quick.assert_not_called()


# --------------------------------------------------------------------------
# Layer 3: attacks.ollama_attack mode 4
# --------------------------------------------------------------------------


def _pattern_ctx(tmp_path, has_cracked=False):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    if has_cracked:
        (tmp_path / "hashes.txt.out").write_text("hash:Alpha2024!\n")
    return SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile=str(hash_file),
        hcatWordlists=str(tmp_path),
        rulesDirectory=str(tmp_path),
        hcatOllamaPatterns=mock.MagicMock(),
        hcatOllama=mock.MagicMock(),
    )


def test_mode_4_offered_with_and_without_cracked(tmp_path):
    """The key stays "4" either way so it does not move between sessions."""
    seen = {}

    def fake_menu(items, **kwargs):
        seen["items"] = items
        return "99"

    for has_cracked in (False, True):
        ctx = _pattern_ctx(tmp_path, has_cracked=has_cracked)
        with (
            mock.patch.object(hc_attacks, "interactive_menu", fake_menu),
            mock.patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        ):
            hc_attacks.ollama_attack(ctx)
        labels = dict(seen["items"])
        assert "Pattern rules" in labels["4"]
        assert ("3" in labels) is has_cracked


def test_mode_4_passes_only_the_source_and_never_prompts_for_rules(tmp_path):
    ctx = _pattern_ctx(tmp_path)
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("Alpha2024!\n")

    with (
        mock.patch.object(hc_attacks, "interactive_menu", return_value="4"),
        mock.patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        mock.patch.object(hc_attacks, "_pick_pattern_source", return_value=str(corpus)),
        mock.patch.object(hc_attacks, "_select_rules") as sel,
    ):
        hc_attacks.ollama_attack(ctx)

    sel.assert_not_called()
    ctx.hcatOllamaPatterns.assert_called_once_with(
        ctx.hcatHashType, ctx.hcatHashFile, str(corpus)
    )


def test_mode_4_source_cancel_runs_nothing(tmp_path):
    ctx = _pattern_ctx(tmp_path)
    with (
        mock.patch.object(hc_attacks, "interactive_menu", return_value="4"),
        mock.patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        mock.patch.object(hc_attacks, "_pick_pattern_source", return_value=None),
    ):
        hc_attacks.ollama_attack(ctx)
    ctx.hcatOllamaPatterns.assert_not_called()


def test_pick_pattern_source_prefers_cracked_when_available(tmp_path):
    ctx = _pattern_ctx(tmp_path, has_cracked=True)
    with mock.patch.object(hc_attacks, "interactive_menu", return_value="1"):
        assert hc_attacks._pick_pattern_source(ctx, "/tmp/cracked.out") == (
            "/tmp/cracked.out"
        )


def test_pick_pattern_source_falls_through_to_wordlist(tmp_path):
    ctx = _pattern_ctx(tmp_path)
    with mock.patch.object(
        hc_attacks, "_pick_training_wordlist", return_value="/tmp/wl.txt"
    ):
        assert hc_attacks._pick_pattern_source(ctx, None) == "/tmp/wl.txt"


def test_pick_pattern_source_cancel_returns_none(tmp_path):
    ctx = _pattern_ctx(tmp_path, has_cracked=True)
    with mock.patch.object(hc_attacks, "interactive_menu", return_value="99"):
        assert hc_attacks._pick_pattern_source(ctx, "/tmp/cracked.out") is None


# --------------------------------------------------------------------------
# Cleanup
# --------------------------------------------------------------------------


def test_llm_patterns_removed_by_cleanup(tmp_path, monkeypatch):
    """Mirrors test_main_spoonman.test_cleanup_removes_derived_output."""
    hash_file = str(tmp_path / "hashes.txt")
    patterns_path = hash_file + ".llm_patterns"
    os.makedirs(patterns_path)
    with open(os.path.join(patterns_path, "basewords.txt"), "w") as f:
        f.write("delta\n")

    monkeypatch.setattr(hc_main, "hcatHashFile", hash_file)
    monkeypatch.setattr(hc_main, "hcatHashFileOrig", hash_file)
    monkeypatch.setattr(hc_main, "hcatHashType", "1000")
    monkeypatch.setattr(hc_main, "pwdump_format", False)
    hc_main.cleanup()

    assert not os.path.exists(patterns_path)


# --------------------------------------------------------------------------
# Layer 1: the "rules" generation mode
# --------------------------------------------------------------------------


def test_rules_mode_has_a_prompt():
    assert "rules" in llm._PROMPTS


def test_rules_request_embeds_the_corpus_description():
    request = llm._build_request("rules", {"summary": "mask ?u?l?l?l?d?d 42%"})
    assert "?u?l?l?l?d?d" in request
    assert "hashcat rules" in request


def test_rules_prompt_names_the_allowed_ops():
    """A model told only "write hashcat rules" invents ops that get discarded."""
    prompt = llm._PROMPTS["rules"].generate_prompt()
    for op_description in ("append character", "prepend character", "capitalize"):
        assert op_description in prompt


def test_generate_rules_dedupes_and_strips():
    result = mock.MagicMock()
    result.rules = ["  c$1  ", "c$1", "$!", "", None]
    agent_instance = mock.MagicMock()
    agent_instance.run.return_value = result
    agent_cls = mock.MagicMock()
    agent_cls.__getitem__.return_value.return_value = agent_instance

    with (
        mock.patch(
            "hate_crack.llm.instructor.from_openai",
            return_value=mock.MagicMock(spec=instructor.Instructor),
        ),
        mock.patch("hate_crack.llm.OpenAI"),
        mock.patch("hate_crack.llm.AtomicAgent", agent_cls),
    ):
        out = llm.generate_rules(OLLAMA_URL, MODEL, 2048, {"summary": "x"})

    assert out == ["c$1", "$!"]
    assert "x" in agent_instance.run.call_args[0][0].request


def test_all_rules_rejected_says_how_many(pattern_env, capsys):
    """ "nothing came back" and "everything came back invalid" need different
    responses from the operator, so the failure message carries the count.

    Four, not two: an empty first yield is retried, and the count covers every
    rule the model returned across both attempts.
    """
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch("hate_crack.main.llm.generate_rules", return_value=["QQQ", ""]),
        mock.patch("hate_crack.main.hcatQuickDictionary"),
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    out = capsys.readouterr().out
    assert "No usable rules were inferred" in out
    assert "all 4 returned rules were rejected as invalid" in out, out


def test_no_rules_at_all_omits_the_count(pattern_env, capsys):
    """With an empty model response there is nothing to have rejected, so the
    message must not claim a count."""
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["alpha"]),
        mock.patch("hate_crack.main.llm.generate_rules", return_value=[]),
        mock.patch("hate_crack.main.hcatQuickDictionary"),
    ):
        hc_main.hcatOllamaPatterns("1000", pattern_env.hash_file, pattern_env.corpus)

    out = capsys.readouterr().out
    assert "No usable rules were inferred" in out
    assert "rejected as invalid" not in out, out
