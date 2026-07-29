"""Tests for the LLM Pattern Rules attack (pattern inference is mocked).

Covers the three layers: the "pattern" prompt/request in hate_crack.llm, the
_clean_pattern filter and hcatOllamaPatterns orchestration in hate_crack.main,
and the mode-4 wiring in hate_crack.attacks.
"""

import os
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

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
    request = llm._build_request("pattern", {"sample": "Acme2024!\nWidget99"})
    assert "Acme2024!" in request and "Widget99" in request


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
        ("summer", "summer"),
        ("Summer2024!", "summer"),
        ("ACME", "acme"),
        ("acme widgets", "acmewidgets"),
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
    corpus.write_text("Acme2024!\nSummer99\nWidget1\n")
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


def test_patterns_written_and_rules_passed_through(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            return_value=["Acme2024!", "widgets", "summer"],
        ) as gen,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, "-r best64.rule"
        )

    assert gen.call_args[0][3] == "pattern"
    assert "Acme2024!" in gen.call_args[0][4]["sample"]

    patterns_path = f"{pattern_env.hash_file}.llm_patterns"
    assert open(patterns_path).read().split() == ["acme", "widgets", "summer"]

    quick.assert_called_once()
    args = quick.call_args[0]
    assert args[2] == "-r best64.rule"
    assert args[3] == patterns_path
    assert quick.call_args[1]["attack_name"] == "LLM Patterns"


def test_no_rules_chain_is_allowed(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["summer"]),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, ""
        )
    assert quick.call_args[0][2] == ""


def test_chained_rules_pass_through_verbatim(pattern_env):
    chain = " -r best64.rule -r toggles1.rule"
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["summer"]),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, chain
        )
    assert quick.call_args[0][2] == chain


def test_multiple_chains_infer_once_and_reuse_the_baseword_file(pattern_env):
    """A round trip to the model is slow and non-deterministic, so it runs once."""
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["summer"]
        ) as gen,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000",
            pattern_env.hash_file,
            pattern_env.corpus,
            ["-r a.rule", " -r b.rule -r c.rule", ""],
        )

    gen.assert_called_once()
    assert quick.call_count == 3
    assert [c[0][2] for c in quick.call_args_list] == [
        "-r a.rule",
        " -r b.rule -r c.rule",
        "",
    ]
    # Every pass runs against the same inferred baseword file.
    assert {c[0][3] for c in quick.call_args_list} == {
        f"{pattern_env.hash_file}.llm_patterns"
    }


def test_empty_chain_list_infers_but_runs_nothing(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=["summer"]),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, []
        )
    quick.assert_not_called()


def test_duplicate_patterns_deduped_after_cleaning(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            # All three clean to "acme" — the model decorated its own output.
            return_value=["acme", "ACME", "Acme2024"],
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary"),
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, ""
        )
    patterns_path = f"{pattern_env.hash_file}.llm_patterns"
    assert open(patterns_path).read().split() == ["acme"]


def test_missing_source_skips_the_model(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates") as gen,
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, str(pattern_env.tmp_path / "nope.txt"), ""
        )
    gen.assert_not_called()
    quick.assert_not_called()


def test_all_output_filtered_out_skips_hashcat(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["1", "22", "!!"]
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, ""
        )
    quick.assert_not_called()
    assert not os.path.exists(f"{pattern_env.hash_file}.llm_patterns")


def test_timeout_skips_hashcat(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=llm.LLMTimeoutError("boom"),
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, ""
        )
    quick.assert_not_called()


def test_connection_failure_skips_hashcat(pattern_env):
    with (
        pattern_globals(pattern_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=RuntimeError("connection refused"),
        ),
        mock.patch("hate_crack.main.hcatQuickDictionary") as quick,
    ):
        hc_main.hcatOllamaPatterns(
            "1000", pattern_env.hash_file, pattern_env.corpus, ""
        )
    quick.assert_not_called()


# --------------------------------------------------------------------------
# Layer 3: attacks.ollama_attack mode 4
# --------------------------------------------------------------------------


def _pattern_ctx(tmp_path, has_cracked=False):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    if has_cracked:
        (tmp_path / "hashes.txt.out").write_text("hash:Summer2024!\n")
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


def test_mode_4_hands_all_chains_over_in_one_call(tmp_path):
    """Every chain goes over at once so the model is queried once, not per rule."""
    ctx = _pattern_ctx(tmp_path)
    corpus = tmp_path / "corpus.txt"
    corpus.write_text("Summer2024!\n")

    with (
        mock.patch.object(hc_attacks, "interactive_menu", return_value="4"),
        mock.patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        mock.patch.object(hc_attacks, "_pick_pattern_source", return_value=str(corpus)),
        mock.patch.object(
            hc_attacks, "_select_rules", return_value=["-r a.rule", "-r b.rule"]
        ),
    ):
        hc_attacks.ollama_attack(ctx)

    ctx.hcatOllamaPatterns.assert_called_once()
    assert ctx.hcatOllamaPatterns.call_args[0][3] == ["-r a.rule", "-r b.rule"]


def test_mode_4_rule_cancel_runs_nothing(tmp_path):
    ctx = _pattern_ctx(tmp_path)
    with (
        mock.patch.object(hc_attacks, "interactive_menu", return_value="4"),
        mock.patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        mock.patch.object(hc_attacks, "_pick_pattern_source", return_value="/x"),
        mock.patch.object(hc_attacks, "_select_rules", return_value=None),
    ):
        hc_attacks.ollama_attack(ctx)
    ctx.hcatOllamaPatterns.assert_not_called()


def test_mode_4_source_cancel_skips_rule_picker(tmp_path):
    ctx = _pattern_ctx(tmp_path)
    with (
        mock.patch.object(hc_attacks, "interactive_menu", return_value="4"),
        mock.patch.object(hc_attacks._notify, "prompt_notify_for_attack"),
        mock.patch.object(hc_attacks, "_pick_pattern_source", return_value=None),
        mock.patch.object(hc_attacks, "_select_rules") as sel,
    ):
        hc_attacks.ollama_attack(ctx)
    sel.assert_not_called()
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
    with open(patterns_path, "w") as f:
        f.write("acme\n")

    monkeypatch.setattr(hc_main, "hcatHashFile", hash_file, raising=False)
    monkeypatch.setattr(hc_main, "hcatHashFileOrig", hash_file, raising=False)
    monkeypatch.setattr(hc_main, "hcatHashType", "1000", raising=False)
    monkeypatch.setattr(hc_main, "pwdump_format", False, raising=False)
    hc_main.cleanup()

    assert not os.path.exists(patterns_path)
