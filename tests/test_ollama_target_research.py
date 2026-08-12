"""Tests for LLM target-research pre-fill (menu 12, Target info mode).

Covers both layers: hcatOllamaResearchTarget in main (spinner + failure
degradation) and ollama_attack's editable-default prompts in attacks. The LLM is
always mocked; no network.
"""

import os
from unittest import mock
from unittest.mock import MagicMock, patch

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import llm  # noqa: E402
from hate_crack import main as hc_main  # noqa: E402
from hate_crack.attacks import ollama_attack  # noqa: E402


def _make_ctx(hash_type: str = "1000", hash_file: str = "/tmp/hashes.txt") -> MagicMock:
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


class _InputRecorder:
    """input() stub that records prompts and replays canned answers."""

    def __init__(self, answers):
        self.answers = list(answers)
        self.prompts: list[str] = []

    def __call__(self, prompt=""):
        self.prompts.append(prompt)
        return self.answers.pop(0)


def _run_target_mode(ctx, answers):
    recorder = _InputRecorder(answers)
    with (
        patch("hate_crack.attacks.interactive_menu", return_value="1"),
        patch("builtins.input", recorder),
    ):
        ollama_attack(ctx)
    return recorder


# ---------------------------------------------------------------------------
# attacks layer: prompt defaults
# ---------------------------------------------------------------------------


class TestResearchPrefill:
    def test_successful_research_prefills_defaults(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "freight rail maintenance",
            "location": "Omaha, Nebraska",
            "parent_company": "",
        }

        recorder = _run_target_mode(ctx, ["Acme Rail", "", "", ""])

        ctx.hcatOllamaResearchTarget.assert_called_once_with("Acme Rail")
        assert recorder.prompts == [
            "Company name: ",
            "Industry (freight rail maintenance): ",
            "Location (Omaha, Nebraska): ",
            "Parent company / acquired by: ",
        ]

    def test_enter_accepts_the_suggested_defaults(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "healthcare",
            "location": "Austin, Texas",
            "parent_company": "",
        }

        _run_target_mode(ctx, ["Acme", "", "", ""])

        assert ctx.hcatOllama.call_args[0][3] == {
            "company": "Acme",
            "industry": "healthcare",
            "location": "Austin, Texas",
            "parent_company": "",
        }

    def test_typed_input_overrides_the_default(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "healthcare",
            "location": "Austin, Texas",
            "parent_company": "",
        }

        _run_target_mode(ctx, ["Acme", "  banking  ", "Berlin", ""])

        assert ctx.hcatOllama.call_args[0][3] == {
            "company": "Acme",
            "industry": "banking",
            "location": "Berlin",
            "parent_company": "",
        }

    def test_partial_research_prefills_only_known_field(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "mining",
            "location": "",
            "parent_company": "",
        }

        recorder = _run_target_mode(ctx, ["Acme", "", "Perth", ""])

        assert recorder.prompts[1] == "Industry (mining): "
        assert recorder.prompts[2] == "Location: "
        assert recorder.prompts[3] == "Parent company / acquired by: "
        assert ctx.hcatOllama.call_args[0][3]["location"] == "Perth"

    def test_partial_research_includes_parent_company_when_known(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "",
            "location": "",
            "parent_company": "Acquired by Global Holdings in 2022",
        }

        recorder = _run_target_mode(ctx, ["Acme", "", "", ""])

        assert recorder.prompts[1] == "Industry: "
        assert recorder.prompts[2] == "Location: "
        assert (
            recorder.prompts[3]
            == "Parent company / acquired by (Acquired by Global Holdings in 2022): "
        )
        assert (
            ctx.hcatOllama.call_args[0][3]["parent_company"]
            == "Acquired by Global Holdings in 2022"
        )

    def test_empty_research_falls_back_to_blank_prompts(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "",
            "location": "",
            "parent_company": "",
        }

        recorder = _run_target_mode(ctx, ["Acme", "tech", "NYC", ""])

        assert recorder.prompts == [
            "Company name: ",
            "Industry: ",
            "Location: ",
            "Parent company / acquired by: ",
        ]
        assert ctx.hcatOllama.call_args[0][3] == {
            "company": "Acme",
            "industry": "tech",
            "location": "NYC",
            "parent_company": "",
        }

    def test_whitespace_only_research_is_treated_as_no_suggestion(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "   ",
            "location": "\t\n",
            "parent_company": "  \n  ",
        }

        recorder = _run_target_mode(ctx, ["Acme", "", "", ""])

        assert recorder.prompts == [
            "Company name: ",
            "Industry: ",
            "Location: ",
            "Parent company / acquired by: ",
        ]

    def test_overlong_suggestion_is_capped_in_the_prompt(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "z" * 500,
            "location": "",
            "parent_company": "",
        }

        recorder = _run_target_mode(ctx, ["Acme", "", "", ""])

        assert recorder.prompts[1] == f"Industry ({'z' * llm.MAX_RESEARCH_FIELD_LEN}): "
        industry = ctx.hcatOllama.call_args[0][3]["industry"]
        assert len(industry) == llm.MAX_RESEARCH_FIELD_LEN

    def test_research_exception_falls_back_and_does_not_abort(self) -> None:
        """Even an unexpected raise from the research call must not block."""
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.side_effect = RuntimeError("boom")

        recorder = _run_target_mode(ctx, ["Acme", "tech", "NYC", ""])

        assert recorder.prompts == [
            "Company name: ",
            "Industry: ",
            "Location: ",
            "Parent company / acquired by: ",
        ]
        ctx.hcatOllama.assert_called_once()

    def test_non_dict_research_result_falls_back(self) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = None

        recorder = _run_target_mode(ctx, ["Acme", "tech", "NYC", ""])

        assert recorder.prompts == [
            "Company name: ",
            "Industry: ",
            "Location: ",
            "Parent company / acquired by: ",
        ]

    def test_blank_company_skips_research_entirely(self) -> None:
        ctx = _make_ctx()

        recorder = _run_target_mode(ctx, ["", "tech", "NYC", ""])

        ctx.hcatOllamaResearchTarget.assert_not_called()
        assert recorder.prompts == [
            "Company name: ",
            "Industry: ",
            "Location: ",
            "Parent company / acquired by: ",
        ]

    def test_suggestions_are_labelled_as_guesses(self, capsys) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "healthcare",
            "location": "Austin, Texas",
            "parent_company": "",
        }

        _run_target_mode(ctx, ["Acme", "", "", ""])

        out = capsys.readouterr().out
        assert "GUESSES" in out
        assert "not verified OSINT" in out

    def test_no_guess_banner_when_research_returns_nothing(self, capsys) -> None:
        ctx = _make_ctx()
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "",
            "location": "",
            "parent_company": "",
        }

        _run_target_mode(ctx, ["Acme", "", "", ""])

        assert "GUESSES" not in capsys.readouterr().out

    def test_hcatOllama_call_shape_unchanged(self) -> None:
        ctx = _make_ctx(hash_type="1800", hash_file="/tmp/sha512.txt")
        ctx.hcatOllamaResearchTarget.return_value = {
            "industry": "healthcare",
            "location": "Austin",
            "parent_company": "",
        }

        _run_target_mode(ctx, ["Acme", "", "", ""])

        args = ctx.hcatOllama.call_args[0]
        assert args[0] == "1800"
        assert args[1] == "/tmp/sha512.txt"
        assert args[2] == "target"
        assert set(args[3]) == {"company", "industry", "location", "parent_company"}


# ---------------------------------------------------------------------------
# main layer: hcatOllamaResearchTarget
# ---------------------------------------------------------------------------


class TestHcatOllamaResearchTarget:
    def test_returns_researched_fields_and_shows_progress(self) -> None:
        result = hc_main.llm.TargetResearchOutput(
            industry="mining", location="Perth", parent_company=""
        )
        with (
            mock.patch.object(hc_main, "ollamaAutoResearch", True),
            mock.patch.object(hc_main, "ollamaModel", "qwen2.5:32b"),
            mock.patch.object(hc_main, "ollamaTimeout", 30.0),
            mock.patch.object(hc_main.llm, "research_target", return_value=result),
            mock.patch.object(hc_main, "spinner") as spin,
        ):
            out = hc_main.hcatOllamaResearchTarget("Acme")

        assert out == {"industry": "mining", "location": "Perth", "parent_company": ""}
        # The call must be wrapped in the progress spinner, not look like a hang.
        assert spin.call_count == 1
        assert "Acme" in spin.call_args[0][0]

    def test_forwards_config_values_to_research_target(self) -> None:
        result = hc_main.llm.TargetResearchOutput(
            industry="", location="", parent_company=""
        )
        with (
            mock.patch.object(hc_main, "ollamaAutoResearch", True),
            mock.patch.object(hc_main, "ollamaUrl", "http://localhost:11434"),
            mock.patch.object(hc_main, "ollamaModel", "m"),
            mock.patch.object(hc_main, "ollamaNumCtx", 4096),
            mock.patch.object(hc_main, "ollamaTimeout", 12.5),
            mock.patch.object(
                hc_main.llm, "research_target", return_value=result
            ) as research,
        ):
            hc_main.hcatOllamaResearchTarget("Acme")

        assert research.call_args[0] == ("http://localhost:11434", "m", 4096, "Acme")
        assert research.call_args.kwargs["timeout"] == 12.5

    def test_timeout_degrades_to_blank_suggestions(self, capsys) -> None:
        with (
            mock.patch.object(hc_main, "ollamaAutoResearch", True),
            mock.patch.object(hc_main, "ollamaTimeout", 5.0),
            mock.patch.object(
                hc_main.llm,
                "research_target",
                side_effect=hc_main.llm.LLMTimeoutError("no response"),
            ),
        ):
            out = hc_main.hcatOllamaResearchTarget("Acme")

        assert out == {"industry": "", "location": "", "parent_company": ""}
        assert "timed out" in capsys.readouterr().out

    def test_connection_failure_degrades_to_blank_suggestions(self, capsys) -> None:
        with (
            mock.patch.object(hc_main, "ollamaAutoResearch", True),
            mock.patch.object(
                hc_main.llm,
                "research_target",
                side_effect=ConnectionError("connection refused"),
            ),
        ):
            out = hc_main.hcatOllamaResearchTarget("Acme")

        assert out == {"industry": "", "location": "", "parent_company": ""}
        assert "unavailable" in capsys.readouterr().out

    def test_disabled_by_config_skips_the_model_call(self) -> None:
        with (
            mock.patch.object(hc_main, "ollamaAutoResearch", False),
            mock.patch.object(hc_main.llm, "research_target") as research,
        ):
            out = hc_main.hcatOllamaResearchTarget("Acme")

        research.assert_not_called()
        assert out == {"industry": "", "location": "", "parent_company": ""}

    def test_blank_company_skips_the_model_call(self) -> None:
        with (
            mock.patch.object(hc_main, "ollamaAutoResearch", True),
            mock.patch.object(hc_main.llm, "research_target") as research,
        ):
            out = hc_main.hcatOllamaResearchTarget("")

        research.assert_not_called()
        assert out == {"industry": "", "location": "", "parent_company": ""}

    def test_auto_research_default_is_enabled(self) -> None:
        assert hc_main.ollamaAutoResearch is True
