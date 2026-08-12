"""Unit tests for hate_crack.llm.generate_candidates."""

import os
from types import SimpleNamespace
from unittest import mock

import httpx
import instructor
import openai
import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import llm  # noqa: E402


def _patch_agent(candidates):
    """Patch the client builders + AtomicAgent so no network happens.

    Returns the AtomicAgent class mock so callers can inspect construction.
    """
    result = mock.MagicMock()
    result.candidates = list(candidates)

    agent_instance = mock.MagicMock()
    agent_instance.run.return_value = result

    agent_cls = mock.MagicMock()
    # AtomicAgent[In, Out](config=...) -> agent_instance
    agent_cls.__getitem__.return_value.return_value = agent_instance

    return (
        mock.patch(
            "hate_crack.llm.instructor.from_openai",
            return_value=mock.MagicMock(spec=instructor.Instructor),
        ),
        mock.patch("hate_crack.llm.OpenAI"),
        mock.patch("hate_crack.llm.AtomicAgent", agent_cls),
        agent_cls,
        agent_instance,
    )


def test_target_mode_returns_candidates():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(
        ["AcmeCorp2024", "Finance123"]
    )
    with p_instr, p_openai, p_agent:
        out = llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {"company": "AcmeCorp", "industry": "Finance", "location": "NYC"},
            no_cloud=False,
        )
    assert out == ["AcmeCorp2024", "Finance123"]
    # The instruction the agent received must include the target context.
    run_arg = agent_instance.run.call_args[0][0]
    assert "AcmeCorp" in run_arg.request
    assert "Finance" in run_arg.request
    assert "NYC" in run_arg.request


def test_wordlist_mode_includes_sample_in_request():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["Passw0rd"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "wordlist",
            {"sample": "password\nletmein\nsummer2024"},
            no_cloud=False,
        )
    run_arg = agent_instance.run.call_args[0][0]
    assert "letmein" in run_arg.request


def test_cracked_mode_includes_sample_in_request():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(
        ["Winter2025!"]
    )
    with p_instr, p_openai, p_agent:
        out = llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "cracked",
            {"sample": "Summer2024!\nAcme2023\nP@ssw0rd1"},
            no_cloud=False,
        )
    assert out == ["Winter2025!"]
    run_arg = agent_instance.run.call_args[0][0]
    assert "Acme2023" in run_arg.request
    # The request must tell the model not to regenerate what is already cracked.
    assert "NEW" in run_arg.request
    assert "Do not repeat" in run_arg.request


def test_cracked_mode_uses_its_own_prompt_not_the_denylist_one():
    """cracked mode must select _CRACKED_PROMPT, never the denylist _WORDLIST_PROMPT."""
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "cracked",
            {"sample": "Summer2024!"},
            no_cloud=False,
        )
    config = agent_cls.__getitem__.return_value.call_args.kwargs["config"]
    assert config.system_prompt_generator is llm._CRACKED_PROMPT
    assert config.system_prompt_generator is not llm._WORDLIST_PROMPT


def test_wordlist_mode_still_uses_wordlist_prompt():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "wordlist",
            {"sample": "password"},
            no_cloud=False,
        )
    config = agent_cls.__getitem__.return_value.call_args.kwargs["config"]
    assert config.system_prompt_generator is llm._WORDLIST_PROMPT


def test_target_mode_still_uses_target_prompt():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
            no_cloud=False,
        )
    config = agent_cls.__getitem__.return_value.call_args.kwargs["config"]
    assert config.system_prompt_generator is llm._TARGET_PROMPT


def test_target_mode_includes_parent_company_when_present():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(
        ["AcmeCorp2024"]
    )
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {
                "company": "AcmeCorp",
                "industry": "Finance",
                "location": "NYC",
                "parent_company": "Acquired by Global Holdings in 2022",
            },
            no_cloud=False,
        )
    run_arg = agent_instance.run.call_args[0][0]
    # Verify all fields are in the request.
    assert "AcmeCorp" in run_arg.request
    assert "Finance" in run_arg.request
    assert "NYC" in run_arg.request
    assert "Acquired by Global Holdings in 2022" in run_arg.request


def test_target_mode_handles_empty_parent_company():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["Candidate1"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {
                "company": "IndependentCorp",
                "industry": "Tech",
                "location": "SF",
                "parent_company": "",
            },
            no_cloud=False,
        )
    run_arg = agent_instance.run.call_args[0][0]
    # Verify required fields are present but no empty parens appear.
    assert "IndependentCorp" in run_arg.request
    assert "Tech" in run_arg.request
    assert "SF" in run_arg.request
    # Ensure that an empty parent_company doesn't add stray parentheses.
    assert "( )" not in run_arg.request
    assert "()" not in run_arg.request


def test_cracked_prompt_is_offensive_not_denylist():
    """_CRACKED_PROMPT's objective is candidate generation, not denylist building."""
    rendered = llm._CRACKED_PROMPT.generate_prompt()
    assert "denylist" not in rendered.lower()
    assert "authorized penetration test" in rendered.lower()
    assert "already recovered" in rendered.lower()


def test_prompts_map_covers_every_supported_mode():
    # "mask" is deliberately absent: generate_masks() delegates to
    # hashcat_rosetta.nlmask.generate_masks rather than an Atomic Agents
    # prompt from this map -- see generate_masks()'s own docstring.
    assert set(llm._PROMPTS) == {
        "target",
        "wordlist",
        "cracked",
        "pattern",
        "rules",
    }


def test_dedupes_and_caps_length():
    long_pw = "A" * 129
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(
        ["  keep  ", "keep", "dup", "dup", long_pw, ""]
    )
    with p_instr, p_openai, p_agent:
        out = llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
            no_cloud=False,
        )
    assert out == ["keep", "dup"]  # trimmed, deduped, blank + >128 dropped


def test_num_ctx_forwarded_via_model_api_parameters():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            4096,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
            no_cloud=False,
        )
    # AtomicAgent[In, Out](config=<AgentConfig>) — inspect the config.
    config = agent_cls.__getitem__.return_value.call_args.kwargs["config"]
    assert config.model == "qwen2.5:32b"
    assert config.model_api_parameters["extra_body"]["options"]["num_ctx"] == 4096


def test_build_request_rejects_unknown_mode():
    """Unit test of _build_request's mode validation only — no agent involved."""
    with pytest.raises(ValueError, match="Unknown LLM generation mode: bogus"):
        llm._build_request("bogus", {})


def test_generate_candidates_rejects_unknown_mode_before_building_client():
    """generate_candidates surfaces _build_request's ValueError to its caller."""
    with pytest.raises(ValueError, match="Unknown LLM generation mode: bogus"):
        llm.generate_candidates(
            "http://localhost:11434", "qwen2.5:32b", 2048, "bogus", {}, no_cloud=False
        )


def test_timeout_forwarded_to_openai_client():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai as openai_cls, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
            timeout=42.5,
            no_cloud=False,
        )
    assert openai_cls.call_args.kwargs["timeout"] == 42.5


def test_default_timeout_used_when_omitted():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai as openai_cls, p_agent:
        llm.generate_candidates(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
            no_cloud=False,
        )
    assert llm.DEFAULT_TIMEOUT_SECONDS == 300.0
    assert openai_cls.call_args.kwargs["timeout"] == llm.DEFAULT_TIMEOUT_SECONDS


def test_api_timeout_reraised_as_domain_error():
    """openai.APITimeoutError is translated into llm.LLMTimeoutError."""
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    agent_instance.run.side_effect = openai.APITimeoutError(
        request=httpx.Request("POST", "http://localhost:11434/v1/chat/completions")
    )
    with p_instr, p_openai, p_agent:
        with pytest.raises(llm.LLMTimeoutError):
            llm.generate_candidates(
                "http://localhost:11434",
                "qwen2.5:32b",
                2048,
                "target",
                {"company": "X", "industry": "Y", "location": "Z"},
                timeout=1.0,
                no_cloud=False,
            )


# ---------------------------------------------------------------------------
# research_target
# ---------------------------------------------------------------------------


def _patch_research_agent(industry, location, parent_company=""):
    """Patch client builders + AtomicAgent for a research call. No network."""
    result = mock.MagicMock()
    result.industry = industry
    result.location = location
    result.parent_company = parent_company

    agent_instance = mock.MagicMock()
    agent_instance.run.return_value = result

    agent_cls = mock.MagicMock()
    agent_cls.__getitem__.return_value.return_value = agent_instance

    return (
        mock.patch(
            "hate_crack.llm.instructor.from_openai",
            return_value=mock.MagicMock(spec=instructor.Instructor),
        ),
        mock.patch("hate_crack.llm.OpenAI"),
        mock.patch("hate_crack.llm.AtomicAgent", agent_cls),
        agent_cls,
        agent_instance,
    )


def test_research_target_returns_fields_and_passes_company():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "freight rail maintenance", "Omaha, Nebraska"
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "Acme Rail Services",
            no_cloud=False,
        )
    assert out.industry == "freight rail maintenance"
    assert out.location == "Omaha, Nebraska"
    assert agent_instance.run.call_args[0][0].company == "Acme Rail Services"


def test_research_target_uses_research_prompt_and_num_ctx():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "x", "y"
    )
    with p_instr, p_openai, p_agent:
        llm.research_target(
            "http://localhost:11434", "qwen2.5:32b", 4096, "Acme", no_cloud=False
        )
    config = agent_cls.__getitem__.return_value.call_args.kwargs["config"]
    assert config.system_prompt_generator is llm._RESEARCH_PROMPT
    assert config.model_api_parameters["extra_body"]["options"]["num_ctx"] == 4096


def test_research_prompt_tells_model_to_return_empty_when_unsure():
    rendered = llm._RESEARCH_PROMPT.generate_prompt().lower()
    assert "empty string" in rendered
    assert "no internet access" in rendered


def test_research_target_strips_and_blanks_whitespace_only():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "  healthcare  ", "   "
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434", "m", 2048, "Acme", no_cloud=False
        )
    assert out.industry == "healthcare"
    assert out.location == ""


def test_research_target_caps_overlong_values():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "A" * 500, "B" * (llm.MAX_RESEARCH_FIELD_LEN + 1)
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434", "m", 2048, "Acme", no_cloud=False
        )
    assert len(out.industry) == llm.MAX_RESEARCH_FIELD_LEN
    assert len(out.location) == llm.MAX_RESEARCH_FIELD_LEN


def test_research_target_tolerates_non_string_fields():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        None, 42
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434", "m", 2048, "Acme", no_cloud=False
        )
    assert out.industry == ""
    assert out.location == ""


def test_research_target_timeout_forwarded_and_translated():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "x", "y"
    )
    agent_instance.run.side_effect = openai.APITimeoutError(
        request=httpx.Request("POST", "http://localhost:11434/v1/chat/completions")
    )
    with p_instr, p_openai as openai_cls, p_agent:
        with pytest.raises(llm.LLMTimeoutError):
            llm.research_target(
                "http://localhost:11434", "m", 2048, "Acme", timeout=7.5, no_cloud=False
            )
    assert openai_cls.call_args.kwargs["timeout"] == 7.5


def test_clean_research_field_collapses_internal_whitespace():
    assert llm.clean_research_field("commercial   \n construction") == (
        "commercial construction"
    )


def test_research_target_includes_parent_company_field():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "healthcare", "Boston, Massachusetts", "Acquired by Global Health Corp in 2023"
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "Acme Health Services",
            no_cloud=False,
        )
    assert out.parent_company == "Acquired by Global Health Corp in 2023"


def test_research_target_handles_empty_parent_company():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "healthcare", "Boston, Massachusetts", ""
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "Independent Clinic",
            no_cloud=False,
        )
    assert out.parent_company == ""


def _rosetta_suggestion(mask, custom_charsets=()):
    """A minimal stand-in for hashcat_rosetta.nlmask.MaskSuggestion.

    generate_masks() only reads .mask and .custom_charsets off what
    _rosetta_generate_masks returns (to build the combined hcmask line via
    the real _rosetta_format_hcmask_line), so a plain namespace is enough --
    no need to depend on HashcatRosetta's actual dataclass in this test file.
    """
    return SimpleNamespace(mask=mask, custom_charsets=list(custom_charsets))


def test_generate_masks_returns_masks(monkeypatch):
    captured = {}

    def fake_generate_masks(description, *, model, client, extra_options):
        captured["description"] = description
        captured["model"] = model
        captured["extra_options"] = extra_options
        return [
            _rosetta_suggestion("?u?l?l?l?d?d"),
            _rosetta_suggestion("?l?l?l?l?l?l?d"),
        ]

    monkeypatch.setattr(llm, "_rosetta_generate_masks", fake_generate_masks)

    out = llm.generate_masks(
        "http://localhost:11434",
        "qwen2.5:32b",
        2048,
        "8 character passwords, capitalized word plus two digits",
        no_cloud=False,
    )

    assert out == ["?u?l?l?l?d?d", "?l?l?l?l?l?l?d"]
    assert captured["model"] == "qwen2.5:32b"
    assert captured["extra_options"] == {"num_ctx": 2048}
    assert "8 character passwords" in captured["description"]


def test_generate_masks_combines_custom_charsets(monkeypatch):
    monkeypatch.setattr(
        llm,
        "_rosetta_generate_masks",
        lambda description, **kwargs: [_rosetta_suggestion("?1?1?1?1?d?d", ["aeiou"])],
    )

    out = llm.generate_masks(
        "http://localhost:11434",
        "qwen2.5:32b",
        2048,
        "four vowels then two digits",
        no_cloud=False,
    )

    assert out == ["aeiou,?1?1?1?1?d?d"]


def test_generate_masks_dedupes_combined_lines(monkeypatch):
    monkeypatch.setattr(
        llm,
        "_rosetta_generate_masks",
        lambda description, **kwargs: [
            _rosetta_suggestion("?d?d?d?d"),
            _rosetta_suggestion("?d?d?d?d"),
            _rosetta_suggestion("?u?l?l?l"),
        ],
    )

    out = llm.generate_masks(
        "http://localhost:11434", "qwen2.5:32b", 2048, "four digit pins", no_cloud=False
    )

    assert out == ["?d?d?d?d", "?u?l?l?l"]


def test_generate_masks_raises_llm_timeout_error(monkeypatch):
    def raise_wrapped_timeout(description, **kwargs):
        try:
            raise openai.APITimeoutError(request=mock.MagicMock())
        except openai.APITimeoutError as timeout_exc:
            # Mirrors how hashcat_rosetta.nlmask.generate_masks itself wraps
            # every request failure: `raise MaskGenerationError(...) from exc`,
            # preserving the original as __cause__.
            raise llm._RosettaMaskGenerationError("request failed") from timeout_exc

    monkeypatch.setattr(llm, "_rosetta_generate_masks", raise_wrapped_timeout)

    with pytest.raises(llm.LLMTimeoutError):
        llm.generate_masks(
            "http://localhost:11434", "qwen2.5:32b", 2048, "pins", no_cloud=False
        )


def test_generate_masks_reraises_non_timeout_rosetta_errors(monkeypatch):
    def raise_other_error(description, **kwargs):
        raise llm._RosettaMaskGenerationError("model returned invalid JSON")

    monkeypatch.setattr(llm, "_rosetta_generate_masks", raise_other_error)

    with pytest.raises(llm._RosettaMaskGenerationError):
        llm.generate_masks(
            "http://localhost:11434", "qwen2.5:32b", 2048, "pins", no_cloud=False
        )


def test_generate_masks_raises_runtime_error_when_rosetta_unavailable(monkeypatch):
    monkeypatch.setattr(llm, "_rosetta_generate_masks", None)

    with pytest.raises(RuntimeError, match="HashcatRosetta is unavailable"):
        llm.generate_masks(
            "http://localhost:11434", "qwen2.5:32b", 2048, "pins", no_cloud=False
        )


def test_generate_masks_refuses_cloud_model_when_no_cloud():
    with pytest.raises(llm.CloudModelRefused):
        llm.generate_masks(
            "http://localhost:11434",
            "deepseek-v3.1:671b-cloud",
            2048,
            "pins",
            no_cloud=True,
        )
