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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "bogus",
            {},
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
                backend="ollama",
                api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            "http://localhost:11434",
            "qwen2.5:32b",
            4096,
            "Acme",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
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
            "http://localhost:11434",
            "m",
            2048,
            "Acme",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
        )
    assert out.industry == "healthcare"
    assert out.location == ""


def test_research_target_caps_overlong_values():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        "A" * 500, "B" * (llm.MAX_RESEARCH_FIELD_LEN + 1)
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434",
            "m",
            2048,
            "Acme",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
        )
    assert len(out.industry) == llm.MAX_RESEARCH_FIELD_LEN
    assert len(out.location) == llm.MAX_RESEARCH_FIELD_LEN


def test_research_target_tolerates_non_string_fields():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_research_agent(
        None, 42
    )
    with p_instr, p_openai, p_agent:
        out = llm.research_target(
            "http://localhost:11434",
            "m",
            2048,
            "Acme",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
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
                "http://localhost:11434",
                "m",
                2048,
                "Acme",
                timeout=7.5,
                no_cloud=False,
                backend="ollama",
                api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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
            backend="ollama",
            api_key="ollama",
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

    def fake_generate_masks(description, *, model, client, extra_options, host=None):
        captured["description"] = description
        captured["model"] = model
        captured["extra_options"] = extra_options
        captured["host"] = host
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
        backend="ollama",
        api_key="ollama",
    )

    assert out == ["?u?l?l?l?d?d", "?l?l?l?l?l?l?d"]
    assert captured["model"] == "qwen2.5:32b"
    assert captured["extra_options"] == {"num_ctx": 2048}
    assert "8 character passwords" in captured["description"]
    assert captured["host"] == "http://localhost:11434"


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
        backend="ollama",
        api_key="ollama",
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
        "http://localhost:11434",
        "qwen2.5:32b",
        2048,
        "four digit pins",
        no_cloud=False,
        backend="ollama",
        api_key="ollama",
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
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "pins",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
        )


def test_generate_masks_reraises_non_timeout_rosetta_errors(monkeypatch):
    def raise_other_error(description, **kwargs):
        raise llm._RosettaMaskGenerationError("model returned invalid JSON")

    monkeypatch.setattr(llm, "_rosetta_generate_masks", raise_other_error)

    with pytest.raises(llm._RosettaMaskGenerationError):
        llm.generate_masks(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "pins",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
        )


def test_generate_masks_raises_runtime_error_when_rosetta_unavailable(monkeypatch):
    monkeypatch.setattr(llm, "_rosetta_generate_masks", None)

    with pytest.raises(RuntimeError, match="HashcatRosetta is unavailable"):
        llm.generate_masks(
            "http://localhost:11434",
            "qwen2.5:32b",
            2048,
            "pins",
            no_cloud=False,
            backend="ollama",
            api_key="ollama",
        )


def test_generate_masks_refuses_cloud_model_when_no_cloud():
    with pytest.raises(llm.CloudModelRefused):
        llm.generate_masks(
            "http://localhost:11434",
            "deepseek-v3.1:671b-cloud",
            2048,
            "pins",
            no_cloud=True,
            backend="ollama",
            api_key="ollama",
        )


# ---------------------------------------------------------------------------
# backend_extra_body
# ---------------------------------------------------------------------------


def test_backend_extra_body_ollama_uses_options_num_ctx():
    assert llm.backend_extra_body("ollama", 4096) == {"options": {"num_ctx": 4096}}


def test_backend_extra_body_vllm_disables_thinking_via_chat_template_kwargs():
    """The verified fix for vLLM's reasoning-parser trap: 'thinking', not
    'enable_thinking' -- the latter silently returns an empty object rather
    than erroring, so this must check the exact key, not just dict truthiness.
    """
    body = llm.backend_extra_body("vllm", 4096)
    assert body["chat_template_kwargs"]["thinking"] is False
    # Regression guard: no leaked Ollama-shaped field, and not the wrong key.
    assert "options" not in body
    assert "enable_thinking" not in body["chat_template_kwargs"]


def test_backend_extra_body_openai_is_empty():
    assert llm.backend_extra_body("openai", 4096) == {}


def test_backend_extra_body_rejects_unknown_backend():
    with pytest.raises(ValueError, match="bogus"):
        llm.backend_extra_body("bogus", 4096)


# ---------------------------------------------------------------------------
# _build_client
# ---------------------------------------------------------------------------


def test_build_client_passes_configured_api_key_through():
    with (
        mock.patch("hate_crack.llm.OpenAI") as openai_cls,
        mock.patch("hate_crack.llm.instructor.from_openai"),
    ):
        llm._build_client("http://localhost:8000", "sk-real-vllm-key", 30.0)
    assert openai_cls.call_args.kwargs["api_key"] == "sk-real-vllm-key"
    assert openai_cls.call_args.kwargs["base_url"] == "http://localhost:8000/v1"
    assert openai_cls.call_args.kwargs["timeout"] == 30.0


def test_generate_candidates_forwards_backend_and_api_key():
    """The vllm branch's extra_body reaches model_api_parameters, and the
    configured api_key reaches the OpenAI client -- not just "some value".
    """
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai as openai_cls, p_agent:
        llm.generate_candidates(
            "http://localhost:8000",
            "qwen2.5:32b",
            2048,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
            no_cloud=False,
            backend="vllm",
            api_key="sk-real-vllm-key",
        )
    assert openai_cls.call_args.kwargs["api_key"] == "sk-real-vllm-key"
    config = agent_cls.__getitem__.return_value.call_args.kwargs["config"]
    assert config.model_api_parameters["extra_body"] == {
        "chat_template_kwargs": {"thinking": False}
    }


# ---------------------------------------------------------------------------
# rosetta_backend_kwargs
# ---------------------------------------------------------------------------


def test_rosetta_backend_kwargs_ollama_uses_extra_options_and_no_think():
    kwargs = llm.rosetta_backend_kwargs("ollama", 4096)
    assert kwargs == {"extra_options": {"num_ctx": 4096}}
    # Deliberately absent: leaving nlmask.generate_masks()'s own think
    # default (True) untouched is what keeps this path byte-identical to
    # before this function existed.
    assert "think" not in kwargs


def test_rosetta_backend_kwargs_vllm_disables_thinking_and_omits_extra_options():
    kwargs = llm.rosetta_backend_kwargs("vllm", 4096)
    assert kwargs["think"] is False
    thinking_kwargs = kwargs["extra_request_body"]["chat_template_kwargs"]
    assert thinking_kwargs["thinking"] is False
    # Regression guard: no leaked Ollama-shaped field, and not the wrong key.
    assert "extra_options" not in kwargs
    assert "enable_thinking" not in thinking_kwargs


def test_rosetta_backend_kwargs_openai_disables_thinking_only():
    assert llm.rosetta_backend_kwargs("openai", 4096) == {"think": False}


def test_rosetta_backend_kwargs_rejects_unknown_backend():
    with pytest.raises(ValueError, match="bogus"):
        llm.rosetta_backend_kwargs("bogus", 4096)


# ---------------------------------------------------------------------------
# generate_masks: no longer refuses vllm/openai, forwards backend kwargs,
# and still guards a HashcatRosetta submodule too old to accept them.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("backend", ["vllm", "openai"])
def test_generate_masks_no_longer_refuses_non_ollama_backend(monkeypatch, backend):
    """The upstream fix (think/extra_request_body params on
    nlmask.generate_masks) landed, so a current HashcatRosetta checkout must
    not be refused for vllm/openai any more.
    """

    def current_signature_stub(
        description,
        *,
        model,
        client,
        extra_options=None,
        think=True,
        extra_request_body=None,
        host=None,
    ):
        return []

    monkeypatch.setattr(llm, "_rosetta_generate_masks", current_signature_stub)

    out = llm.generate_masks(
        "http://localhost:8000",
        "qwen2.5:32b",
        2048,
        "pins",
        no_cloud=False,
        backend=backend,
        api_key="sk-real-vllm-key",
    )
    assert out == []


def test_generate_masks_forwards_vllm_kwargs_to_rosetta(monkeypatch):
    captured = {}

    def fake_generate_masks(
        description,
        *,
        model,
        client,
        extra_options=None,
        think=True,
        extra_request_body=None,
        host=None,
    ):
        if extra_options is not None:
            captured["extra_options"] = extra_options
        if think is not True:
            captured["think"] = think
        if extra_request_body is not None:
            captured["extra_request_body"] = extra_request_body
        return []

    monkeypatch.setattr(llm, "_rosetta_generate_masks", fake_generate_masks)

    llm.generate_masks(
        "http://localhost:8000",
        "qwen2.5:32b",
        2048,
        "pins",
        no_cloud=False,
        backend="vllm",
        api_key="sk-real-vllm-key",
    )

    assert captured["think"] is False
    assert captured["extra_request_body"] == {
        "chat_template_kwargs": {"thinking": False}
    }
    assert "extra_options" not in captured


def test_generate_masks_forwards_host_so_error_messages_name_the_real_server(
    monkeypatch,
):
    """nlmask.generate_masks()'s own resolve_base_url(host) is used only to
    build its error-message text -- the actual request always rides on the
    `client` object, which generate_masks() already builds against `url`.
    Omitting `host=` left it falling back to OLLAMA_HOST/localhost, so a
    failed request to a remote vLLM host reported 'could not reach Ollama at
    http://localhost:11434/v1' -- the right request, the wrong error message.
    This asserts the actual forwarded value, not merely that the kwarg is
    present.
    """
    captured = {}

    def fake_generate_masks(
        description,
        *,
        model,
        client,
        host=None,
        extra_options=None,
        think=True,
        extra_request_body=None,
    ):
        captured["host"] = host
        return []

    monkeypatch.setattr(llm, "_rosetta_generate_masks", fake_generate_masks)

    llm.generate_masks(
        "http://vllm-remote.example:8000",
        "qwen2.5:32b",
        2048,
        "pins",
        no_cloud=False,
        backend="vllm",
        api_key="sk-real-vllm-key",
    )

    assert captured["host"] == "http://vllm-remote.example:8000"


def test_generate_masks_forwards_ollama_kwargs_without_think(monkeypatch):
    captured = {}

    def fake_generate_masks(description, *, model, client, **kwargs):
        captured.update(kwargs)
        return []

    monkeypatch.setattr(llm, "_rosetta_generate_masks", fake_generate_masks)

    llm.generate_masks(
        "http://localhost:11434",
        "qwen2.5:32b",
        2048,
        "pins",
        no_cloud=False,
        backend="ollama",
        api_key="ollama",
    )

    assert captured == {
        "extra_options": {"num_ctx": 2048},
        "host": "http://localhost:11434",
    }
    assert "think" not in captured


def test_generate_masks_capability_guard_refuses_old_submodule_for_non_ollama(
    monkeypatch,
):
    """A stubbed _rosetta_generate_masks whose signature lacks
    think/extra_request_body must raise RosettaBackendRefused for a
    non-ollama backend -- this is the "submodule too old" meaning the
    exception now carries.
    """

    def old_signature_stub(
        description, *, model, client, extra_options=None, host=None
    ):
        return []

    monkeypatch.setattr(llm, "_rosetta_generate_masks", old_signature_stub)

    with pytest.raises(llm.RosettaBackendRefused) as exc:
        llm.generate_masks(
            "http://localhost:8000",
            "qwen2.5:32b",
            2048,
            "pins",
            no_cloud=False,
            backend="vllm",
            api_key="sk-real-vllm-key",
        )
    # Still a RuntimeError, so existing callers that catch RuntimeError
    # (including the "HashcatRosetta is unavailable" case) keep working.
    assert isinstance(exc.value, RuntimeError)
    assert exc.value.backend == "vllm"


def test_generate_masks_capability_guard_does_not_apply_to_ollama(monkeypatch):
    """An old submodule signature (missing think/extra_request_body) must not
    break the Ollama path, which never needed those parameters."""

    def old_signature_stub(
        description, *, model, client, extra_options=None, host=None
    ):
        return []

    monkeypatch.setattr(llm, "_rosetta_generate_masks", old_signature_stub)

    out = llm.generate_masks(
        "http://localhost:11434",
        "qwen2.5:32b",
        2048,
        "pins",
        no_cloud=False,
        backend="ollama",
        api_key="ollama",
    )
    assert out == []


# ---------------------------------------------------------------------------
# _resolve_api_key / empty LLM_API_KEY handling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\t\n"])
def test_resolve_api_key_substitutes_the_inert_placeholder(raw):
    assert llm._resolve_api_key(raw) == "ollama"


def test_resolve_api_key_passes_through_a_real_key():
    assert llm._resolve_api_key("sk-real-vllm-key") == "sk-real-vllm-key"


def test_build_client_never_passes_an_empty_api_key_to_openai():
    """openai.OpenAI(api_key='') raises OpenAIError: Missing credentials --
    confirmed directly against the SDK. An operator who clears LLM_API_KEY=
    for a vLLM server with no auth must not hit that SDK error.
    """
    with (
        mock.patch("hate_crack.llm.OpenAI") as openai_cls,
        mock.patch("hate_crack.llm.instructor.from_openai"),
    ):
        llm._build_client("http://localhost:8000", "", 30.0)
    assert openai_cls.call_args.kwargs["api_key"] == "ollama"


def test_generate_masks_substitutes_empty_api_key(monkeypatch):
    """generate_masks builds its own OpenAI client directly (not through
    _build_client), so it needs the same empty-key guard independently."""
    captured = {}

    def fake_openai(*, base_url, api_key, timeout):
        captured["api_key"] = api_key
        return mock.MagicMock()

    monkeypatch.setattr(llm, "OpenAI", fake_openai)
    monkeypatch.setattr(
        llm,
        "_rosetta_generate_masks",
        lambda description, **kwargs: [],
    )

    llm.generate_masks(
        "http://localhost:8000",
        "qwen2.5:32b",
        2048,
        "pins",
        no_cloud=False,
        backend="ollama",
        api_key="   ",
    )

    assert captured["api_key"] == "ollama"
