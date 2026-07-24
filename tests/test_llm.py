"""Unit tests for hate_crack.llm.generate_candidates."""

import os
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
        mock.patch("hate_crack.llm.instructor.from_openai", return_value=mock.MagicMock(spec=instructor.Instructor)),
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
        )
    run_arg = agent_instance.run.call_args[0][0]
    assert "letmein" in run_arg.request


def test_dedupes_and_caps_length():
    long_pw = "A" * 129
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(
        ["  keep  ", "keep", "dup", "dup", long_pw, ""]
    )
    with p_instr, p_openai, p_agent:
        out = llm.generate_candidates(
            "http://localhost:11434", "qwen2.5:32b", 2048,
            "target", {"company": "X", "industry": "Y", "location": "Z"},
        )
    assert out == ["keep", "dup"]  # trimmed, deduped, blank + >128 dropped


def test_num_ctx_forwarded_via_model_api_parameters():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai, p_agent:
        llm.generate_candidates(
            "http://localhost:11434", "qwen2.5:32b", 4096,
            "target", {"company": "X", "industry": "Y", "location": "Z"},
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
            "http://localhost:11434", "qwen2.5:32b", 2048, "bogus", {},
        )


def test_timeout_forwarded_to_openai_client():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai as openai_cls, p_agent:
        llm.generate_candidates(
            "http://localhost:11434", "qwen2.5:32b", 2048,
            "target", {"company": "X", "industry": "Y", "location": "Z"},
            timeout=42.5,
        )
    assert openai_cls.call_args.kwargs["timeout"] == 42.5


def test_default_timeout_used_when_omitted():
    p_instr, p_openai, p_agent, agent_cls, agent_instance = _patch_agent(["x"])
    with p_instr, p_openai as openai_cls, p_agent:
        llm.generate_candidates(
            "http://localhost:11434", "qwen2.5:32b", 2048,
            "target", {"company": "X", "industry": "Y", "location": "Z"},
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
                "http://localhost:11434", "qwen2.5:32b", 2048,
                "target", {"company": "X", "industry": "Y", "location": "Z"},
                timeout=1.0,
            )
