"""Structured LLM password-candidate generation via Atomic Agents + Ollama.

Isolates the atomic-agents / instructor dependency. The rest of hate_crack talks
to this module only through ``generate_candidates``.
"""

from typing import Any

import instructor
from openai import OpenAI
from pydantic import Field

from atomic_agents import AgentConfig, AtomicAgent, BaseIOSchema
from atomic_agents.context import SystemPromptGenerator

MAX_CANDIDATE_LEN = 128


class GenerationInput(BaseIOSchema):
    """Instruction and context for a password-candidate generation request."""

    request: str = Field(
        ..., description="The full instruction, including any target or sample context."
    )


class PasswordCandidatesOutput(BaseIOSchema):
    """A structured list of candidate passwords / basewords."""

    candidates: list[str] = Field(
        ...,
        description=(
            "Candidate passwords, one per list entry. No numbering, bullets, or "
            "explanation — just the raw candidate strings."
        ),
    )


_TARGET_PROMPT = SystemPromptGenerator(
    background=[
        "You are a security professional generating password candidates during an "
        "authorized penetration test / capture-the-flag exercise.",
    ],
    steps=[
        "Study the provided target context (company, industry, location).",
        "Derive basewords from the company name and industry terms.",
        "Combine basewords with common suffixes, years, and leetspeak substitutions.",
    ],
    output_instructions=[
        "Return only candidate passwords in the candidates list.",
        "Do not include explanations, numbering, or duplicate entries.",
    ],
)

_WORDLIST_PROMPT = SystemPromptGenerator(
    background=[
        "You build denylist basewords so users cannot set weak passwords.",
    ],
    steps=[
        "Study the sample passwords for patterns: capitalization, leetspeak, "
        "suffixes, and common substitutions.",
        "Produce basewords that capture those patterns.",
    ],
    output_instructions=[
        "Return only basewords in the candidates list.",
        "Do not include explanations, numbering, or duplicate entries.",
    ],
)


def _build_request(mode: str, context_data: dict) -> str:
    """Build the natural-language request string for the given mode."""
    if mode == "target":
        company = context_data.get("company", "")
        industry = context_data.get("industry", "")
        location = context_data.get("location", "")
        return (
            f"The target organization is '{company}', a {industry} in {location}. "
            "Generate as many plausible password candidates as you can, using "
            "permutations of the company name and industry terms with common "
            "suffixes, years, and leetspeak substitutions."
        )
    if mode == "wordlist":
        sample = context_data.get("sample", "")
        return (
            "Here are sample passwords. Study their patterns and generate basewords "
            "for a denylist:\n" + sample
        )
    raise ValueError(f"Unknown LLM generation mode: {mode}")


def generate_candidates(
    url: str,
    model: str,
    num_ctx: int,
    mode: str,
    context_data: dict,
) -> list[str]:
    """Generate password candidates via an Ollama-backed AtomicAgent.

    Returns a deduped, length-capped list of candidate strings (may be empty).
    Raises ValueError for an unknown mode. Client/connection errors propagate to
    the caller.
    """
    request = _build_request(mode, context_data)

    client = instructor.from_openai(
        OpenAI(base_url=f"{url}/v1", api_key="ollama"),
        mode=instructor.Mode.JSON,
    )
    prompt_generator = _TARGET_PROMPT if mode == "target" else _WORDLIST_PROMPT

    agent = AtomicAgent[GenerationInput, PasswordCandidatesOutput](
        config=AgentConfig(
            client=client,
            model=model,
            system_prompt_generator=prompt_generator,
            model_api_parameters={"extra_body": {"options": {"num_ctx": num_ctx}}},
        )
    )

    result: Any = agent.run(GenerationInput(request=request))

    seen: set[str] = set()
    candidates: list[str] = []
    for raw in getattr(result, "candidates", []) or []:
        candidate = str(raw).strip()
        if not candidate or len(candidate) > MAX_CANDIDATE_LEN:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        candidates.append(candidate)
    return candidates
