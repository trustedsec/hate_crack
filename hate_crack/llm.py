"""Structured LLM password-candidate generation via Atomic Agents + Ollama.

Isolates the atomic-agents / instructor dependency. The rest of hate_crack talks
to this module only through ``generate_candidates``.
"""

import instructor
from openai import APITimeoutError, OpenAI
from pydantic import Field

from atomic_agents import AgentConfig, AtomicAgent, BaseIOSchema
from atomic_agents.context import SystemPromptGenerator

MAX_CANDIDATE_LEN = 128
DEFAULT_TIMEOUT_SECONDS = 300.0


class LLMTimeoutError(Exception):
    """The LLM server accepted the request but did not respond in time.

    Raised instead of ``openai.APITimeoutError`` so callers do not need to import
    ``openai`` themselves.
    """


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

_CRACKED_PROMPT = SystemPromptGenerator(
    background=[
        "You are a security professional generating password candidates during an "
        "authorized penetration test.",
        "The passwords you are shown were already recovered from this specific "
        "target organization, so they reveal that organization's real password "
        "conventions.",
    ],
    steps=[
        "Study the recovered plaintexts for the organization's conventions: "
        "basewords, capitalization, seasons and months, years, separators, "
        "suffixes, and leetspeak substitutions.",
        "Infer the naming habits behind them (company and product names, local "
        "sports teams, site or department names, keyboard walks).",
        "Generate NEW candidates that follow the same conventions, varying the "
        "basewords, years, and suffixes the organization clearly favours.",
    ],
    output_instructions=[
        "Return only candidate passwords in the candidates list.",
        "Do not repeat any password that appears in the input — those are already "
        "cracked and retrying them is wasted work.",
        "Do not include explanations, numbering, or duplicate entries.",
    ],
)

_PROMPTS = {
    "target": _TARGET_PROMPT,
    "wordlist": _WORDLIST_PROMPT,
    "cracked": _CRACKED_PROMPT,
}


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
    if mode == "cracked":
        sample = context_data.get("sample", "")
        return (
            "These passwords were already cracked from the target organization. "
            "Study the conventions they reveal and generate as many NEW password "
            "candidates as you can that follow the same conventions. Do not repeat "
            "any of these:\n" + sample
        )
    raise ValueError(f"Unknown LLM generation mode: {mode}")


def generate_candidates(
    url: str,
    model: str,
    num_ctx: int,
    mode: str,
    context_data: dict,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> list[str]:
    """Generate password candidates via an Ollama-backed AtomicAgent.

    ``timeout`` is the number of seconds to wait for a generation response before
    giving up; it bounds the whole request so a server that accepts the
    connection but never replies (e.g. a large model still loading into VRAM)
    cannot hang the caller forever.

    Returns a deduped, length-capped list of candidate strings (may be empty).
    Raises ValueError for an unknown mode and LLMTimeoutError if the request
    exceeds ``timeout``. Other client/connection errors propagate to the caller.
    """
    request = _build_request(mode, context_data)

    client = instructor.from_openai(
        OpenAI(base_url=f"{url}/v1", api_key="ollama", timeout=timeout),
        mode=instructor.Mode.JSON,
    )
    # _build_request has already rejected unknown modes, so this lookup is safe.
    prompt_generator = _PROMPTS[mode]

    agent = AtomicAgent[GenerationInput, PasswordCandidatesOutput](
        config=AgentConfig(
            client=client,
            model=model,
            system_prompt_generator=prompt_generator,
            model_api_parameters={"extra_body": {"options": {"num_ctx": num_ctx}}},
        )
    )

    try:
        result = agent.run(GenerationInput(request=request))
    except APITimeoutError as e:
        raise LLMTimeoutError(
            f"no response from {url} within {timeout:g} seconds"
        ) from e

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
