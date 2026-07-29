"""Structured LLM password-candidate generation via Atomic Agents + Ollama.

Isolates the atomic-agents / instructor dependency. The rest of hate_crack talks
to this module only through ``generate_candidates`` and ``research_target``.
"""

import instructor
from openai import APITimeoutError, OpenAI
from pydantic import Field

from atomic_agents import AgentConfig, AtomicAgent, BaseIOSchema
from atomic_agents.context import SystemPromptGenerator

MAX_CANDIDATE_LEN = 128
DEFAULT_TIMEOUT_SECONDS = 300.0

# Researched target fields are pasted into an interactive prompt as an editable
# default, so they must stay short enough to fit on one terminal line.
MAX_RESEARCH_FIELD_LEN = 80


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


class TargetResearchInput(BaseIOSchema):
    """The company name to recall industry and location details for."""

    company: str = Field(
        ..., description="The name of the target organization, exactly as typed."
    )


class TargetResearchOutput(BaseIOSchema):
    """Recalled industry and location for a named organization, or empty strings."""

    industry: str = Field(
        ...,
        description=(
            "The organization's industry or sector as a short phrase, e.g. "
            "'regional healthcare provider' or 'commercial construction'. Return "
            "an empty string if you do not actually recognize this organization."
        ),
    )
    location: str = Field(
        ...,
        description=(
            "The organization's primary location as 'City, State/Country'. Return "
            "an empty string if you do not actually recognize this organization."
        ),
    )


_RESEARCH_PROMPT = SystemPromptGenerator(
    background=[
        "You are assisting a security professional on an authorized penetration "
        "test who is about to generate password candidates for a named client "
        "organization.",
        "You have no internet access. You may only answer from what you already "
        "know about the organization.",
        "Most client organizations are small and will be completely unknown to "
        "you. That is the expected case, not a failure.",
    ],
    steps=[
        "Decide whether you genuinely recognize this specific organization by name.",
        "If you do, recall its industry or sector and its primary location.",
        "If you do not recognize it, or you are not reasonably confident, do not "
        "guess and do not infer anything from the words in the name.",
    ],
    output_instructions=[
        "Return an empty string for any field you are not reasonably confident "
        "about. An empty field is correct and useful; a fabricated one is harmful "
        "because the operator may mistake it for real intelligence.",
        "Keep each field under 80 characters.",
        "Return only the industry and location fields — no explanations, "
        "hedging, caveats, or commentary.",
    ],
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

_PATTERN_PROMPT = SystemPromptGenerator(
    background=[
        "You are a security professional working an authorized penetration test.",
        "The sample passwords you are shown come from the target environment, so "
        "the words behind them reveal what that organization's users draw on when "
        "they invent a password.",
        "Your output is a baseword list. A separate hashcat rule file will supply "
        "all of the capitalization, digits, years, separators, suffixes, and "
        "leetspeak — so decorating a baseword yourself only wastes a slot.",
    ],
    steps=[
        "Strip each sample password down to the word or words behind it, ignoring "
        "case, digits, and punctuation.",
        "Group those words into the semantic families they belong to: the company "
        "and its products, site or department names, local sports teams and city "
        "names, seasons and months, hobbies, mascots, keyboard walks.",
        "For every family you identify, list more members of that family than the "
        "sample actually contains — the point is to predict the words other users "
        "at this organization chose, not to echo the ones already recovered.",
    ],
    output_instructions=[
        "Return lowercase letters only. No digits, punctuation, spaces, or "
        "capitals anywhere in a baseword — the rules add those.",
        "One baseword per list entry. Multi-word basewords run together, e.g. "
        "'acmewidgets', not 'acme widgets'.",
        "Skip generic filler such as 'password', 'welcome', 'letmein', and "
        "'qwerty'. Stock wordlists already cover those, so they crowd out the "
        "organization-specific guesses that make this list worth running.",
        "Do not include explanations, numbering, or duplicate entries.",
    ],
)

_PROMPTS = {
    "target": _TARGET_PROMPT,
    "wordlist": _WORDLIST_PROMPT,
    "cracked": _CRACKED_PROMPT,
    "pattern": _PATTERN_PROMPT,
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
    if mode == "pattern":
        sample = context_data.get("sample", "")
        return (
            "Here is a sample of passwords from the target environment. Identify "
            "the semantic families of words behind them, then return as many "
            "lowercase letters-only basewords from those families as you can, "
            "including words the sample does not contain. Hashcat rules will "
            "mutate these, so add no digits, capitals, or punctuation:\n" + sample
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


def _build_client(url: str, timeout: float) -> instructor.Instructor:
    """Build the instructor-wrapped OpenAI client pointed at an Ollama server."""
    return instructor.from_openai(
        OpenAI(base_url=f"{url}/v1", api_key="ollama", timeout=timeout),
        mode=instructor.Mode.JSON,
    )


def clean_research_field(value: object) -> str:
    """Strip and length-cap one researched field; return '' for no suggestion.

    Anything that is not a non-empty string after stripping — including a model
    that echoed whitespace or an over-long ramble — becomes '' so the caller
    falls back to a plain blank prompt instead of pasting model noise into it.
    """
    if not isinstance(value, str):
        return ""
    cleaned = " ".join(value.split())
    if len(cleaned) > MAX_RESEARCH_FIELD_LEN:
        cleaned = cleaned[:MAX_RESEARCH_FIELD_LEN].rstrip()
    return cleaned


def research_target(
    url: str,
    model: str,
    num_ctx: int,
    company: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> TargetResearchOutput:
    """Ask the local model what it already knows about *company*.

    Returns a ``TargetResearchOutput`` whose ``industry`` and ``location`` are
    stripped and capped at ``MAX_RESEARCH_FIELD_LEN``; either may be '' when the
    model is not confident, which callers must treat as "no suggestion".

    Uses only the configured local Ollama server — no web lookups, so the client
    name never leaves the host. Raises LLMTimeoutError if the request exceeds
    ``timeout``; other client/connection errors propagate to the caller.
    """
    client = _build_client(url, timeout)

    agent = AtomicAgent[TargetResearchInput, TargetResearchOutput](
        config=AgentConfig(
            client=client,
            model=model,
            system_prompt_generator=_RESEARCH_PROMPT,
            model_api_parameters={"extra_body": {"options": {"num_ctx": num_ctx}}},
        )
    )

    try:
        result = agent.run(TargetResearchInput(company=company))
    except APITimeoutError as e:
        raise LLMTimeoutError(
            f"no response from {url} within {timeout:g} seconds"
        ) from e

    return TargetResearchOutput(
        industry=clean_research_field(getattr(result, "industry", "")),
        location=clean_research_field(getattr(result, "location", "")),
    )


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

    client = _build_client(url, timeout)
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
