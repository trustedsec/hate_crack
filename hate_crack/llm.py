"""Structured LLM password-candidate generation via Atomic Agents + Ollama.

Isolates the atomic-agents / instructor dependency. The rest of hate_crack talks
to this module only through ``generate_candidates`` and ``research_target``.

``generate_masks`` is the one exception: it delegates entirely to
``hashcat_rosetta.nlmask.generate_masks`` rather than using Atomic Agents,
so hate_crack's mask-attack prompt, output schema, and hcmask validation
all come from HashcatRosetta itself instead of a second, hand-maintained
copy that would drift from it.
"""

import os
import sys

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

# Import HashcatRosetta for mask generation. This module doesn't import
# hate_crack.main (nor is it guaranteed to be imported after main.py's own
# sys.path insertion -- main.py imports this module before doing that), so
# it needs its own independent path setup rather than relying on main.py's.
# See hate_crack.main.ROSETTA_IMPORT_ERROR for the identical pattern; the
# two guards are deliberately separate rather than shared; either module
# can be imported and used standalone.
_ROSETTA_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "HashcatRosetta")
)
# Holds the ImportError when HashcatRosetta could not be imported, else None.
ROSETTA_MASK_IMPORT_ERROR = None
try:
    if _ROSETTA_DIR not in sys.path:
        sys.path.insert(0, _ROSETTA_DIR)
    from hashcat_rosetta.mask import format_hcmask_line as _rosetta_format_hcmask_line
    from hashcat_rosetta.nlmask import (
        MaskGenerationError as _RosettaMaskGenerationError,
    )
    from hashcat_rosetta.nlmask import generate_masks as _rosetta_generate_masks
except ImportError as _rosetta_mask_import_error:
    ROSETTA_MASK_IMPORT_ERROR = _rosetta_mask_import_error
    _rosetta_format_hcmask_line = None
    _RosettaMaskGenerationError = None
    _rosetta_generate_masks = None


def rosetta_mask_unavailable_reason() -> str:
    """Return a human-readable explanation for HashcatRosetta being missing.

    Mirrors ``hate_crack.main.rosetta_unavailable_reason`` -- see that
    function's docstring for why the underlying ImportError is preserved
    rather than discarded.
    """
    message = (
        "HashcatRosetta is unavailable. Run: git submodule update --init HashcatRosetta"
    )
    if ROSETTA_MASK_IMPORT_ERROR is not None:
        message += f" (import failed: {ROSETTA_MASK_IMPORT_ERROR!r})"
    return message


class LLMTimeoutError(Exception):
    """The LLM server accepted the request but did not respond in time.

    Raised instead of ``openai.APITimeoutError`` so callers do not need to import
    ``openai`` themselves.
    """


class CloudModelRefused(Exception):
    """``OLLAMA_NO_CLOUD`` is set and the configured model is cloud-hosted."""

    def __init__(self, model: str) -> None:
        self.model = model
        super().__init__(
            f"{model!r} is an Ollama cloud model and OLLAMA_NO_CLOUD is set. "
            "Prompts carry client corpus and target details, so this request "
            "was not sent. Pick a locally-hosted model, or unset "
            "OLLAMA_NO_CLOUD in your .env."
        )


def is_cloud_model(model: str) -> bool:
    """Is *model* one Ollama proxies to ollama.com rather than running locally?

    Cloud models are identified by a ``-cloud`` suffix on the tag
    (``gpt-oss:120b-cloud``, ``deepseek-v3.1:671b-cloud``) or, untagged, on the
    name itself. The local daemon accepts them at the same ``/v1`` endpoint as
    a local model and forwards the prompt offsite, so the request looks
    identical from here -- the name is the only signal available before the
    data has already left.
    """
    return model.strip().rsplit(":", 1)[-1].endswith("-cloud")


def ensure_model_allowed(model: str, *, no_cloud: bool) -> None:
    """Raise :class:`CloudModelRefused` for a cloud model when *no_cloud*.

    Called by every public entry point in this module rather than by their
    callers, so the guard cannot be bypassed by reaching past ``main.py``.
    ``no_cloud`` is keyword-only and has no default for the same reason: a new
    call site has to state its policy instead of silently inheriting a
    permissive one.
    """
    if no_cloud and is_cloud_model(model):
        raise CloudModelRefused(model)


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


class HashcatRulesOutput(BaseIOSchema):
    """A structured list of hashcat rule strings."""

    rules: list[str] = Field(
        ...,
        description=(
            "Hashcat rules, one per list entry. Each entry is the raw rule "
            "string of single-character functions, e.g. 'c$2$0$2$5'. No "
            "numbering, comments, quoting, or explanation."
        ),
    )


class TargetResearchInput(BaseIOSchema):
    """The company name to recall industry and location details for."""

    company: str = Field(
        ..., description="The name of the target organization, exactly as typed."
    )


class TargetResearchOutput(BaseIOSchema):
    """Recalled industry, location, and parent company for a named organization, or empty strings."""

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
    parent_company: str = Field(
        ...,
        description=(
            "The organization's parent company or the company that acquired it, "
            "if you specifically recall an acquisition or merger, e.g. 'Acquired "
            "by Global Corp in 2021'. Return an empty string if you do not "
            "genuinely recall an acquisition, or if the organization is "
            "independent as far as you know."
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
        "If you do, recall its industry or sector, its primary location, and "
        "whether you specifically recall it being acquired by or merged into "
        "another company.",
        "If you do not recognize it, or you are not reasonably confident, do not "
        "guess and do not infer anything from the words in the name.",
    ],
    output_instructions=[
        "Return an empty string for any field you are not reasonably confident "
        "about. An empty field is correct and useful; a fabricated one is harmful "
        "because the operator may mistake it for real intelligence.",
        "Keep each field under 80 characters.",
        "Return only the industry, location, and parent_company fields — no "
        "explanations, hedging, caveats, or commentary.",
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
        "Read the corpus statistics. They cover every password in the corpus, so "
        "a baseword's share tells you how much of the organization chose it — "
        "treat the high-share entries as the strongest signal about what these "
        "users draw on.",
        "Strip each word you are shown down to the word or words behind it, "
        "ignoring case, digits, and punctuation.",
        "Group them into the semantic families they belong to: the company "
        "and its products, site or department names, local sports teams and city "
        "names, seasons and months, hobbies, mascots, keyboard walks.",
        "For every family you identify, list more members of that family than the "
        "corpus actually contains — the point is to predict the words other users "
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

_RULES_PROMPT = SystemPromptGenerator(
    background=[
        "You are a security professional working an authorized penetration test.",
        "You write hashcat rules. A rule is a string of single-character "
        "functions applied left to right to a candidate baseword.",
        "A separate baseword list supplies the words. Your rules supply "
        "everything else: capitalization, digits, years, symbols, leetspeak.",
        "The functions you may use, and nothing else: ':' no-op, 'l' lowercase "
        "all, 'u' uppercase all, 'c' capitalize first, 'C' lowercase first and "
        "uppercase the rest, 't' toggle all, 'TN' toggle position N, '$X' append "
        "character X, '^X' prepend character X, 'DN' delete position N, '[' "
        "delete first, ']' delete last, 'r' reverse, 'd' duplicate, 'sXY' "
        "replace every X with Y.",
        "Positions are single characters: 0-9 for 0-9, then A-Z for 10-35.",
        "Every append and prepend takes exactly one character, so a two-character "
        "suffix needs two functions. To append the digits 99, write '$9$9'. To "
        "append the symbol '$' itself, write '$$' — one function whose argument "
        "happens to be a dollar sign.",
    ],
    steps=[
        "Read the corpus statistics. The mask, casing, length, trailing-digit "
        "and trailing-symbol tables describe how this organization decorates a "
        "word, and each entry's share tells you how many users decorate it that "
        "way.",
        "Work through the tables one entry at a time and write the rule that "
        "reproduces that entry on a plain lowercase baseword. A capitalized word "
        "with a year appended is 'c' then '$2' '$0' '$2' '$5', written together "
        "as 'c$2$0$2$5'. An all-caps word with a symbol and two digits is "
        "'u$#$4$2'.",
        "Cover every distinct shape the statistics show, not only the most "
        "common one. A mask or suffix listed at 8% is 8% of the corpus you leave "
        "uncracked by skipping it.",
        "Then add variations around each shape — the neighbouring years, the "
        "other common symbols, the same suffix without the capital, the suffix "
        "on an all-caps word — since the point is to predict decorations the "
        "corpus does not already contain.",
    ],
    output_instructions=[
        "Return one rule per list entry. A rule is the raw function string with "
        "no quotes, no comments, no '#' lines, and no explanation.",
        "Return at least 40 rules, and more when the statistics show more shapes. "
        "A handful of rules wastes the run: the operator gets one pass over the "
        "basewords and every shape you omit is a shape that goes uncracked.",
        "Use only the functions listed above. Any other character makes the rule "
        "invalid and it will be discarded.",
        "Never include a literal newline or tab inside a rule.",
        "Keep each rule under 31 functions.",
        "Do not include duplicate rules.",
    ],
)

_PROMPTS = {
    "target": _TARGET_PROMPT,
    "wordlist": _WORDLIST_PROMPT,
    "cracked": _CRACKED_PROMPT,
    "pattern": _PATTERN_PROMPT,
    "rules": _RULES_PROMPT,
}


def _corpus_block(context_data: dict) -> str:
    """Render the corpus portion of a request from *context_data*.

    ``summary`` holds whole-corpus statistics (see hate_crack.corpus_stats) and
    ``sample`` the literal plaintexts, which are only present when the whole
    corpus fit under the sample cap. Either may be absent; both are labelled so
    the model does not mistake a frequency table for a list of passwords to
    return.
    """
    parts = []
    summary = context_data.get("summary", "")
    sample = context_data.get("sample", "")
    if summary:
        parts.append("=== CORPUS STATISTICS (whole corpus) ===\n" + summary)
    if sample:
        parts.append("=== PASSWORDS ===\n" + sample)
    return "\n".join(parts)


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
        return (
            "Here is a description of a password corpus. Study its patterns and "
            "generate basewords for a denylist:\n" + _corpus_block(context_data)
        )
    if mode == "pattern":
        return (
            "Here is a description of the passwords in the target environment. "
            "Identify the semantic families of words behind them, then return as "
            "many lowercase letters-only basewords from those families as you "
            "can, including words the corpus does not contain. The statistics "
            "tell you which basewords and habits dominate the organization, so "
            "weight your answer toward the families the common ones belong to. "
            "Hashcat rules will mutate these, so add no digits, capitals, or "
            "punctuation:\n" + _corpus_block(context_data)
        )
    if mode == "rules":
        return (
            "Here is a description of the passwords in the target environment. "
            "Study the decoration habits it reveals — where users put capitals, "
            "which digits and years they append, which symbols they favour, how "
            "they substitute letters — and return hashcat rules that reproduce "
            "those habits. The masks, casing shares, and trailing-digit and "
            "trailing-symbol tables tell you which decorations dominate, so "
            "order your rules with the most common first:\n"
            + _corpus_block(context_data)
        )
    if mode == "cracked":
        return (
            "The passwords described below were already cracked from the target "
            "organization. Study the conventions they reveal and generate as many "
            "NEW password candidates as you can that follow the same conventions. "
            "Do not repeat any password shown to you, and note that a high-share "
            "baseword in the statistics is one many users chose, so it is worth "
            "varying rather than repeating:\n" + _corpus_block(context_data)
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
    *,
    no_cloud: bool,
) -> TargetResearchOutput:
    """Ask the local model what it already knows about *company*.

    Returns a ``TargetResearchOutput`` whose ``industry`` and ``location`` are
    stripped and capped at ``MAX_RESEARCH_FIELD_LEN``; either may be '' when the
    model is not confident, which callers must treat as "no suggestion".

    Uses only the configured local Ollama server — no web lookups, so the client
    name never leaves the host. Raises LLMTimeoutError if the request exceeds
    ``timeout``, CloudModelRefused when ``no_cloud`` rules out ``model``; other
    client/connection errors propagate to the caller.
    """
    ensure_model_allowed(model, no_cloud=no_cloud)
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
        parent_company=clean_research_field(getattr(result, "parent_company", "")),
    )


def generate_candidates(
    url: str,
    model: str,
    num_ctx: int,
    mode: str,
    context_data: dict,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    no_cloud: bool,
) -> list[str]:
    """Generate password candidates via an Ollama-backed AtomicAgent.

    ``timeout`` is the number of seconds to wait for a generation response before
    giving up; it bounds the whole request so a server that accepts the
    connection but never replies (e.g. a large model still loading into VRAM)
    cannot hang the caller forever.

    Returns a deduped, length-capped list of candidate strings (may be empty).
    Raises ValueError for an unknown mode, LLMTimeoutError if the request
    exceeds ``timeout``, and CloudModelRefused when ``no_cloud`` rules out
    ``model``. Other client/connection errors propagate to the caller.
    """
    ensure_model_allowed(model, no_cloud=no_cloud)
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


def generate_rules(
    url: str,
    model: str,
    num_ctx: int,
    context_data: dict,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    no_cloud: bool,
) -> list[str]:
    """Generate hashcat rules describing a corpus's decoration habits.

    The companion to ``generate_candidates(mode="pattern")``: that call infers
    the basewords, this one infers the rules that mutate them, so the pair
    covers what the Spoonman attack derives mechanically (see
    hate_crack.rulegen).

    Returns a deduped list of raw rule strings in the order the model gave them,
    which its prompt asks to be most-productive-first. Entries are *not*
    validated here — callers must screen them with ``rulegen.validate_rule``
    before handing the file to hashcat, since an invalid rule is dropped
    silently rather than reported.

    Raises LLMTimeoutError if the request exceeds ``timeout``,
    CloudModelRefused when ``no_cloud`` rules out ``model``; other
    client/connection errors propagate to the caller.
    """
    ensure_model_allowed(model, no_cloud=no_cloud)
    request = _build_request("rules", context_data)
    client = _build_client(url, timeout)

    agent = AtomicAgent[GenerationInput, HashcatRulesOutput](
        config=AgentConfig(
            client=client,
            model=model,
            system_prompt_generator=_PROMPTS["rules"],
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
    rules: list[str] = []
    for raw in getattr(result, "rules", []) or []:
        # A non-string entry is model noise, not a rule; str() on it would turn
        # None into the literal "None", which validate_rule would then reject
        # for the wrong reason.
        if not isinstance(raw, str):
            continue
        # Surrounding whitespace goes so that '  c$1  ' and 'c$1' dedupe against
        # each other. The cost is that a rule ending in a literal space
        # argument ('$ ', append a space) cannot come back from the model this
        # way — worth it, since models pad far more often than they append
        # spaces, and an unstripped rule would otherwise slip past dedup.
        rule = raw.strip()
        if not rule or rule in seen:
            continue
        seen.add(rule)
        rules.append(rule)
    return rules


def generate_masks(
    url: str,
    model: str,
    num_ctx: int,
    description: str,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    *,
    no_cloud: bool,
) -> list[str]:
    """Generate hashcat brute-force masks from a plain-English description.

    Unlike the other generation modes, this one takes no corpus context — the
    operator's free-text description of expected password shapes is the whole
    request. Unlike them too, this one delegates entirely to
    ``hashcat_rosetta.nlmask.generate_masks`` rather than using Atomic Agents
    directly -- the prompt, the output schema (including custom charsets),
    hcmask syntax validation, and the one-retry-on-failure behavior all come
    from HashcatRosetta itself, so this module never carries its own
    independent copy of any of that to drift out of sync.

    Each suggestion HashcatRosetta returns (a mask plus 0-8 custom charsets)
    is combined into a single canonical hcmask line via
    ``hashcat_rosetta.mask.format_hcmask_line`` before being returned here.

    Returns a deduped list of hcmask line strings in the order HashcatRosetta
    gave them. Every entry is already syntax-validated -- unlike the other
    generation modes in this module, there is no separate screening step
    callers need to run before handing the file to hashcat.

    Raises LLMTimeoutError if the request exceeds ``timeout``,
    CloudModelRefused when ``no_cloud`` rules out ``model``, RuntimeError if
    HashcatRosetta itself is unavailable (see
    ``rosetta_mask_unavailable_reason``); other client/connection errors
    propagate as HashcatRosetta's own MaskGenerationError.
    """
    ensure_model_allowed(model, no_cloud=no_cloud)

    # The three names are always set together in the single try/except above
    # (all real or all None) -- checking all three, not just the one this
    # function calls first, is what lets the type checker narrow the later
    # uses of the other two instead of still seeing `X | None`.
    if (
        _rosetta_generate_masks is None
        or _RosettaMaskGenerationError is None
        or _rosetta_format_hcmask_line is None
    ):
        raise RuntimeError(rosetta_mask_unavailable_reason())

    client = OpenAI(base_url=f"{url}/v1", api_key="ollama", timeout=timeout)

    try:
        suggestions = _rosetta_generate_masks(
            description,
            model=model,
            client=client,
            extra_options={"num_ctx": num_ctx},
        )
    except _RosettaMaskGenerationError as e:
        # HashcatRosetta wraps every request failure (including a plain
        # openai.APITimeoutError) into its own MaskGenerationError, but
        # preserves the original as __cause__ (`raise ... from exc`) -- that
        # chained exception, not string-matching the message, is what tells
        # a genuine timeout apart from every other failure it also wraps the
        # same way (connection refused, bad JSON, validation failure after
        # retry, ...).
        if isinstance(e.__cause__, APITimeoutError):
            raise LLMTimeoutError(
                f"no response from {url} within {timeout:g} seconds"
            ) from e
        raise

    seen: set[str] = set()
    masks: list[str] = []
    for suggestion in suggestions:
        combined = _rosetta_format_hcmask_line(
            suggestion.custom_charsets, suggestion.mask
        )
        if combined in seen:
            continue
        seen.add(combined)
        masks.append(combined)
    return masks
