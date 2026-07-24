# LLM Attack Refactor onto Atomic Agents

**Date:** 2026-07-24
**Branch:** `feature/llm-atomic-agents`

## Goal

Replace the hand-rolled `urllib` + regex-parsing Ollama integration in the LLM
attack with a structured `AtomicAgent` (Atomic Agents framework) that returns a
validated Pydantic candidate list. Wire up the currently-unreachable `wordlist`
(denylist) generation mode so it is usable from the menu.

## Decisions (locked with user)

1. **Full atomic-agents** — use `AtomicAgent` + `SystemPromptGenerator` + Pydantic
   I/O schemas, not just raw instructor.
2. **Default model → `qwen2.5:32b`** — best structured-output adherence that runs
   comfortably on a 64 GB Apple-silicon MacBook (Q4 ~20 GB). Replaces `mistral`.
3. **Drop auto-pull** — remove `_pull_ollama_model`; on missing model / connection
   failure, print instructions to run `ollama serve` / `ollama pull <model>`.
4. **Keep + wire up wordlist mode** — port the denylist-from-sample-wordlist mode
   to the new design AND add a menu path so it is reachable.

## Architecture

### New module `hate_crack/llm.py`
Isolates the framework dependency and keeps `main.py` from growing.

- **Schemas** (Pydantic / `BaseIOSchema`):
  - `PasswordCandidatesOutput(candidates: list[str])` — shared output schema.
  - Target-mode and wordlist-mode input schemas (or a single input schema with
    optional fields — implementation detail for the plan).
- **System prompts**: two `SystemPromptGenerator` configs carrying the existing
  prompt intent:
  - *target*: CTF-partner framing, company/industry/location → candidate list.
  - *wordlist*: study sample passwords, emit basewords for a denylist.
- **`generate_candidates(url, model, num_ctx, mode, context_data) -> list[str]`**:
  - Client: `instructor.from_openai(OpenAI(base_url=f"{url}/v1", api_key="ollama"), mode=instructor.Mode.JSON)`.
  - `AgentConfig(client=..., model=..., system_prompt_generator=..., model_api_parameters={"extra_body": {"options": {"num_ctx": num_ctx}}})`.
  - Runs the agent, returns `output.candidates`, deduped and length-capped (≤128).
  - No regex line-cleaning — the schema guarantees structure.
  - Raises / returns empty on connection failure or refusal; caller reports.

### `main.py`
- `hcatOllama(hcatHashType, hcatHashFile, mode, context_data)` keeps hashcat
  orchestration (Step C wordlist run + Step D per-rule runs) but delegates
  candidate generation to `llm.generate_candidates(...)`.
- Delete `_pull_ollama_model`.
- Error UX on generation failure: "Ensure Ollama is running (`ollama serve`) and
  the model is pulled (`ollama pull <model>`)."
- Default `ollamaModel` fallback → `qwen2.5:32b`.

### `attacks.py` — `ollama_attack`
- Add a mode prompt:
  - `1. Target info` → existing company / industry / location prompts.
  - `2. Wordlist (denylist)` → wordlist picker reusing the
    `_omen_pick_training_wordlist` pattern; chosen path passed as `context_data`.

### Config / docs
- `config.json.example`: `ollamaModel` → `qwen2.5:32b`.
- `README.md`: update default and note auto-pull removed.
- `CHANGELOG.md`: new entry; version bump (own release per cadence).

### Dependencies
- Add `atomic-agents` to `pyproject.toml` `dependencies` (pulls in
  openai / instructor / pydantic). `uv sync`.

## Data Flow

```
ollama_attack (attacks.py)
  → prompt mode (target | wordlist) + gather context_data
  → ctx.hcatOllama(type, file, mode, context_data)        [main.py]
      → llm.generate_candidates(url, model, num_ctx, mode, context_data)  [llm.py]
          → AtomicAgent.run() via instructor→Ollama /v1
          → PasswordCandidatesOutput.candidates
      → write <hashfile>.ollama_candidates
      → hashcat wordlist run  (Step C)
      → hashcat per-rule runs (Step D)
```

## Error Handling
- Ollama unreachable → catch instructor/openai connection error, print serve/pull
  guidance, return without running hashcat.
- Model missing → same guidance (no auto-pull).
- Empty / refused candidates → "Ollama returned no usable password candidates."
- Wordlist mode: missing sample file → error and return.

## Testing
- **Remove** `tests/test_pull_ollama_model.py` (auto-pull dropped).
- **Update** `tests/test_attacks_behavior.py` and `tests/test_ui_menu_options.py`
  for the new mode prompt in `ollama_attack`.
- **Add** `tests/test_llm.py`: mock the instructor client / `AtomicAgent.run`,
  assert schema parsing, dedup + length cap, empty-result error path, and that
  `num_ctx` is forwarded via `model_api_parameters`.
- Verify `tests/test_optimized_kernel.py` still passes (touches ollama refs).
- Full suite: `HATE_CRACK_SKIP_INIT=1 uv run pytest -v`; lint via `make lint`.

## Out of Scope
- No change to OMEN, markov, or other attacks.
- No change to the hashcat run/rule-iteration logic beyond the delegation seam.
- No provider abstraction beyond Ollama (instructor supports others, not wired).
