# LLM Attack Refactor onto Atomic Agents — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled urllib+regex Ollama integration in the LLM attack with a structured `AtomicAgent` returning a validated Pydantic candidate list, and make the `wordlist` (denylist) generation mode reachable from the menu.

**Architecture:** A new `hate_crack/llm.py` module owns all Atomic Agents / instructor code and exposes one function, `generate_candidates(...)`, returning `list[str]`. `main.py`'s `hcatOllama` keeps hashcat orchestration (candidate wordlist run + per-rule runs) and delegates generation to that function. `attacks.py`'s `ollama_attack` gains a mode prompt (target vs wordlist). Auto-pull is removed.

**Tech Stack:** Python 3.13, atomic-agents (instructor + openai + pydantic), hashcat, pytest, uv, ruff/ty.

**Spec:** `docs/superpowers/specs/2026-07-24-llm-atomic-agents-design.md`

**Working dir:** worktree `/tmp/hate_crack-llm-atomic` on branch `feature/llm-atomic-agents`.

**Test invariant:** All pytest commands run with `HATE_CRACK_SKIP_INIT=1`.

---

## File Structure

- **Create** `hate_crack/llm.py` — schemas + `generate_candidates()`. Only file importing atomic-agents.
- **Create** `tests/test_llm.py` — unit tests for `generate_candidates()` (mocks the client + AtomicAgent).
- **Modify** `pyproject.toml` — add `atomic-agents` dependency.
- **Modify** `hate_crack/main.py` — rewrite `hcatOllama` to delegate; delete `_pull_ollama_model`; change `ollamaModel` default.
- **Modify** `hate_crack/attacks.py` — add mode prompt + wordlist picker to `ollama_attack`; generalize `_omen_pick_training_wordlist`.
- **Modify** `config.json.example`, `README.md`, `CHANGELOG.md` — default model + docs + version entry.
- **Delete** `tests/test_pull_ollama_model.py` — tests old internals (auto-pull, urllib, regex filtering) that no longer exist.
- **Modify** `tests/test_attacks_behavior.py` — update `TestOllamaAttack` for the new mode prompt.
- **Create** `tests/test_hcat_ollama.py` — new orchestration tests (mock `llm.generate_candidates`, assert hashcat steps).
- `tests/test_ui_menu_options.py` and `tests/test_optimized_kernel.py` — verify unaffected (option 12 mapping + `hcatOllama` attribute still exist).

---

### Task 1: Add the atomic-agents dependency

**Files:**
- Modify: `pyproject.toml` (the `dependencies = [...]` array)

- [ ] **Step 1: Add the dependency**

In `pyproject.toml`, change the `dependencies` array to add `atomic-agents`:

```toml
dependencies = [
    "requests>=2.31.0",
    "beautifulsoup4>=4.12.0",
    "openpyxl>=3.0.0",
    "packaging>=21.0",
    "simple-term-menu==1.6.6",
    "click>=8.0.0",
    "atomic-agents>=2.0.0",
]
```

- [ ] **Step 2: Sync the environment**

Run: `cd /tmp/hate_crack-llm-atomic && uv sync --dev`
Expected: resolves and installs `atomic-agents`, `instructor`, `openai`, `pydantic` (no errors).

- [ ] **Step 3: Verify the imports load**

Run: `cd /tmp/hate_crack-llm-atomic && uv run python -c "from atomic_agents import AtomicAgent, AgentConfig, BaseIOSchema; from atomic_agents.context import SystemPromptGenerator; import instructor; from openai import OpenAI; print('ok')"`
Expected: prints `ok`.

- [ ] **Step 4: Commit**

```bash
cd /tmp/hate_crack-llm-atomic
git add pyproject.toml uv.lock
git commit -m "build(deps): add atomic-agents for structured LLM candidate generation"
```

---

### Task 2: Create `hate_crack/llm.py` (TDD)

`generate_candidates` builds an instructor→Ollama client, runs an `AtomicAgent` with a
`PasswordCandidatesOutput` schema, and returns a deduped, length-capped `list[str]`.
`context_data` is ALWAYS a dict: target mode → `{"company","industry","location"}`;
wordlist mode → `{"sample": "<newline-joined sample passwords>"}`.

**Files:**
- Create: `hate_crack/llm.py`
- Test: `tests/test_llm.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_llm.py`:

```python
"""Unit tests for hate_crack.llm.generate_candidates."""

import os
from unittest import mock

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
        mock.patch("hate_crack.llm.instructor"),
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


def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        llm.generate_candidates(
            "http://localhost:11434", "qwen2.5:32b", 2048, "bogus", {},
        )
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_llm.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'hate_crack.llm'`.

- [ ] **Step 3: Implement `hate_crack/llm.py`**

Create `hate_crack/llm.py`:

```python
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
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_llm.py -v`
Expected: PASS (5 passed).

- [ ] **Step 5: Lint the new module**

Run: `cd /tmp/hate_crack-llm-atomic && uv run ruff check hate_crack/llm.py && uv run ty check hate_crack/llm.py`
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
cd /tmp/hate_crack-llm-atomic
git add hate_crack/llm.py tests/test_llm.py
git commit -m "feat(llm): structured candidate generation module via Atomic Agents"
```

---

### Task 3: Rewrite `hcatOllama` to delegate; delete `_pull_ollama_model` (TDD)

`hcatOllama` keeps its signature `(hcatHashType, hcatHashFile, mode, context_data)` and its
hashcat orchestration. For `wordlist` mode, `context_data` is a file PATH — `hcatOllama`
validates + reads it and passes `{"sample": ...}` to `llm.generate_candidates`. For
`target` mode, `context_data` is the dict, passed through unchanged.

**Files:**
- Modify: `hate_crack/main.py` — delete `_pull_ollama_model` (lines ~2039-2073); rewrite `hcatOllama` (lines ~2076-2284).
- Delete: `tests/test_pull_ollama_model.py`
- Create: `tests/test_hcat_ollama.py`

- [ ] **Step 1: Delete the obsolete test file**

Run: `cd /tmp/hate_crack-llm-atomic && git rm tests/test_pull_ollama_model.py`
Expected: file staged for deletion. (It tests auto-pull, urllib payloads, and regex
filtering — all removed by this refactor.)

- [ ] **Step 2: Write the new failing orchestration tests**

Create `tests/test_hcat_ollama.py`:

```python
"""Orchestration tests for hcatOllama (candidate generation is mocked)."""

import os
from types import SimpleNamespace
from contextlib import contextmanager
from unittest import mock

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import main as hc_main  # noqa: E402

OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen2.5:32b"


@pytest.fixture
def ollama_env(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    wordlist = tmp_path / "sample.txt"
    wordlist.write_text("password\n123456\nletmein\n")
    return SimpleNamespace(
        tmp_path=tmp_path, hash_file=str(hash_file), wordlist=str(wordlist)
    )


@contextmanager
def ollama_globals(tmp_path, tuning="", potfile=""):
    rules_dir = str(tmp_path / "rules")
    os.makedirs(rules_dir, exist_ok=True)
    with mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL), \
         mock.patch.object(hc_main, "ollamaModel", MODEL), \
         mock.patch.object(hc_main, "ollamaNumCtx", 2048), \
         mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"), \
         mock.patch.object(hc_main, "hcatTuning", tuning), \
         mock.patch.object(hc_main, "hcatPotfilePath", potfile), \
         mock.patch.object(hc_main, "rulesDirectory", rules_dir), \
         mock.patch("hate_crack.main.generate_session_id", return_value="s"):
        yield


def _make_proc(wait_return=0):
    proc = mock.MagicMock()
    proc.wait.return_value = wait_return
    proc.communicate.return_value = (b"", b"")
    proc.returncode = wait_return
    return proc


def test_pull_ollama_model_is_gone():
    assert not hasattr(hc_main, "_pull_ollama_model")


def test_target_mode_passes_dict_through(ollama_env):
    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates",
                    return_value=["Password1"]) as gen, \
         mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama(
            "0", ollama_env.hash_file, "target",
            {"company": "ACME", "industry": "tech", "location": "NYC"},
        )
    gen.assert_called_once()
    args = gen.call_args[0]
    assert args[0] == OLLAMA_URL and args[1] == MODEL and args[3] == "target"
    assert args[4] == {"company": "ACME", "industry": "tech", "location": "NYC"}


def test_wordlist_mode_reads_file_and_passes_sample(ollama_env):
    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates",
                    return_value=["Password1"]) as gen, \
         mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", ollama_env.hash_file, "wordlist", ollama_env.wordlist)
    ctx_data = gen.call_args[0][4]
    assert "letmein" in ctx_data["sample"]


def test_missing_wordlist_prints_error(ollama_env, capsys):
    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates") as gen:
        hc_main.hcatOllama("0", ollama_env.hash_file, "wordlist", "/no/such.txt")
    captured = capsys.readouterr()
    assert "Wordlist not found" in captured.out
    gen.assert_not_called()


def test_writes_candidates_and_runs_hashcat(ollama_env):
    calls = []

    def track_popen(cmd, **kwargs):
        calls.append(list(cmd))
        return _make_proc()

    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates",
                    return_value=["Password1", "Summer2024"]), \
         mock.patch("subprocess.Popen", side_effect=track_popen):
        hc_main.hcatOllama("1000", ollama_env.hash_file, "target",
                           {"company": "X", "industry": "Y", "location": "Z"})

    candidates_path = f"{ollama_env.hash_file}.ollama_candidates"
    assert os.path.isfile(candidates_path)
    with open(candidates_path) as f:
        assert f.read().splitlines() == ["Password1", "Summer2024"]
    # First hashcat call is the plain wordlist run with the candidates file.
    assert calls and candidates_path in calls[0]
    assert "-r" not in calls[0]


def test_empty_candidates_skips_hashcat(ollama_env, capsys):
    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates", return_value=[]), \
         mock.patch("subprocess.Popen") as popen:
        hc_main.hcatOllama("0", ollama_env.hash_file, "target",
                           {"company": "X", "industry": "Y", "location": "Z"})
    captured = capsys.readouterr()
    assert "no usable" in captured.out.lower()
    popen.assert_not_called()


def test_generation_error_reports_and_aborts(ollama_env, capsys):
    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates",
                    side_effect=Exception("connection refused")), \
         mock.patch("subprocess.Popen") as popen:
        hc_main.hcatOllama("0", ollama_env.hash_file, "target",
                           {"company": "X", "industry": "Y", "location": "Z"})
    captured = capsys.readouterr()
    assert "Ensure Ollama is running" in captured.out
    popen.assert_not_called()


def test_unknown_mode_prints_error(ollama_env, capsys):
    with ollama_globals(ollama_env.tmp_path), \
         mock.patch("hate_crack.main.llm.generate_candidates") as gen:
        hc_main.hcatOllama("0", ollama_env.hash_file, "bogus", {})
    captured = capsys.readouterr()
    assert "Unknown LLM generation mode" in captured.out
    gen.assert_not_called()
```

- [ ] **Step 3: Run the new tests to verify they fail**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_hcat_ollama.py -v`
Expected: FAIL — `hate_crack.main` has no attribute `llm` / old `hcatOllama` still calls urllib.

- [ ] **Step 4: Add the `llm` import in `main.py`**

Near the other `hate_crack` sub-module imports at the top of `hate_crack/main.py`, add:

```python
from hate_crack import llm
```

(Place it alongside the existing `from hate_crack import ...` imports. If there are none in that form, add `from . import llm` consistent with the module's import style.)

- [ ] **Step 5: Delete `_pull_ollama_model`**

Remove the entire `_pull_ollama_model` function (the block starting at the
`# Pull an Ollama model via the /api/pull streaming endpoint` comment through its
`return True`, ~lines 2039-2073).

- [ ] **Step 6: Replace the body of `hcatOllama`**

Replace the whole `hcatOllama` function (from `def hcatOllama(...)` through the end of
its Step D loop) with:

```python
# LLM Ollama Attack
def hcatOllama(hcatHashType, hcatHashFile, mode, context_data):
    global hcatProcess
    candidates_path = f"{hcatHashFile}.ollama_candidates"

    # Step A: normalize context into the dict generate_candidates expects.
    if mode == "wordlist":
        wordlist_path = context_data
        if not os.path.isfile(wordlist_path):
            print(f"Error: Wordlist not found: {wordlist_path}")
            return
        lines = []
        try:
            with open(wordlist_path, "r", errors="ignore") as f:
                for line in f:
                    stripped = line.strip()
                    if not stripped:
                        continue
                    # hash:password -> password
                    if ":" in stripped:
                        stripped = stripped.split(":", 1)[1]
                    if stripped:
                        lines.append(stripped)
        except Exception as e:
            print(f"Error reading wordlist: {e}")
            return
        print(f"Loaded {len(lines)} passwords from wordlist.")
        gen_context = {"sample": "\n".join(lines)}
    elif mode == "target":
        gen_context = context_data
    else:
        print(f"Error: Unknown LLM generation mode: {mode}")
        return

    # Step B: generate candidates via the Atomic Agents module.
    print(f"Generating password candidates via Ollama ({ollamaModel})...")
    try:
        candidates = llm.generate_candidates(
            ollamaUrl, ollamaModel, ollamaNumCtx, mode, gen_context
        )
    except ValueError as e:
        print(f"Error: {e}")
        return
    except Exception as e:
        print(f"Error generating candidates: {e}")
        print(
            "Ensure Ollama is running (ollama serve) and the model is pulled "
            f"(ollama pull {ollamaModel})."
        )
        return

    if not candidates:
        print("Error: Ollama returned no usable password candidates.")
        return

    try:
        with open(candidates_path, "w") as f:
            for candidate in candidates:
                f.write(candidate + "\n")
    except Exception as e:
        print(f"Error writing candidates file: {e}")
        return

    print(f"Generated {len(candidates)} password candidates -> {candidates_path}")

    # Step C: hashcat wordlist attack with the generated candidates (no rules).
    print("Running wordlist attack with LLM-generated candidates...")
    cmd = [
        hcatBin,
        "-m",
        hcatHashType,
        hcatHashFile,
        "--session",
        generate_session_id(),
        "-o",
        f"{hcatHashFile}.out",
        candidates_path,
    ]
    cmd.extend(shlex.split(hcatTuning))
    _append_potfile_arg(cmd)
    try:
        _run_hcat_cmd(
            cmd,
            attack_name="LLM",
            hash_file=hcatHashFile,
            reraise_interrupt=True,
        )
    except KeyboardInterrupt:
        return

    # Step D: hashcat with candidates against every rule in the rules directory.
    rule_files = sorted(f for f in os.listdir(rulesDirectory) if f != ".DS_Store")
    if not rule_files:
        print("No rule files found in rules directory. Skipping rule-based attacks.")
        return

    print(
        f"\nRunning LLM candidates with {len(rule_files)} rule file(s) from {rulesDirectory}..."
    )
    for rule in rule_files:
        rule_path = os.path.join(rulesDirectory, rule)
        print(f"\n\tRunning with rule: {rule}")
        cmd = [
            hcatBin,
            "-m",
            hcatHashType,
            hcatHashFile,
            "--session",
            generate_session_id(),
            "-o",
            f"{hcatHashFile}.out",
            "-r",
            rule_path,
            candidates_path,
        ]
        cmd.extend(shlex.split(hcatTuning))
        _append_potfile_arg(cmd)
        try:
            _run_hcat_cmd(
                cmd,
                attack_name="LLM",
                hash_file=hcatHashFile,
                reraise_interrupt=True,
            )
        except KeyboardInterrupt:
            return
```

- [ ] **Step 7: Remove now-unused imports if orphaned**

Check whether `re` and `urllib` are still used elsewhere in `main.py`:

Run: `cd /tmp/hate_crack-llm-atomic && grep -n "urllib\.\|re\.\(sub\|match\|search\|compile\|findall\)" hate_crack/main.py`
If `urllib.` no longer appears anywhere, remove its `import urllib.*` lines. If `re.` no
longer appears, remove `import re`. (Leave them if still referenced.)

- [ ] **Step 8: Run the orchestration tests**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_hcat_ollama.py -v`
Expected: PASS (9 passed).

- [ ] **Step 9: Commit**

```bash
cd /tmp/hate_crack-llm-atomic
git add hate_crack/main.py tests/test_hcat_ollama.py tests/test_pull_ollama_model.py
git commit -m "refactor(llm): delegate candidate generation to llm module; drop auto-pull"
```

---

### Task 4: Change the default model to `qwen2.5:32b`

**Files:**
- Modify: `hate_crack/main.py:454`
- Modify: `config.json.example:28`

- [ ] **Step 1: Update the code fallback**

In `hate_crack/main.py`, change line ~454:

```python
ollamaModel = config_parser.get("ollamaModel", "qwen2.5:32b")
```

- [ ] **Step 2: Update the example config**

In `config.json.example`, change the `ollamaModel` line:

```json
  "ollamaModel": "qwen2.5:32b",
```

- [ ] **Step 3: Verify the default loads**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run python -c "import os; os.environ['HATE_CRACK_SKIP_INIT']='1'; from hate_crack import main; print(main.ollamaModel)"`
Expected: prints a model string (`qwen2.5:32b` when no config overrides it).

- [ ] **Step 4: Commit**

```bash
cd /tmp/hate_crack-llm-atomic
git add hate_crack/main.py config.json.example
git commit -m "feat(llm): default Ollama model to qwen2.5:32b for structured output"
```

---

### Task 5: Wire up wordlist mode in `ollama_attack` (TDD)

Add a mode prompt to `ollama_attack`. Generalize `_omen_pick_training_wordlist` to accept a
title so the LLM wordlist picker reuses it without duplicating logic.

**Files:**
- Modify: `hate_crack/attacks.py` — `_omen_pick_training_wordlist` (~527) and `ollama_attack` (~513-524)
- Modify: `tests/test_attacks_behavior.py` — `TestOllamaAttack` (~328-369)

- [ ] **Step 1: Update the existing target-mode tests for the new prompt**

In `tests/test_attacks_behavior.py`, every `ollama_attack` test now needs to select mode
`"1"` (target) first. Replace the three `input` side-effect lists in `TestOllamaAttack`:

```python
class TestOllamaAttack:
    def test_calls_hcatOllama_with_context(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", side_effect=["1", "ACME", "tech", "NYC"]):
            ollama_attack(ctx)

        ctx.hcatOllama.assert_called_once_with(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            "target",
            {"company": "ACME", "industry": "tech", "location": "NYC"},
        )

    def test_passes_hash_type_and_file(self) -> None:
        ctx = _make_ctx(hash_type="1800", hash_file="/tmp/sha512.txt")

        with patch("builtins.input", side_effect=["1", "Corp", "finance", "London"]):
            ollama_attack(ctx)

        call_args = ctx.hcatOllama.call_args[0]
        assert call_args[0] == "1800"
        assert call_args[1] == "/tmp/sha512.txt"

    def test_strips_whitespace_from_inputs(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", side_effect=["1", "  ACME  ", "  tech  ", "  NYC  "]):
            ollama_attack(ctx)

        target_info = ctx.hcatOllama.call_args[0][3]
        assert target_info["company"] == "ACME"
        assert target_info["industry"] == "tech"
        assert target_info["location"] == "NYC"

    def test_target_string_is_literal_target(self) -> None:
        ctx = _make_ctx()

        with patch("builtins.input", side_effect=["1", "X", "Y", "Z"]):
            ollama_attack(ctx)

        assert ctx.hcatOllama.call_args[0][2] == "target"
```

- [ ] **Step 2: Add a failing test for wordlist mode**

Append to `TestOllamaAttack` in `tests/test_attacks_behavior.py`:

```python
    def test_wordlist_mode_calls_hcatOllama_with_path(self) -> None:
        ctx = _make_ctx()
        ctx.list_wordlist_files.return_value = ["rockyou.txt"]
        ctx.hcatWordlists = "/tmp/wl"

        # mode "2", then pick wordlist "1"
        with patch("builtins.input", side_effect=["2", "1"]):
            ollama_attack(ctx)

        args = ctx.hcatOllama.call_args[0]
        assert args[2] == "wordlist"
        assert args[3].endswith("rockyou.txt")

    def test_invalid_mode_does_not_call_hcatOllama(self) -> None:
        ctx = _make_ctx()
        with patch("builtins.input", side_effect=["9"]):
            ollama_attack(ctx)
        ctx.hcatOllama.assert_not_called()
```

Check `_make_ctx` in this file provides a MagicMock ctx (it does — attributes auto-create).
If `list_wordlist_files` needs a default, the test sets it explicitly above.

- [ ] **Step 3: Run the ollama tests to verify the new ones fail**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_attacks_behavior.py::TestOllamaAttack -v`
Expected: the two new tests FAIL (old handler ignores the mode prompt / no wordlist path).

- [ ] **Step 4: Generalize the wordlist picker**

In `hate_crack/attacks.py`, change `_omen_pick_training_wordlist` to accept a title. Update
its signature and the `print_multicolumn_list` call:

```python
def _omen_pick_training_wordlist(ctx: Any, title: str = "Training Wordlists"):
    """Show wordlist picker. Returns path or None."""
    wordlist_files = ctx.list_wordlist_files(ctx.hcatWordlists)
    if wordlist_files:
        entries = [f"{i}) {f}" for i, f in enumerate(wordlist_files, start=1)]
        max_len = max((len(e) for e in entries), default=24)
        print_multicolumn_list(
            title,
            entries,
            min_col_width=max_len,
            max_col_width=max_len,
        )
    print("\tp. Enter a custom path")
    sel = input("\n\tSelect wordlist: ").strip()
    if sel.lower() == "p":
        path = input("\n\tPath to wordlist: ").strip()
        return path if path else None
    try:
        idx = int(sel)
        if 1 <= idx <= len(wordlist_files):
            return os.path.join(ctx.hcatWordlists, wordlist_files[idx - 1])
    except (ValueError, IndexError):
        pass
    print("\t[!] Invalid selection.")
    return None
```

(The existing `omen_attack` call `ctx._omen_model_dir()`... uses `_omen_pick_training_wordlist(ctx)`
with no title — still valid via the default.)

- [ ] **Step 5: Rewrite `ollama_attack` with the mode prompt**

Replace `ollama_attack` in `hate_crack/attacks.py`:

```python
def ollama_attack(ctx: Any) -> None:
    _notify.prompt_notify_for_attack("LLM")
    print("\n\tLLM Attack")
    print("\t1. Target info (company / industry / location)")
    print("\t2. Wordlist (generate basewords from a sample wordlist)")
    choice = input("\n\tSelect generation mode: ").strip()

    if choice == "1":
        company = input("Company name: ").strip()
        industry = input("Industry: ").strip()
        location = input("Location: ").strip()
        ctx.hcatOllama(
            ctx.hcatHashType,
            ctx.hcatHashFile,
            "target",
            {"company": company, "industry": industry, "location": location},
        )
    elif choice == "2":
        path = _omen_pick_training_wordlist(ctx, title="LLM Sample Wordlists")
        if not path:
            return
        ctx.hcatOllama(ctx.hcatHashType, ctx.hcatHashFile, "wordlist", path)
    else:
        print("\t[!] Invalid selection.")
```

- [ ] **Step 6: Run the ollama handler tests**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest tests/test_attacks_behavior.py::TestOllamaAttack -v`
Expected: PASS (6 passed).

- [ ] **Step 7: Commit**

```bash
cd /tmp/hate_crack-llm-atomic
git add hate_crack/attacks.py tests/test_attacks_behavior.py
git commit -m "feat(llm): add wordlist (denylist) mode to LLM attack menu"
```

---

### Task 6: Full suite + lint, then docs & changelog

**Files:**
- Modify: `README.md:460-473`
- Modify: `CHANGELOG.md` (new entry after line 8)

- [ ] **Step 1: Run the entire test suite**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest -v`
Expected: all pass. If `tests/test_ui_menu_options.py` (option 12 → `ollama_attack`) or
`tests/test_optimized_kernel.py` (references `hcatOllama`) fail, fix per their assertions —
both the option-12 mapping and the `hcatOllama` symbol still exist, so they should pass
unchanged.

- [ ] **Step 2: Lint**

Run: `cd /tmp/hate_crack-llm-atomic && make lint`
Expected: ruff + ty clean. Fix any unused-import / typing findings.

- [ ] **Step 3: Update the README Ollama section**

In `README.md`, replace the Ollama configuration block (lines ~464-473):

```json
{
  "ollamaModel": "qwen2.5:32b",
  "ollamaNumCtx": 2048
}
```

```markdown
- **`ollamaModel`** — The Ollama model used for candidate generation (default: `qwen2.5:32b`). The LLM attack uses structured (JSON) output, so choose a model with good tool/JSON support.
- **`ollamaNumCtx`** — Context window size for the model (default: `2048`).
- The Ollama URL defaults to `http://localhost:11434` (override via the `OLLAMA_HOST` env var). Ensure Ollama is running and the model is pulled (`ollama pull qwen2.5:32b`) before using the LLM Attack — hate_crack no longer auto-pulls missing models.
```

- [ ] **Step 4: Add the CHANGELOG entry**

In `CHANGELOG.md`, insert after line 8 (before `## [2.11.3]`):

```markdown
## [2.12.0] - 2026-07-24

### Changed

- **LLM attack now uses the Atomic Agents framework** for structured (JSON) candidate
  generation instead of raw HTTP + regex line-parsing. Candidate generation lives in the
  new `hate_crack/llm.py` module.
- **Default Ollama model is now `qwen2.5:32b`** (was `mistral`), chosen for reliable
  structured-output adherence.

### Added

- **Wordlist (denylist) generation mode** for the LLM attack is now reachable from the
  menu: select the LLM attack, then choose "Wordlist" to derive basewords from a sample
  wordlist.

### Removed

- **Automatic model pulling.** hate_crack no longer pulls missing Ollama models; pull them
  yourself with `ollama pull <model>`.
```

- [ ] **Step 5: Commit**

```bash
cd /tmp/hate_crack-llm-atomic
git add README.md CHANGELOG.md
git commit -m "docs(llm): document Atomic Agents refactor, new default model, wordlist mode (2.12.0)"
```

---

### Task 7: Final verification

- [ ] **Step 1: Full suite once more**

Run: `cd /tmp/hate_crack-llm-atomic && HATE_CRACK_SKIP_INIT=1 uv run pytest -v`
Expected: all pass.

- [ ] **Step 2: Lint once more**

Run: `cd /tmp/hate_crack-llm-atomic && make lint`
Expected: clean.

- [ ] **Step 3: Confirm the branch is ready**

Run: `cd /tmp/hate_crack-llm-atomic && git log --oneline main..HEAD && git status`
Expected: the task commits listed, clean working tree.

**Release note:** version is derived from git tags via setuptools_scm — tag `v2.12.0` at
release time (per the project's per-change release cadence). Merge back via PR from the
worktree branch.

---

## Self-Review Notes

- **Spec coverage:** new module (T2), delegation + auto-pull removal (T3), default model (T4), wordlist menu wiring (T5), deps (T1), tests (T2/T3/T5), docs+changelog+version (T6). All spec sections mapped.
- **num_ctx risk:** resolved — forwarded via `AgentConfig.model_api_parameters={"extra_body": {"options": {"num_ctx": N}}}` (T2), asserted in `test_num_ctx_forwarded_via_model_api_parameters`.
- **Contract consistency:** `generate_candidates(url, model, num_ctx, mode, context_data)` signature identical across `llm.py` (T2), `main.py` call (T3), and tests. `context_data` is always a dict at the `llm` boundary; `hcatOllama` converts the wordlist path → `{"sample": ...}`.
- **Type consistency:** `PasswordCandidatesOutput.candidates` used in `llm.py` and asserted via mock `.candidates` in tests. `_omen_pick_training_wordlist(ctx, title=...)` default keeps the existing `omen_attack` caller valid.
