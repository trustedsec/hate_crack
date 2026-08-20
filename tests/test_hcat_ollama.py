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

# Hash fields are recognized by digest length, so fixtures need realistic ones:
# a short stand-in is correctly read as part of the password.
DIGEST_A = "31d6cfe0d16ae931b73c59d7e0c089c0"
DIGEST_B = "8846f7eaee8fb117ad06bdd830b7586c"


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
    with (
        mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL),
        mock.patch.object(hc_main, "ollamaModel", MODEL),
        mock.patch.object(hc_main, "ollamaNumCtx", 2048),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", tuning),
        mock.patch.object(hc_main, "hcatPotfilePath", potfile),
        mock.patch.object(hc_main, "rulesDirectory", rules_dir),
        mock.patch("hate_crack.main.generate_session_id", return_value="s"),
    ):
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
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Password1"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "ACME", "industry": "tech", "location": "NYC"},
        )
    gen.assert_called_once()
    args = gen.call_args[0]
    assert args[0] == OLLAMA_URL and args[1] == MODEL and args[3] == "target"
    assert args[4] == {"company": "ACME", "industry": "tech", "location": "NYC"}


def test_wordlist_mode_reads_file_and_passes_sample(ollama_env):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Password1"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama("0", ollama_env.hash_file, "wordlist", ollama_env.wordlist)
    ctx_data = gen.call_args[0][4]
    assert "letmein" in ctx_data["sample"]


def test_wordlist_mode_strips_hash_prefix(ollama_env):
    # hash:password lines should contribute only the post-colon plaintext.
    dump = ollama_env.tmp_path / "dump.txt"
    dump.write_text(f"{DIGEST_A}:Bravo2024\nnocolonline\n")
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["x"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama("0", ollama_env.hash_file, "wordlist", str(dump))
    sample = gen.call_args[0][4]["sample"]
    assert "Bravo2024" in sample
    assert DIGEST_A not in sample
    assert "nocolonline" in sample


def test_per_rule_runs_hashcat_with_rule_flag(ollama_env):
    rules_dir = str(ollama_env.tmp_path / "rules")
    os.makedirs(rules_dir, exist_ok=True)
    rule_file = os.path.join(rules_dir, "test.rule")
    open(rule_file, "w").close()
    calls = []

    def track_popen(cmd, **kwargs):
        calls.append(list(cmd))
        return _make_proc()

    with (
        mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL),
        mock.patch.object(hc_main, "ollamaModel", MODEL),
        mock.patch.object(hc_main, "ollamaNumCtx", 2048),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", ""),
        mock.patch.object(hc_main, "hcatPotfilePath", ""),
        mock.patch.object(hc_main, "rulesDirectory", rules_dir),
        mock.patch("hate_crack.main.generate_session_id", return_value="s"),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Password1"]
        ),
        mock.patch("subprocess.Popen", side_effect=track_popen),
    ):
        hc_main.hcatOllama(
            "1000",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )

    # call 0 = plain wordlist run, call 1 = rule run
    assert len(calls) == 2
    rule_call = calls[1]
    assert "-r" in rule_call
    assert rule_file in rule_call


def test_missing_wordlist_prints_error(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates") as gen,
    ):
        hc_main.hcatOllama("0", ollama_env.hash_file, "wordlist", "/no/such.txt")
    captured = capsys.readouterr()
    assert "Wordlist not found" in captured.out
    gen.assert_not_called()


def test_writes_candidates_and_runs_hashcat(ollama_env):
    calls = []

    def track_popen(cmd, **kwargs):
        calls.append(list(cmd))
        return _make_proc()

    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            return_value=["Password1", "Summer2024"],
        ),
        mock.patch("subprocess.Popen", side_effect=track_popen),
    ):
        hc_main.hcatOllama(
            "1000",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )

    candidates_path = f"{ollama_env.hash_file}.ollama_candidates"
    assert os.path.isfile(candidates_path)
    with open(candidates_path) as f:
        assert f.read().splitlines() == ["Password1", "Summer2024"]
    # First hashcat call is the plain wordlist run with the candidates file.
    assert calls and candidates_path in calls[0]
    assert "-r" not in calls[0]


def test_empty_candidates_skips_hashcat(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=[]),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    captured = capsys.readouterr()
    assert "no usable" in captured.out.lower()
    popen.assert_not_called()


def test_generation_error_reports_and_aborts(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=Exception("connection refused"),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    captured = capsys.readouterr()
    assert "Ensure Ollama is running" in captured.out
    popen.assert_not_called()


def test_empty_candidates_on_vllm_backend_names_vllm_not_ollama(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch.object(hc_main, "llmBackend", "vllm"),
        mock.patch.object(hc_main, "llmApiKey", "sk-real-vllm-key"),
        mock.patch("hate_crack.main.llm.generate_candidates", return_value=[]),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    captured = capsys.readouterr()
    assert "vLLM returned no usable password candidates" in captured.out
    assert "Ollama returned" not in captured.out
    popen.assert_not_called()


def test_generation_error_on_vllm_backend_does_not_mention_ollama(ollama_env, capsys):
    """Regression guard for the backend-aware connection-help text.

    A vLLM operator must not be told to run ``ollama serve``/``ollama pull`` --
    that is the exact misleading-error class the backend selector exists to
    remove. Checks presence of the vLLM-appropriate text AND absence of the
    Ollama-specific text, so a refactor that collapses back to one hardcoded
    string fails here even if it happens to still print *something*.
    """
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch.object(hc_main, "llmBackend", "vllm"),
        mock.patch.object(hc_main, "llmApiKey", "sk-real-vllm-key"),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=Exception("connection refused"),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    captured = capsys.readouterr()
    assert "vLLM" in captured.out
    assert OLLAMA_URL in captured.out
    assert "ollama serve" not in captured.out
    assert "ollama pull" not in captured.out
    assert "Ensure Ollama is running" not in captured.out
    popen.assert_not_called()


def test_timeout_error_reports_timeout_guidance(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch.object(hc_main, "ollamaTimeout", 300.0),
        mock.patch(
            "hate_crack.main.llm.generate_candidates",
            side_effect=hc_main.llm.LLMTimeoutError("timed out"),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    captured = capsys.readouterr()
    assert "timed out" in captured.out.lower()
    assert "300" in captured.out
    # Names the .env key, not the config.json legacy name: OLLAMA_TIMEOUT is a
    # home="env" key after the split.
    assert "OLLAMA_TIMEOUT" in captured.out
    assert ".env" in captured.out
    assert "Ensure Ollama is running" not in captured.out
    popen.assert_not_called()
    assert not os.path.isfile(f"{ollama_env.hash_file}.ollama_candidates")


def test_value_error_reports_message_and_aborts(ollama_env, capsys):
    """Covers the defensive `except ValueError` handler in hcatOllama."""
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", side_effect=ValueError("boom")
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    captured = capsys.readouterr()
    assert "Error: boom" in captured.out
    popen.assert_not_called()
    assert not os.path.isfile(f"{ollama_env.hash_file}.ollama_candidates")


def test_timeout_config_forwarded_to_generate_candidates(ollama_env):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch.object(hc_main, "ollamaTimeout", 77.0),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Password1"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama(
            "0",
            ollama_env.hash_file,
            "target",
            {"company": "X", "industry": "Y", "location": "Z"},
        )
    assert gen.call_args.kwargs["timeout"] == 77.0


def test_unknown_mode_prints_error(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates") as gen,
    ):
        hc_main.hcatOllama("0", ollama_env.hash_file, "bogus", {})
    captured = capsys.readouterr()
    assert "Unknown LLM generation mode" in captured.out
    gen.assert_not_called()


# ---------------------------------------------------------------------------
# cracked mode
# ---------------------------------------------------------------------------


def test_cracked_mode_samples_out_file(ollama_env):
    """cracked mode reads <hashfile>.out and passes the plaintexts as the sample."""
    with open(f"{ollama_env.hash_file}.out", "w") as f:
        f.write(f"{DIGEST_A}:Alpha2024!\n{DIGEST_B}:Delta2023\n")

    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Winter2025!"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama("1000", ollama_env.hash_file, "cracked", None)

    args = gen.call_args[0]
    assert args[3] == "cracked"
    sample = args[4]["sample"].splitlines()
    assert sample == ["Alpha2024!", "Delta2023"]
    # Hash portions must not leak into the prompt.
    assert DIGEST_A not in args[4]["sample"]


def test_cracked_mode_accepts_explicit_path(ollama_env):
    """An explicit path in context_data is honoured (what attacks.py passes)."""
    out_path = f"{ollama_env.hash_file}.out"
    with open(out_path, "w") as f:
        f.write("hash:Falcons2024\n")

    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Falcons2025"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama("1000", ollama_env.hash_file, "cracked", out_path)

    assert "Falcons2024" in gen.call_args[0][4]["sample"]


def test_cracked_mode_missing_out_file_prints_error(ollama_env, capsys):
    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates") as gen,
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama("0", ollama_env.hash_file, "cracked", None)
    captured = capsys.readouterr()
    assert "No cracked passwords found" in captured.out
    gen.assert_not_called()
    popen.assert_not_called()


def test_cracked_mode_empty_out_file_prints_error(ollama_env, capsys):
    """An existing but empty/blank .out must abort before calling the LLM."""
    with open(f"{ollama_env.hash_file}.out", "w") as f:
        f.write("\n   \n")

    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch("hate_crack.main.llm.generate_candidates") as gen,
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatOllama("0", ollama_env.hash_file, "cracked", None)
    captured = capsys.readouterr()
    assert "No cracked passwords yet" in captured.out
    gen.assert_not_called()
    popen.assert_not_called()


def test_cracked_mode_writes_candidates_to_separate_file(ollama_env):
    """The candidate file must be distinct from the .out file it samples."""
    out_path = f"{ollama_env.hash_file}.out"
    with open(out_path, "w") as f:
        f.write("hash:Summer2024!\n")

    with (
        ollama_globals(ollama_env.tmp_path),
        mock.patch(
            "hate_crack.main.llm.generate_candidates", return_value=["Winter2025!"]
        ),
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatOllama("1000", ollama_env.hash_file, "cracked", None)

    candidates_path = f"{ollama_env.hash_file}.ollama_candidates"
    assert candidates_path != out_path
    with open(candidates_path) as f:
        assert f.read().splitlines() == ["Winter2025!"]
    # The sampled source file is untouched by candidate writing.
    with open(out_path) as f:
        assert f.read() == "hash:Summer2024!\n"
