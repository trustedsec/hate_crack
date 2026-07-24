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
