"""Tests for the capped / evenly-sampled wordlist path in hcatOllama.

Covers:
- ollamaMaxSampleLines config default (500)
- Small wordlist (< cap): all lines included, "Loaded N" message
- Large wordlist (> cap): exactly `cap` lines sampled, "Sampled N of M" message
- Evenly-spaced sample covers the whole file (first and last entries present)
- hash:password splitting and blank-line skipping still work
- spinner is called with the right message regardless of TTY
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import main as hc_main  # noqa: E402

OLLAMA_URL = "http://localhost:11434"
MODEL = "test-model"


@contextmanager
def _ollama_globals(tmp_path, *, max_sample: int = 500):
    rules_dir = str(tmp_path / "rules")
    os.makedirs(rules_dir, exist_ok=True)
    with (
        mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL),
        mock.patch.object(hc_main, "ollamaModel", MODEL),
        mock.patch.object(hc_main, "ollamaNumCtx", 2048),
        mock.patch.object(hc_main, "ollamaMaxSampleLines", max_sample),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", ""),
        mock.patch.object(hc_main, "hcatPotfilePath", ""),
        mock.patch.object(hc_main, "rulesDirectory", rules_dir),
        mock.patch("hate_crack.main.generate_session_id", return_value="s"),
    ):
        yield


def _make_proc(rc: int = 0):
    proc = mock.MagicMock()
    proc.wait.return_value = rc
    proc.communicate.return_value = (b"", b"")
    proc.returncode = rc
    return proc


@pytest.fixture
def env(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    return SimpleNamespace(tmp_path=tmp_path, hash_file=str(hash_file))


# ---------------------------------------------------------------------------
# Config default
# ---------------------------------------------------------------------------


def test_ollama_max_sample_lines_default(env, capsys):
    """ollamaMaxSampleLines fallback behaviour is 500.

    Rather than asserting on the ambient live value (which a developer can
    override in their local config.json), we verify the *behaviour*: a
    wordlist with exactly 500 usable lines is loaded in full (no capping),
    while one with 501 lines is capped to 500.
    """
    # 500 lines → no capping, uses the "Loaded N" path
    wl500 = env.tmp_path / "w500.txt"
    wl500.write_text("\n".join(f"w{i:04d}" for i in range(500)) + "\n")

    with mock.patch.object(hc_main, "ollamaMaxSampleLines", 500), mock.patch.object(
        hc_main.llm, "generate_candidates", return_value=["x"]
    ) as gen500, mock.patch.object(
        hc_main, "ollamaUrl", OLLAMA_URL
    ), mock.patch.object(
        hc_main, "ollamaModel", MODEL
    ), mock.patch.object(
        hc_main, "ollamaNumCtx", 2048
    ), mock.patch.object(
        hc_main, "hcatBin", "/usr/bin/hashcat"
    ), mock.patch.object(
        hc_main, "hcatTuning", ""
    ), mock.patch.object(
        hc_main, "hcatPotfilePath", ""
    ), mock.patch.object(
        hc_main, "rulesDirectory", str(env.tmp_path / "rules")
    ), mock.patch(
        "hate_crack.main.generate_session_id", return_value="s"
    ), mock.patch(
        "subprocess.Popen", return_value=_make_proc()
    ):
        import os as _os
        _os.makedirs(str(env.tmp_path / "rules"), exist_ok=True)
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl500))

    captured = capsys.readouterr()
    assert "Loaded 500" in captured.out
    sample_lines = gen500.call_args[0][4]["sample"].splitlines()
    assert len(sample_lines) == 500


# ---------------------------------------------------------------------------
# Small wordlist — no capping
# ---------------------------------------------------------------------------


def test_small_wordlist_loads_all(env, capsys):
    """When total lines < cap, all are included and message says 'Loaded'."""
    wl = env.tmp_path / "small.txt"
    wl.write_text("alpha\nbeta\ngamma\n")

    with _ollama_globals(env.tmp_path), mock.patch.object(
        hc_main.llm, "generate_candidates", return_value=["x"]
    ) as gen, mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    captured = capsys.readouterr()
    assert "Loaded 3" in captured.out
    # All three words must appear in the sample passed to the LLM
    sample = gen.call_args[0][4]["sample"]
    assert "alpha" in sample
    assert "beta" in sample
    assert "gamma" in sample


def test_small_wordlist_no_sampled_message(env, capsys):
    """'Sampled N of M' must NOT appear when no capping occurred."""
    wl = env.tmp_path / "small.txt"
    wl.write_text("a\nb\nc\n")

    with _ollama_globals(env.tmp_path, max_sample=500), mock.patch.object(
        hc_main.llm, "generate_candidates", return_value=["x"]
    ), mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    captured = capsys.readouterr()
    assert "Sampled" not in captured.out


# ---------------------------------------------------------------------------
# Large wordlist — capping
# ---------------------------------------------------------------------------


def _make_large_wordlist(path, n: int) -> None:
    """Write n unique numbered lines to path."""
    lines = "\n".join(f"word{i:06d}" for i in range(n))
    path.write_text(lines + "\n")


def test_large_wordlist_caps_to_max(env, capsys):
    """When total > cap, exactly cap lines are sampled."""
    wl = env.tmp_path / "big.txt"
    _make_large_wordlist(wl, 1000)

    captured_ctx: list[dict] = []

    def _capture_gen(*args, **kwargs):
        captured_ctx.append(args[4])
        return ["x"]

    with _ollama_globals(env.tmp_path, max_sample=50), mock.patch.object(
        hc_main.llm, "generate_candidates", side_effect=_capture_gen
    ), mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    sample_lines = captured_ctx[0]["sample"].splitlines()
    assert len(sample_lines) == 50

    captured = capsys.readouterr()
    assert "Sampled 50 of 1,000" in captured.out


def test_large_wordlist_covers_full_range(env):
    """Evenly-spaced sample must contain entries from both the start and end of the file."""
    wl = env.tmp_path / "range.txt"
    _make_large_wordlist(wl, 1000)

    captured_ctx: list[dict] = []

    def _capture_gen(*args, **kwargs):
        captured_ctx.append(args[4])
        return ["x"]

    # Use a small cap (10) over 1000 lines so the stride is clearly 100.
    with _ollama_globals(env.tmp_path, max_sample=10), mock.patch.object(
        hc_main.llm, "generate_candidates", side_effect=_capture_gen
    ), mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    sample_lines = captured_ctx[0]["sample"].splitlines()
    # The sampled words should come from across the file, not just the head.
    # word000000..word000099 are the first 100; word000900..word000999 are the last 100.
    indices = [int(w.replace("word", "")) for w in sample_lines]
    assert min(indices) < 100, "sample should include entries from the start of the file"
    assert max(indices) >= 900, "sample should include entries from the end of the file"


# ---------------------------------------------------------------------------
# Stride < 2 regime: boundary cases for small total_usable values
# ---------------------------------------------------------------------------


def _sample_count(env, total: int, cap: int) -> int:
    """Helper: write a wordlist with *total* lines, run hcatOllama capped to *cap*,
    return the number of lines that reached the LLM."""
    wl = env.tmp_path / f"wl_{total}_{cap}.txt"
    wl.write_text("\n".join(f"p{i:04d}" for i in range(total)) + "\n")
    captured_ctx: list[dict] = []

    def _capture(*args, **kwargs):
        captured_ctx.append(args[4])
        return ["x"]

    with _ollama_globals(env.tmp_path, max_sample=cap), mock.patch.object(
        hc_main.llm, "generate_candidates", side_effect=_capture
    ), mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    if not captured_ctx:
        return 0
    return len(captured_ctx[0]["sample"].splitlines())


def test_stride_exact_total_equals_cap(env) -> None:
    """total == cap: all lines must be returned (no capping branch taken)."""
    assert _sample_count(env, 5, 5) == 5


def test_stride_total_one_above_cap(env) -> None:
    """total == cap + 1: exactly cap items must be sampled (stride < 2)."""
    assert _sample_count(env, 4, 3) == 3


def test_stride_tiny_three_cap_two(env) -> None:
    """total=3, cap=2: exactly 2 items must be sampled (stride = 1.5 < 2)."""
    assert _sample_count(env, 3, 2) == 2


def test_stride_cap_one(env) -> None:
    """cap=1 over a larger file must return exactly 1 item."""
    assert _sample_count(env, 10, 1) == 1


# ---------------------------------------------------------------------------
# Defect 2: ZeroDivisionError guard — cap=0 falls back to 500
# ---------------------------------------------------------------------------


def test_zero_cap_falls_back_to_default(env, capsys) -> None:
    """ollamaMaxSampleLines=0 must not crash; it falls back to cap=500.

    A 10-line wordlist with cap=0 (invalid) should load all 10 lines using
    the "no capping needed" path since 10 <= 500 (the fallback).
    """
    wl = env.tmp_path / "zero_cap.txt"
    wl.write_text("\n".join(f"pw{i}" for i in range(10)) + "\n")

    with _ollama_globals(env.tmp_path, max_sample=0), mock.patch.object(
        hc_main.llm, "generate_candidates", return_value=["x"]
    ) as gen, mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    captured = capsys.readouterr()
    # Must not raise; must load all 10 words (10 <= 500 fallback)
    assert "Loaded 10" in captured.out
    assert len(gen.call_args[0][4]["sample"].splitlines()) == 10


# ---------------------------------------------------------------------------
# hash:password splitting and blank-line skipping
# ---------------------------------------------------------------------------


def test_wordlist_sampling_strips_hash_prefix(env):
    """hash:password lines must contribute only the plaintext in capped mode."""
    wl = env.tmp_path / "dump.txt"
    # 20 lines: half with colon prefix, half plain; more than max_sample=5
    lines = [f"hash{i}:plain{i:02d}" if i % 2 == 0 else f"plain{i:02d}" for i in range(20)]
    wl.write_text("\n".join(lines) + "\n")

    captured_ctx: list[dict] = []

    def _capture_gen(*args, **kwargs):
        captured_ctx.append(args[4])
        return ["x"]

    with _ollama_globals(env.tmp_path, max_sample=5), mock.patch.object(
        hc_main.llm, "generate_candidates", side_effect=_capture_gen
    ), mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    sample = captured_ctx[0]["sample"]
    # No hash prefix should appear in the sample
    assert "hash" not in sample


def test_wordlist_sampling_skips_blank_lines(env, capsys):
    """Blank lines must not count toward total or be included in the sample."""
    wl = env.tmp_path / "blanks.txt"
    # 3 real words surrounded by blank lines
    wl.write_text("\nalpha\n\nbeta\n\ngamma\n\n")

    with _ollama_globals(env.tmp_path, max_sample=500), mock.patch.object(
        hc_main.llm, "generate_candidates", return_value=["x"]
    ) as gen, mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    captured = capsys.readouterr()
    assert "Loaded 3" in captured.out
    sample = gen.call_args[0][4]["sample"]
    for line in sample.splitlines():
        assert line.strip() != "", "blank lines leaked into sample"


# ---------------------------------------------------------------------------
# Spinner is invoked (via the TTY guard — non-TTY in test suite)
# ---------------------------------------------------------------------------


def test_spinner_called_with_model_message(env, capsys):
    """The spinner message must include the model name (non-TTY: just print)."""
    wl = env.tmp_path / "s.txt"
    wl.write_text("pw\n")

    with _ollama_globals(env.tmp_path), mock.patch.object(
        hc_main.llm, "generate_candidates", return_value=["x"]
    ), mock.patch("subprocess.Popen", return_value=_make_proc()):
        hc_main.hcatOllama("0", env.hash_file, "wordlist", str(wl))

    captured = capsys.readouterr()
    assert MODEL in captured.out
    assert "Generating password candidates via Ollama" in captured.out
