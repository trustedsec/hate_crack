"""main.py wiring for the OLLAMA_NO_CLOUD destination check (#274).

hate_crack/llm.py's ensure_destination_allowed / offsite_destination_warning
are unit-tested in tests/test_no_cloud_destination.py. This file covers the
main.py side: each of the four operator-facing entry points that reach the
LLM (hcatOllama, hcatOllamaPatterns, hcatOllamaResearchTarget, hcatRosettaMask)
prints the offsite warning at the start of the call, and prints a clean
refusal message (no misleading "Ensure ... is running" connectivity advice)
when llm.CloudDestinationRefused reaches it.

Every llm.* call is mocked, so no network and no DNS.
"""

import os
from contextlib import contextmanager
from unittest import mock

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import main as hc_main  # noqa: E402

# Exception/model instances below are built from hc_main.llm's *own* current
# reference, not a freshly re-imported top-level `hate_crack.llm` -- some
# existing tests elsewhere in this suite patch a string target like
# "hate_crack.main.llm.generate_masks". On Python 3.13, mock.patch resolves
# that via pkgutil.resolve_name, which -- because main.py sets its own
# __path__ so it can be treated as a package when loaded standalone (see
# main.py's "Allow submodule imports" comment) -- actually imports a *second*,
# non-identical copy of llm.py under the bogus name "hate_crack.main.llm" and
# leaves it permanently attached as hc_main.llm afterwards. That is a
# pre-existing test-isolation hazard, not something this file's tests should
# have to fix, so they sidestep it: constructing exceptions via hc_main.llm.X
# guarantees the `except llm.X` clause inside main.py (which also reads its
# own module-global `llm` at call time) is checking against the exact same
# class, whichever copy that happens to be.

# A well-known public IP literal -- offsite under is_offsite_url without any
# DNS resolution, so these tests never need an injected resolver. (Not an
# RFC 5737 documentation address: Python's ipaddress marks those private.)
OFFSITE_URL = "http://8.8.8.8:11434"
LOCAL_URL = "http://localhost:11434"
MODEL = "qwen2.5:32b"


@contextmanager
def _llm_globals(url):
    with (
        mock.patch.object(hc_main, "ollamaUrl", url),
        mock.patch.object(hc_main, "ollamaModel", MODEL),
        mock.patch.object(hc_main, "ollamaNumCtx", 2048),
        mock.patch.object(hc_main, "ollamaTimeout", 30.0),
        mock.patch.object(hc_main, "ollamaNoCloud", False),
        mock.patch.object(hc_main, "llmBackend", "ollama"),
        mock.patch.object(hc_main, "llmApiKey", "ollama"),
    ):
        yield


# ---------------------------------------------------------------------------
# hcatOllamaResearchTarget
# ---------------------------------------------------------------------------


def test_research_target_warns_for_an_offsite_destination(capsys):
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(hc_main, "ollamaAutoResearch", True),
        mock.patch.object(
            hc_main.llm,
            "research_target",
            return_value=hc_main.llm.TargetResearchOutput(
                industry="", location="", parent_company=""
            ),
        ),
    ):
        hc_main.hcatOllamaResearchTarget("Acme")
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "OLLAMA_NO_CLOUD" in out


def test_research_target_does_not_warn_for_a_local_destination(capsys):
    with (
        _llm_globals(LOCAL_URL),
        mock.patch.object(hc_main, "ollamaAutoResearch", True),
        mock.patch.object(
            hc_main.llm,
            "research_target",
            return_value=hc_main.llm.TargetResearchOutput(
                industry="", location="", parent_company=""
            ),
        ),
    ):
        hc_main.hcatOllamaResearchTarget("Acme")
    out = capsys.readouterr().out
    assert "OLLAMA_NO_CLOUD" not in out


def test_research_target_refusal_prints_a_clean_message(capsys):
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(hc_main, "ollamaAutoResearch", True),
        mock.patch.object(
            hc_main.llm,
            "research_target",
            side_effect=hc_main.llm.CloudDestinationRefused(OFFSITE_URL),
        ),
    ):
        result = hc_main.hcatOllamaResearchTarget("Acme")
    assert result == {"industry": "", "location": "", "parent_company": ""}
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "OLLAMA_NO_CLOUD" in out


# ---------------------------------------------------------------------------
# hcatOllama
# ---------------------------------------------------------------------------


def test_hcat_ollama_warns_for_an_offsite_destination(capsys):
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(hc_main.llm, "generate_candidates", return_value=[]),
    ):
        hc_main.hcatOllama("0", "/tmp/hashes.txt", "target", {"company": "Acme"})
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "OLLAMA_NO_CLOUD" in out


def test_hcat_ollama_does_not_warn_for_a_local_destination(capsys):
    with (
        _llm_globals(LOCAL_URL),
        mock.patch.object(hc_main.llm, "generate_candidates", return_value=[]),
    ):
        hc_main.hcatOllama("0", "/tmp/hashes.txt", "target", {"company": "Acme"})
    out = capsys.readouterr().out
    assert "OLLAMA_NO_CLOUD" not in out


def test_hcat_ollama_refusal_prints_a_clean_message(capsys):
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(
            hc_main.llm,
            "generate_candidates",
            side_effect=hc_main.llm.CloudDestinationRefused(OFFSITE_URL),
        ),
    ):
        hc_main.hcatOllama("0", "/tmp/hashes.txt", "target", {"company": "Acme"})
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    # No misleading connectivity advice for a refusal that never reached a
    # server.
    assert "Ensure" not in out


# ---------------------------------------------------------------------------
# hcatOllamaPatterns
# ---------------------------------------------------------------------------


def test_hcat_ollama_patterns_warns_for_an_offsite_destination(tmp_path, capsys):
    source = tmp_path / "corpus.txt"
    source.write_text("Password1\nSummer2024!\n")
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(
            hc_main, "_corpus_context", return_value={"summary": "stats"}
        ),
        mock.patch.object(hc_main.llm, "generate_candidates", return_value=[]),
    ):
        hc_main.hcatOllamaPatterns("0", "/tmp/hashes.txt", str(source))
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "OLLAMA_NO_CLOUD" in out


def test_hcat_ollama_patterns_does_not_warn_for_a_local_destination(tmp_path, capsys):
    source = tmp_path / "corpus.txt"
    source.write_text("Password1\nSummer2024!\n")
    with (
        _llm_globals(LOCAL_URL),
        mock.patch.object(
            hc_main, "_corpus_context", return_value={"summary": "stats"}
        ),
        mock.patch.object(hc_main.llm, "generate_candidates", return_value=[]),
    ):
        hc_main.hcatOllamaPatterns("0", "/tmp/hashes.txt", str(source))
    out = capsys.readouterr().out
    assert "OLLAMA_NO_CLOUD" not in out


def test_hcat_ollama_patterns_refusal_prints_a_clean_message(tmp_path, capsys):
    source = tmp_path / "corpus.txt"
    source.write_text("Password1\nSummer2024!\n")
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(
            hc_main, "_corpus_context", return_value={"summary": "stats"}
        ),
        mock.patch.object(
            hc_main.llm,
            "generate_candidates",
            side_effect=hc_main.llm.CloudDestinationRefused(OFFSITE_URL),
        ),
    ):
        hc_main.hcatOllamaPatterns("0", "/tmp/hashes.txt", str(source))
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "Ensure" not in out


# ---------------------------------------------------------------------------
# hcatRosettaMask
# ---------------------------------------------------------------------------


def test_hcat_rosetta_mask_warns_for_an_offsite_destination(tmp_path, capsys):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", ""),
        mock.patch.object(hc_main, "hcatPotfilePath", ""),
        mock.patch.object(hc_main.llm, "generate_masks", return_value=["?d?d?d?d"]),
        mock.patch("hate_crack.main.generate_session_id", return_value="s"),
        mock.patch("subprocess.Popen") as popen,
    ):
        popen.return_value.wait.return_value = 0
        popen.return_value.communicate.return_value = (b"", b"")
        popen.return_value.returncode = 0
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "OLLAMA_NO_CLOUD" in out


def test_hcat_rosetta_mask_does_not_warn_for_a_local_destination(tmp_path, capsys):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    with (
        _llm_globals(LOCAL_URL),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", ""),
        mock.patch.object(hc_main, "hcatPotfilePath", ""),
        mock.patch.object(hc_main.llm, "generate_masks", return_value=["?d?d?d?d"]),
        mock.patch("hate_crack.main.generate_session_id", return_value="s"),
        mock.patch("subprocess.Popen") as popen,
    ):
        popen.return_value.wait.return_value = 0
        popen.return_value.communicate.return_value = (b"", b"")
        popen.return_value.returncode = 0
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")
    out = capsys.readouterr().out
    assert "OLLAMA_NO_CLOUD" not in out


def test_hcat_rosetta_mask_refusal_prints_a_clean_message(tmp_path, capsys):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    with (
        _llm_globals(OFFSITE_URL),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", ""),
        mock.patch.object(hc_main, "hcatPotfilePath", ""),
        mock.patch.object(
            hc_main.llm,
            "generate_masks",
            side_effect=hc_main.llm.CloudDestinationRefused(OFFSITE_URL),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")
    popen.assert_not_called()
    out = capsys.readouterr().out
    assert "8.8.8.8" in out
    assert "Ensure the configured" not in out
