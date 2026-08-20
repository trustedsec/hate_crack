"""Orchestration tests for hcatRosettaMask (mask generation is mocked)."""

import os
from contextlib import contextmanager
from unittest import mock

os.environ["HATE_CRACK_SKIP_INIT"] = "1"
from hate_crack import main as hc_main  # noqa: E402

OLLAMA_URL = "http://localhost:11434"
MODEL = "qwen2.5:32b"


@contextmanager
def rosetta_mask_globals(tuning="", potfile=""):
    with (
        mock.patch.object(hc_main, "ollamaUrl", OLLAMA_URL),
        mock.patch.object(hc_main, "ollamaModel", MODEL),
        mock.patch.object(hc_main, "ollamaNumCtx", 2048),
        mock.patch.object(hc_main, "ollamaTimeout", 300.0),
        mock.patch.object(hc_main, "ollamaNoCloud", False),
        mock.patch.object(hc_main, "hcatBin", "/usr/bin/hashcat"),
        mock.patch.object(hc_main, "hcatTuning", tuning),
        mock.patch.object(hc_main, "hcatPotfilePath", potfile),
        mock.patch("hate_crack.main.generate_session_id", return_value="s"),
    ):
        yield


def _make_proc(wait_return=0):
    proc = mock.MagicMock()
    proc.wait.return_value = wait_return
    proc.communicate.return_value = (b"", b"")
    proc.returncode = wait_return
    return proc


def test_writes_hcmask_file_and_runs_mask_attack(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch(
            "hate_crack.main.llm.generate_masks",
            return_value=["?u?l?l?l?d?d", "?d?d?d?d"],
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()) as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "8 char passwords with digits")

    gen.assert_called_once_with(
        OLLAMA_URL,
        MODEL,
        2048,
        "8 char passwords with digits",
        timeout=300.0,
        no_cloud=False,
        backend="ollama",
        api_key="ollama",
    )
    hcmask_path = f"{hash_file}.hcmask"
    assert os.path.isfile(hcmask_path)
    with open(hcmask_path) as f:
        assert f.read() == "?u?l?l?l?d?d\n?d?d?d?d\n"

    cmd = popen.call_args[0][0]
    assert "/usr/bin/hashcat" in cmd
    assert "-a" in cmd and cmd[cmd.index("-a") + 1] == "3"
    assert hcmask_path in cmd


def test_hcmask_file_preserves_high_bytes_in_generated_mask_literals(tmp_path):
    """A mask literal containing a byte >= 0x80 must reach the .hcmask file
    as that exact byte, not a UTF-8 re-encoding of it -- see the identical
    concern in hcatSmartMask's own .hcmask write."""
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch(
            "hate_crack.main.llm.generate_masks",
            return_value=["Sömmer?d?d?d"],  # "ö" -> single byte 0xF6 in latin-1
        ),
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "a mask with a literal stem")

    raw_bytes = (tmp_path / "hashes.txt.hcmask").read_bytes()
    assert b"S\xf6mmer" in raw_bytes  # the original single byte, not \xc3\xb6
    assert b"\xc3\xb6" not in raw_bytes


def test_tuning_and_potfile_reach_the_command(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()
    potfile = tmp_path / "custom.potfile"

    with (
        rosetta_mask_globals(tuning="-w 3", potfile=str(potfile)),
        mock.patch(
            "hate_crack.main.llm.generate_masks",
            return_value=["?d?d?d?d"],
        ),
        mock.patch("subprocess.Popen", return_value=_make_proc()) as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    cmd = popen.call_args[0][0]
    assert "-w" in cmd and cmd[cmd.index("-w") + 1] == "3"
    assert f"--potfile-path={potfile}" in cmd


def test_invalid_masks_are_filtered_out(tmp_path):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch(
            "hate_crack.main.llm.generate_masks",
            return_value=["?d?d?d?d", "?u?l?l?", "?u?x?d"],
        ),
        mock.patch("subprocess.Popen", return_value=_make_proc()),
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    with open(f"{hash_file}.hcmask") as f:
        assert f.read() == "?d?d?d?d\n"


def test_no_valid_masks_skips_hashcat_run(tmp_path, capsys):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch("hate_crack.main.llm.generate_masks", return_value=["?u?x?"]),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    popen.assert_not_called()
    assert not os.path.isfile(f"{hash_file}.hcmask")
    assert "no usable masks" in capsys.readouterr().out.lower()


def test_llm_timeout_error_prints_message_and_skips_hashcat_run(tmp_path, capsys):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch(
            "hate_crack.main.llm.generate_masks",
            side_effect=hc_main.llm.LLMTimeoutError(
                "no response from x within 300 seconds"
            ),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    popen.assert_not_called()
    assert "timed out" in capsys.readouterr().out.lower()


def test_generic_generation_error_prints_message_and_skips_hashcat_run(
    tmp_path, capsys
):
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch(
            "hate_crack.main.llm.generate_masks",
            side_effect=RuntimeError("connection refused"),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    popen.assert_not_called()
    out = capsys.readouterr().out.lower()
    assert "error generating masks" in out
    assert "ollama" in out


def test_vllm_backend_reaches_generate_masks_and_the_spinner(tmp_path, capsys):
    """The Rosetta mask attack now supports LLM_BACKEND=vllm --
    HashcatRosetta's nlmask.generate_masks() gained think/extra_request_body
    upstream (#275), and llm.generate_masks() forwards the vllm-shaped
    kwargs via rosetta_backend_kwargs. The old pre-flight refusal is gone:
    hcatRosettaMask must reach the spinner and call llm.generate_masks.
    """
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch.object(hc_main, "llmBackend", "vllm"),
        mock.patch.object(hc_main, "llmApiKey", "sk-real-vllm-key"),
        mock.patch.object(
            hc_main.llm, "generate_masks", return_value=["?d?d?d?d"]
        ) as gen,
        mock.patch("subprocess.Popen", return_value=_make_proc()) as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    gen.assert_called_once_with(
        OLLAMA_URL,
        MODEL,
        2048,
        "pins",
        timeout=300.0,
        no_cloud=False,
        backend="vllm",
        api_key="sk-real-vllm-key",
    )
    out = capsys.readouterr().out
    assert "Generating masks via vLLM" in out
    popen.assert_called_once()


def test_generation_error_on_vllm_backend_does_not_mention_ollama(tmp_path, capsys):
    """If llm.generate_masks itself raises RosettaBackendRefused -- now
    meaning "this HashcatRosetta submodule predates think/extra_request_body
    support", not "backend unsupported" -- the refusal message must be
    printed alone, no follow-up "Ensure the configured vLLM server..."
    advice, since the refusal already names the real, precise reason.
    """
    hash_file = tmp_path / "hashes.txt"
    hash_file.touch()

    with (
        rosetta_mask_globals(),
        mock.patch.object(hc_main, "llmBackend", "vllm"),
        mock.patch.object(hc_main, "llmApiKey", "sk-real-vllm-key"),
        mock.patch.object(
            hc_main.llm,
            "generate_masks",
            side_effect=hc_main.llm.RosettaBackendRefused("vllm"),
        ),
        mock.patch("subprocess.Popen") as popen,
    ):
        hc_main.hcatRosettaMask("0", str(hash_file), "pins")

    popen.assert_not_called()
    out = capsys.readouterr().out
    assert "predates the think/extra_request_body" in out
    assert "Ensure the configured" not in out
    assert "ollama serve" not in out


def test_hcmask_file_removed_by_cleanup(tmp_path, monkeypatch):
    """Mirrors test_llm_pattern_rules.test_llm_patterns_removed_by_cleanup."""
    hash_file = str(tmp_path / "hashes.txt")
    hcmask_path = hash_file + ".hcmask"
    with open(hcmask_path, "w") as f:
        f.write("?u?l?l?l?d?d\n")

    monkeypatch.setattr(hc_main, "hcatHashFile", hash_file)
    monkeypatch.setattr(hc_main, "hcatHashFileOrig", hash_file)
    monkeypatch.setattr(hc_main, "hcatHashType", "1000")
    monkeypatch.setattr(hc_main, "pwdump_format", False)
    hc_main.cleanup()

    assert not os.path.exists(hcmask_path)
