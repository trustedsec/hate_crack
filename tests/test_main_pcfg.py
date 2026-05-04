"""Tests for PCFG attack subprocess construction in hate_crack.main."""
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


class TestHcatPCFG:
    def test_builds_expected_subprocess(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        Path(hash_file).write_text("dummy")

        captured_calls = []

        class FakeProc:
            def __init__(self, *args, **kwargs):
                captured_calls.append((args, kwargs))
                self.stdout = MagicMock()
                self.stdout.close = MagicMock()

        with patch("hate_crack.main.subprocess.Popen", side_effect=FakeProc), \
             patch("hate_crack.main._run_hcat_cmd") as mock_run, \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "generate_session_id", return_value="test_session"):
            main_module.hcatPCFG("0", hash_file)

        # First Popen call is the pcfg_guesser producer
        producer_args, producer_kwargs = captured_calls[0]
        producer_cmd = producer_args[0]
        assert "python3" in producer_cmd[0] or producer_cmd[0].endswith("python3")
        assert any("pcfg_guesser.py" in part for part in producer_cmd)
        assert "--rule" in producer_cmd
        assert producer_cmd[producer_cmd.index("--rule") + 1] == main_module.pcfgRuleset
        assert "--limit" in producer_cmd
        assert producer_cmd[producer_cmd.index("--limit") + 1] == str(main_module.pcfgMaxCandidates)

        # _run_hcat_cmd was called with attack_name='PCFG' and the hashcat command
        assert mock_run.called
        kwargs = mock_run.call_args.kwargs
        hashcat_cmd = mock_run.call_args.args[0]
        assert kwargs["attack_name"] == "PCFG"
        assert kwargs["hash_file"] == hash_file
        # Hashcat does NOT carry --limit (cap is producer-side)
        assert "--limit" not in hashcat_cmd
        # Hashcat is in stdin mode (no -a flag)
        assert "-a" not in hashcat_cmd
        assert "-m" in hashcat_cmd
        assert hashcat_cmd[hashcat_cmd.index("-m") + 1] == "0"

        # Verify the producer is wired into hashcat's stdin via _run_hcat_cmd
        assert kwargs["stdin"] is not None
        assert kwargs["companion_procs"] is not None
        assert len(kwargs["companion_procs"]) == 1
