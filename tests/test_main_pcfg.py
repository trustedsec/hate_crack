"""Tests for PCFG attack subprocess construction in hate_crack.main."""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def hc_main(monkeypatch):
    """Load hate_crack.main with SKIP_INIT and stub external bits."""
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    if "hate_crack.main" in sys.modules:
        del sys.modules["hate_crack.main"]
    import hate_crack.main as m
    return m


class TestHcatPCFG:
    def test_builds_expected_subprocess(self, hc_main, tmp_path):
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
             patch.object(hc_main, "generate_session_id", return_value="test_session"):
            hc_main.hcatPCFG("0", hash_file)

        # First Popen call is the pcfg_guesser producer
        producer_args, producer_kwargs = captured_calls[0]
        producer_cmd = producer_args[0]
        assert "python3" in producer_cmd[0] or producer_cmd[0].endswith("python3")
        assert any("pcfg_guesser.py" in part for part in producer_cmd)
        assert "--rule" in producer_cmd
        assert producer_cmd[producer_cmd.index("--rule") + 1] == hc_main.pcfgRuleset
        assert "--limit" in producer_cmd
        assert producer_cmd[producer_cmd.index("--limit") + 1] == str(hc_main.pcfgMaxCandidates)

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
