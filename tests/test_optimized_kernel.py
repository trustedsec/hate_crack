"""Tests for optimized kernel system - covers gaps not in test_main_utils.py::TestOptimizedKernel."""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


class TestOptimizedKernelMissingNames:
    """Covers the two DEFAULT_OPTIMIZED_ATTACKS names missing from test_main_utils.py."""

    @pytest.mark.parametrize(
        "attack_name",
        [
            "hcatAdHocMask",
            "hcatMarkovBruteForce",
        ],
    )
    def test_optimized_attacks_return_true(self, main_module, attack_name):
        assert main_module._should_use_optimized_kernel(attack_name) is True


class TestOptimizedKernelNonMembers:
    """Covers False cases not already parametrized in test_main_utils.py."""

    @pytest.mark.parametrize(
        "attack_name",
        [
            "hcatOllama",
            "hcatNgramX",
            "hcatGenerateRules",
            "hcatMarkovTrain",
            "hcatOmenTrain",
            "unknown_attack",
        ],
    )
    def test_non_optimized_attacks_return_false(self, main_module, attack_name):
        assert main_module._should_use_optimized_kernel(attack_name) is False


class TestHcatFingerprintOptimizedFlag:
    """End-to-end mock test verifying hcatFingerprint passes -O to hashcat."""

    def test_fingerprint_includes_optimized_flag(self, main_module, tmp_path):
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("")
        (tmp_path / "hashes.txt.out").write_text("")
        # hcatFingerprint opens .working and .expanded inside the loop; create them.
        (tmp_path / "hashes.txt.working").write_text("")
        (tmp_path / "hashes.txt.expanded").write_text("")

        captured_cmds = []

        def fake_popen(cmd, **kwargs):
            captured_cmds.append(list(cmd))
            proc = MagicMock()
            proc.stdout = MagicMock()
            proc.pid = 1234
            proc.wait.return_value = 0
            return proc

        # lineCount call sequence:
        #   call 1 (initial, before loop): 1  -> crackedBefore=1, crackedAfter=0 -> enter loop
        #   call 2 (top of loop body):     1  -> crackedBefore=1
        #   call 3 (bottom of loop body):  1  -> crackedAfter=1 -> exit loop (1==1)
        #   call 4 (final hcatFingerprintCount assignment): 1
        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatExpanderBin", "expander.bin"),
            patch.object(main_module, "hcatHashCracked", 0),
            patch("hate_crack.main.lineCount", side_effect=[1, 1, 1, 1]),
            patch("hate_crack.main._write_delimited_field"),
            patch("hate_crack.main.ensure_binary"),
            patch("hate_crack.main.generate_session_id", return_value="test_session"),
        ):
            main_module.hcatFingerprint(
                hcatHashType="1000",
                hcatHashFile=str(hash_file),
            )

        hashcat_cmds = [cmd for cmd in captured_cmds if cmd and cmd[0] == "hashcat"]
        assert hashcat_cmds, "No hashcat Popen calls captured"
        assert any("-O" in cmd for cmd in hashcat_cmds), (
            f"Expected -O in hashcat cmd, got: {hashcat_cmds}"
        )
