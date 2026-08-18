"""Tests for optimized kernel system - covers gaps not in test_main_utils.py::TestOptimizedKernel."""

import io
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
        (tmp_path / "hashes.txt.out").write_text("deadbeef:password1\n")

        captured_cmds = []

        def fake_popen(cmd, stdin=None, stdout=None, **_kwargs):
            captured_cmds.append(list(cmd))
            cmd0 = cmd[0]
            if cmd0 == "sort":
                data = stdin.read() if stdin is not None else b""
                for line in sorted(set(data.splitlines())):
                    stdout.write(line + b"\n")
                stdout.flush()
                proc_stdout = None
            elif isinstance(cmd0, str) and "expander" in cmd0:
                data = stdin.read() if stdin is not None else b""
                proc_stdout = io.BytesIO(data)
            else:
                proc_stdout = MagicMock()
            proc = MagicMock()
            proc.stdout = proc_stdout
            proc.pid = 1234
            proc.wait.return_value = 0
            return proc

        # Constant lineCount makes each escalation length's while-loop
        # converge after one iteration (crackedAfter == crackedBefore) and
        # keeps the keyspace guard well under its threshold.
        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatExpanderBin", "expander.bin"),
            patch.object(main_module, "hcatHashCracked", 0),
            patch("hate_crack.main.lineCount", lambda _p: 1),
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


class TestOptInOptimizedAttacks:
    """The four attacks that honour optimizedKernelAttacks without being in the
    default set: -O must be absent by default and present once configured.

    All four built their hashcat command without ever consulting the setting,
    so listing them in config.json did nothing.
    """

    def test_ngramx_omits_optimized_flag_by_default(self, main_module, tmp_path):
        cmds = self._run_ngramx(main_module, tmp_path, enabled=False)
        assert not any("-O" in cmd for cmd in cmds), cmds

    def test_ngramx_includes_optimized_flag_when_enabled(self, main_module, tmp_path):
        cmds = self._run_ngramx(main_module, tmp_path, enabled=True)
        assert cmds, "No hashcat Popen calls captured"
        assert all("-O" in cmd for cmd in cmds), cmds

    def _run_ngramx(self, main_module, tmp_path, enabled):
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("aaa\nbbb\n")
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("")
        captured = []

        def fake_popen(cmd, **kwargs):
            captured.append(list(cmd))
            proc = MagicMock()
            proc.stdout = MagicMock()
            proc.wait.return_value = 0
            proc.returncode = 0
            return proc

        attacks = (
            frozenset({"hcatNgramX"})
            if enabled
            else main_module.DEFAULT_OPTIMIZED_ATTACKS
        )
        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch.object(main_module, "_optimized_kernel_attacks", attacks),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatHashCracked", 0),
            patch("hate_crack.main.lineCount", return_value=0),
            patch("hate_crack.main.generate_session_id", return_value="s"),
        ):
            main_module.hcatNgramX("1000", str(hash_file), str(corpus))

        return [cmd for cmd in captured if cmd and cmd[0] == "hashcat"]

    def test_omen_omits_optimized_flag_by_default(self, main_module, tmp_path):
        cmds = self._run_omen(main_module, tmp_path, enabled=False)
        assert not any("-O" in cmd for cmd in cmds), cmds

    def test_omen_includes_optimized_flag_when_enabled(self, main_module, tmp_path):
        cmds = self._run_omen(main_module, tmp_path, enabled=True)
        assert cmds, "No hashcat Popen calls captured"
        assert all("-O" in cmd for cmd in cmds), cmds

    def _run_omen(self, main_module, tmp_path, enabled):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        (omen_dir / "enumNG").touch()
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")
        captured = []

        def fake_popen(cmd, **kwargs):
            captured.append(list(cmd))
            proc = MagicMock()
            proc.stdout = MagicMock()
            proc.stderr = MagicMock()
            proc.wait.return_value = None
            proc.returncode = 0
            return proc

        attacks = (
            frozenset({"hcatOmen"})
            if enabled
            else main_module.DEFAULT_OPTIMIZED_ATTACKS
        )
        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
            patch.object(main_module, "_optimized_kernel_attacks", attacks),
            patch.object(main_module, "_omen_dir", str(omen_dir)),
            patch.object(main_module, "hcatOmenEnumBin", "enumNG"),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)),
            patch("hate_crack.main.generate_session_id", return_value="s"),
        ):
            main_module.hcatOmen("1000", str(tmp_path / "hashes.txt"), 500000)

        return [cmd for cmd in captured if cmd and cmd[0] == "hashcat"]
