"""Tests for PCFG attack subprocess construction in hate_crack.main."""
import os
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


class TestHcatPrinceLing:
    def _setup_pcfg_dirs(self, tmp_path, main_module, monkeypatch):
        """Lay out fake pcfg_cracker/Rules/<ruleset>/ and optimized_wordlists/."""
        pcfg_root = tmp_path / "pcfg_cracker"
        rules_dir = pcfg_root / "Rules" / "DEFAULT"
        rules_dir.mkdir(parents=True)
        (rules_dir / "config.txt").write_text("dummy")
        # prince_ling script must "exist" for the function to proceed
        (pcfg_root / "prince_ling.py").write_text("# stub")
        opt_dir = tmp_path / "optimized_wordlists"
        opt_dir.mkdir()

        monkeypatch.setattr(main_module, "hate_path", str(tmp_path))
        monkeypatch.setattr(main_module, "hcatOptimizedWordlists", str(opt_dir))
        return rules_dir, opt_dir

    def test_regenerates_when_cache_stale(self, main_module, tmp_path, monkeypatch):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        cache = opt_dir / "pcfg_prince_ling_DEFAULT.txt"
        # Cache exists but is older than ruleset
        cache.write_text("stale")
        old = (rules_dir.stat().st_mtime - 100)
        os.utime(cache, (old, old))

        run_calls = []

        def fake_run(cmd, **kwargs):
            run_calls.append(cmd)
            # Simulate prince_ling writing the .tmp file
            for i, part in enumerate(cmd):
                if part == "--output":
                    Path(cmd[i + 1]).write_text("regenerated")
            class R:
                returncode = 0
            return R()

        with patch("hate_crack.main.subprocess.run", side_effect=fake_run), \
             patch("hate_crack.main.hcatPrince") as mock_prince:
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # prince_ling subprocess.run was invoked
        assert len(run_calls) == 1
        cmd = run_calls[0]
        assert any("prince_ling.py" in p for p in cmd)
        assert "--rule" in cmd
        assert cmd[cmd.index("--rule") + 1] == "DEFAULT"
        # Uses --size, NOT --limit
        assert "--size" in cmd
        assert "--limit" not in cmd
        # hcatPrince delegated
        assert mock_prince.called

    def test_skips_regen_when_cache_fresh(self, main_module, tmp_path, monkeypatch):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        cache = opt_dir / "pcfg_prince_ling_DEFAULT.txt"
        cache.write_text("fresh")
        # Cache is newer than ruleset
        future = rules_dir.stat().st_mtime + 1000
        os.utime(cache, (future, future))

        with patch("hate_crack.main.subprocess.run") as mock_run, \
             patch("hate_crack.main.hcatPrince"):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # subprocess.run was NOT called for prince_ling
        assert not mock_run.called

    def test_atomic_cache_write_cleans_tmp_on_failure(self, main_module, tmp_path, monkeypatch):
        import subprocess as real_subprocess
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)

        def boom(cmd, **kwargs):
            # Touch the .tmp file then fail (simulates partial write + crash)
            for i, part in enumerate(cmd):
                if part == "--output":
                    Path(cmd[i + 1]).write_text("partial")
            raise real_subprocess.CalledProcessError(1, cmd)

        with patch("hate_crack.main.subprocess.run", side_effect=boom), \
             patch("hate_crack.main.hcatPrince"):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # No real cache file created; tmp file cleaned up
        assert not (opt_dir / "pcfg_prince_ling_DEFAULT.txt").exists()
        assert not (opt_dir / "pcfg_prince_ling_DEFAULT.txt.tmp").exists()

    def test_restores_hcatPrinceBaseList_on_exception(self, main_module, tmp_path, monkeypatch):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        cache = opt_dir / "pcfg_prince_ling_DEFAULT.txt"
        cache.write_text("fresh")
        future = rules_dir.stat().st_mtime + 1000
        os.utime(cache, (future, future))

        original = ["original_base.txt"]
        monkeypatch.setattr(main_module, "hcatPrinceBaseList", original)

        def boom(*a, **kw):
            raise RuntimeError("hcatPrince exploded")

        with patch("hate_crack.main.hcatPrince", side_effect=boom), \
             pytest.raises(RuntimeError):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        assert main_module.hcatPrinceBaseList == original
