"""Tests for PCFG attack subprocess construction in hate_crack.main."""

import os
import sys
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

        # hcatPCFG resolves pcfg_guesser.py under the module global hate_path
        # and bails early if it's missing. Pin hate_path to a tmp dir with a
        # stub script so the test is hermetic — independent of the real
        # pcfg_cracker submodule being checked out and of any hate_path value
        # leaked by an earlier test (hate_crack.main is shared session-wide).
        pcfg_dir = tmp_path / "pcfg_cracker"
        pcfg_dir.mkdir()
        (pcfg_dir / "pcfg_guesser.py").write_text("# stub")

        captured_calls = []

        class FakeProc:
            def __init__(self, *args, **kwargs):
                captured_calls.append((args, kwargs))
                self.stdout = MagicMock()
                self.stdout.close = MagicMock()
                self.stdin = MagicMock()
                self.stdin.close = MagicMock()

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=FakeProc),
            patch("hate_crack.main._run_hcat_cmd") as mock_run,
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(
                main_module, "generate_session_id", return_value="test_session"
            ),
        ):
            main_module.hcatPCFG("0", hash_file)

        # First Popen call is the pcfg_guesser producer
        producer_args, producer_kwargs = captured_calls[0]
        producer_cmd = producer_args[0]
        assert producer_cmd[0] == sys.executable
        assert any("pcfg_guesser.py" in part for part in producer_cmd)
        assert "--rule" in producer_cmd
        assert producer_cmd[producer_cmd.index("--rule") + 1] == main_module.pcfgRuleset
        assert "--limit" in producer_cmd
        assert producer_cmd[producer_cmd.index("--limit") + 1] == str(
            main_module.pcfgMaxCandidates
        )

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

    def test_pcfg_child_stdin_stays_open(self, main_module, tmp_path):
        hash_file = str(tmp_path / "hashes.txt")
        Path(hash_file).write_text("dummy")

        pcfg_dir = tmp_path / "pcfg_cracker"
        pcfg_dir.mkdir()
        (pcfg_dir / "pcfg_guesser.py").write_text("# stub")

        captured_calls = []

        class FakeProc:
            def __init__(self, *args, **kwargs):
                captured_calls.append((args, kwargs))
                self.stdout = MagicMock()
                self.stdout.close = MagicMock()
                self.stdin = MagicMock()
                self.stdin.close = MagicMock()

        with (
            patch("hate_crack.main.subprocess.Popen", side_effect=FakeProc),
            patch("hate_crack.main._run_hcat_cmd") as mock_run,
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(
                main_module, "generate_session_id", return_value="test_session"
            ),
        ):
            main_module.hcatPCFG("0", hash_file)

        producer_args, producer_kwargs = captured_calls[0]
        assert producer_kwargs.get("stdin") is not None

        fake_proc = mock_run.call_args.kwargs["companion_procs"][0]
        assert fake_proc.stdin.close.called


class TestHcatPrinceLing:
    def _cache_name(self, main_module, ruleset="Default"):
        """The cache filename for *ruleset* at the module's current --size.

        Both inputs that decide the file's contents are in its name, so the
        candidate budget has to be read from the module rather than hardcoded.
        """
        size = main_module.pcfgPrinceLingMaxCandidates
        return f"pcfg_prince_ling_{ruleset}_{size}.txt"

    def _setup_pcfg_dirs(self, tmp_path, main_module, monkeypatch):
        """Lay out fake pcfg_cracker/Rules/<ruleset>/ and optimized_wordlists/."""
        pcfg_root = tmp_path / "pcfg_cracker"
        rules_dir = pcfg_root / "Rules" / "Default"
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
        cache = opt_dir / self._cache_name(main_module)
        # Cache exists but is older than ruleset
        cache.write_text("stale")
        old = rules_dir.stat().st_mtime - 100
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

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch("hate_crack.main.hcatPrince") as mock_prince,
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # prince_ling subprocess.run was invoked
        assert len(run_calls) == 1
        cmd = run_calls[0]
        assert any("prince_ling.py" in p for p in cmd)
        assert "--rule" in cmd
        assert cmd[cmd.index("--rule") + 1] == "Default"
        # Uses --size, NOT --limit
        assert "--size" in cmd
        assert "--limit" not in cmd
        # hcatPrince delegated
        assert mock_prince.called

    def test_skips_regen_when_cache_fresh(self, main_module, tmp_path, monkeypatch):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        cache = opt_dir / self._cache_name(main_module)
        cache.write_text("fresh")
        # Cache is newer than ruleset
        future = rules_dir.stat().st_mtime + 1000
        os.utime(cache, (future, future))

        with (
            patch("hate_crack.main.subprocess.run") as mock_run,
            patch("hate_crack.main.hcatPrince"),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # subprocess.run was NOT called for prince_ling
        assert not mock_run.called

    def test_changing_max_candidates_forces_regeneration(
        self, main_module, tmp_path, monkeypatch
    ):
        """pcfgPrinceLingMaxCandidates is passed to prince_ling.py as --size, so
        a cache generated under one value does not answer for another. Keyed only
        on the ruleset, raising the setting silently reused the smaller wordlist.
        """
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        monkeypatch.setattr(main_module, "pcfgPrinceLingMaxCandidates", 1000)

        run_calls = []

        def fake_run(cmd, **kwargs):
            run_calls.append(cmd)
            for i, part in enumerate(cmd):
                if part == "--output":
                    Path(cmd[i + 1]).write_text("generated")

            class R:
                returncode = 0

            return R()

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch("hate_crack.main.hcatPrince"),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        assert len(run_calls) == 1
        small_cache = opt_dir / self._cache_name(main_module)
        assert small_cache.exists()
        # Make the small cache unambiguously fresh, so only the changed budget
        # can be what triggers the second generation.
        future = rules_dir.stat().st_mtime + 1000
        os.utime(small_cache, (future, future))

        monkeypatch.setattr(main_module, "pcfgPrinceLingMaxCandidates", 2000)
        # hcatPrinceLing restores hcatPrinceBaseList in a finally block, so the
        # only place to observe which wordlist PRINCE actually got is inside it.
        used = []

        def capture_prince(*args, **kwargs):
            used.append(list(main_module.hcatPrinceBaseList))

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch("hate_crack.main.hcatPrince", side_effect=capture_prince),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        assert len(run_calls) == 2
        assert run_calls[1][run_calls[1].index("--size") + 1] == "2000"
        # Each budget keeps its own cache rather than overwriting the other's.
        big_cache = opt_dir / self._cache_name(main_module)
        assert big_cache.exists()
        assert small_cache.exists()
        assert big_cache != small_cache
        assert used == [[str(big_cache)]]

    def test_atomic_cache_write_cleans_tmp_on_failure(
        self, main_module, tmp_path, monkeypatch
    ):
        import subprocess as real_subprocess

        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)

        def boom(cmd, **kwargs):
            # Touch the .tmp file then fail (simulates partial write + crash)
            for i, part in enumerate(cmd):
                if part == "--output":
                    Path(cmd[i + 1]).write_text("partial")
            raise real_subprocess.CalledProcessError(1, cmd)

        with (
            patch("hate_crack.main.subprocess.run", side_effect=boom),
            patch("hate_crack.main.hcatPrince"),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # No real cache file created; tmp file cleaned up
        assert not (opt_dir / self._cache_name(main_module)).exists()
        assert not (opt_dir / (self._cache_name(main_module) + ".tmp")).exists()

    def test_restores_hcatPrinceBaseList_on_exception(
        self, main_module, tmp_path, monkeypatch
    ):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        cache = opt_dir / self._cache_name(main_module)
        cache.write_text("fresh")
        future = rules_dir.stat().st_mtime + 1000
        os.utime(cache, (future, future))

        original = ["original_base.txt"]
        monkeypatch.setattr(main_module, "hcatPrinceBaseList", original)

        def boom(*a, **kw):
            raise RuntimeError("hcatPrince exploded")

        with (
            patch("hate_crack.main.hcatPrince", side_effect=boom),
            pytest.raises(RuntimeError),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        assert main_module.hcatPrinceBaseList == original

    def test_uses_sys_executable(self, main_module, tmp_path, monkeypatch):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        cache = opt_dir / self._cache_name(main_module)
        cache.write_text("stale")
        old = rules_dir.stat().st_mtime - 100
        os.utime(cache, (old, old))

        run_calls = []

        def fake_run(cmd, **kwargs):
            run_calls.append(cmd)
            for i, part in enumerate(cmd):
                if part == "--output":
                    Path(cmd[i + 1]).write_text("regenerated")

            class R:
                returncode = 0

            return R()

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch("hate_crack.main.hcatPrince"),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        assert run_calls[0][0] == sys.executable

    def test_resolves_ruleset_case_insensitively(
        self, main_module, tmp_path, monkeypatch
    ):
        rules_dir, opt_dir = self._setup_pcfg_dirs(tmp_path, main_module, monkeypatch)
        # Cache file uses the resolved on-disk basename ("Default"), not the
        # raw (legacy, all-caps) config value.
        cache = opt_dir / self._cache_name(main_module)
        cache.write_text("stale")
        old = rules_dir.stat().st_mtime - 100
        os.utime(cache, (old, old))

        # Simulate a config.json predating the default-casing fix, where
        # "DEFAULT" was backfilled to disk instead of "Default".
        monkeypatch.setattr(main_module, "pcfgRuleset", "DEFAULT")

        # Force case-sensitive isdir semantics for this test: on
        # case-insensitive-but-case-preserving filesystems (e.g. macOS
        # APFS), os.path.isdir(".../DEFAULT") would spuriously match the
        # real ".../Default" dir, masking the fallback path this test is
        # meant to exercise (and which is what actually runs on CI's
        # case-sensitive Linux filesystem).
        real_isdir = os.path.isdir

        def case_sensitive_isdir(path):
            parent, name = os.path.split(path)
            try:
                return name in os.listdir(parent) and real_isdir(path)
            except FileNotFoundError:
                return False

        run_calls = []

        def fake_run(cmd, **kwargs):
            run_calls.append(cmd)
            for i, part in enumerate(cmd):
                if part == "--output":
                    Path(cmd[i + 1]).write_text("regenerated")

            class R:
                returncode = 0

            return R()

        with (
            patch("hate_crack.main.subprocess.run", side_effect=fake_run),
            patch("hate_crack.main.hcatPrince") as mock_prince,
            patch("hate_crack.main.os.path.isdir", side_effect=case_sensitive_isdir),
        ):
            main_module.hcatPrinceLing("0", str(tmp_path / "hashes.txt"))

        # Should have found the on-disk "Default" dir and proceeded, not
        # printed "PCFG ruleset not found" and returned early.
        assert len(run_calls) == 1
        cmd = run_calls[0]
        # The subprocess argv and cache filename must both use the resolved
        # on-disk basename ("Default"), not the raw monkeypatched "DEFAULT"
        # value, since prince_ling.py does its own case-sensitive Rules/
        # lookup internally.
        assert "--rule" in cmd
        assert cmd[cmd.index("--rule") + 1] == "Default"
        assert cache.exists()
        assert mock_prince.called
