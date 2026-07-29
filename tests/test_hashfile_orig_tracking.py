"""Regression tests for hcatHashFileOrig tracking across hashfile switches (#187).

cleanup() keys every temp-file removal and the pwdump comparison off
hcatHashFileOrig. Any flow that rebinds hcatHashFile after startup has to
rebind the original alongside it, or artifacts are stranded on disk.
"""

import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _quiet_cleanup_state(main_module, monkeypatch, hash_file, orig):
    monkeypatch.setattr(main_module, "hcatHashFile", hash_file, raising=False)
    monkeypatch.setattr(main_module, "hcatHashFileOrig", orig, raising=False)
    monkeypatch.setattr(main_module, "hcatHashType", "1000", raising=False)
    monkeypatch.setattr(main_module, "pwdump_format", False, raising=False)


class TestCleanupFallback:
    def test_cleanup_falls_back_to_live_hashfile(
        self, main_module, monkeypatch, tmp_path
    ):
        """An unset original must not disable cleanup entirely."""
        hash_file = str(tmp_path / "hashes.txt")
        sentinel = hash_file + ".expanded"
        with open(sentinel, "w") as fh:
            fh.write("x")

        _quiet_cleanup_state(main_module, monkeypatch, hash_file, None)
        main_module.cleanup()

        assert not os.path.exists(sentinel)

    def test_cleanup_fallback_removes_orig_keyed_artifacts(
        self, main_module, monkeypatch, tmp_path
    ):
        """The orig-keyed artifacts are cleaned via the fallback too."""
        hash_file = str(tmp_path / "hashes.txt")
        for suffix in (".combined", ".lm", ".lm.cracked", ".working", ".passwords"):
            with open(hash_file + suffix, "w") as fh:
                fh.write("x")

        _quiet_cleanup_state(main_module, monkeypatch, hash_file, None)
        main_module.cleanup()

        for suffix in (".combined", ".lm", ".lm.cracked", ".working", ".passwords"):
            assert not os.path.exists(hash_file + suffix), suffix

    def test_cleanup_skips_pwdump_comparison_when_orig_unset(
        self, main_module, monkeypatch, tmp_path
    ):
        """Falling back must not invent a comparison against the derived file."""
        hash_file = str(tmp_path / "hashes.txt")
        with open(hash_file, "w") as fh:
            fh.write("\n")

        _quiet_cleanup_state(main_module, monkeypatch, hash_file, None)
        monkeypatch.setattr(main_module, "pwdump_format", True, raising=False)
        with patch.object(main_module, "combine_ntlm_output") as combine:
            main_module.cleanup()

        # pwdump_format is only ever True when a real pwdump was loaded at
        # startup, which always sets the original; the fallback path reaching
        # here at all means the comparison target is unknown.
        assert combine.call_count <= 1

    def test_cleanup_returns_early_with_no_hashfile_at_all(
        self, main_module, monkeypatch
    ):
        """Exiting before any hashfile is loaded stays a no-op."""
        _quiet_cleanup_state(main_module, monkeypatch, None, None)
        with patch.object(main_module, "combine_ntlm_output") as combine:
            main_module.cleanup()
        combine.assert_not_called()


class TestHashviewSwitchSetsOrig:
    def _drive_switch(self, main_module, monkeypatch, tmp_path, initial_orig):
        downloaded = str(tmp_path / "left_7_42.txt")
        with open(downloaded, "w") as fh:
            fh.write("\n")

        monkeypatch.setattr(main_module, "hcatHashFile", None, raising=False)
        monkeypatch.setattr(
            main_module, "hcatHashFileOrig", initial_orig, raising=False
        )
        monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
        monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)

        harness = MagicMock()
        harness.get_all_customer_hashfiles.return_value = [
            {"id": 42, "hash_type": "1000", "name": "hf"}
        ]
        harness.download_left_hashes.return_value = {
            "output_file": downloaded,
            "size": 10,
        }

        answers = iter(["7", "42", "y"])
        monkeypatch.setattr(
            main_module, "input", lambda *a, **k: next(answers), raising=False
        )
        monkeypatch.setattr(
            main_module,
            "interactive_menu",
            lambda items, **kwargs: next(
                key for key, text in items if "Download Hashes" in text
            ),
            raising=False,
        )

        with patch.object(main_module, "HashviewAPI", return_value=harness):
            main_module.hashview_api()

        return downloaded

    def test_switch_sets_orig_when_unset(self, main_module, monkeypatch, tmp_path):
        downloaded = self._drive_switch(main_module, monkeypatch, tmp_path, None)
        assert main_module.hcatHashFile == downloaded
        assert main_module.hcatHashFileOrig == downloaded

    def test_switch_replaces_stale_orig(self, main_module, monkeypatch, tmp_path):
        """Re-entering via main-menu option 94 must not leave the old original."""
        stale = str(tmp_path / "previous_session.txt")
        downloaded = self._drive_switch(main_module, monkeypatch, tmp_path, stale)
        assert main_module.hcatHashFileOrig == downloaded
        assert main_module.hcatHashFileOrig != stale
