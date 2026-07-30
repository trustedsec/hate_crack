"""pwdump_format must be readable before main() has run.

Issue #211: it was assigned only inside main()'s format-detection block, so a
-m 1000 run that reached cleanup() without executing that block raised
NameError instead of cleaning up - at the end of a session, after the cracking
work was already done.
"""

from unittest.mock import patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def test_pwdump_format_exists_at_import_and_defaults_false(main_module):
    assert main_module.pwdump_format is False


def test_cleanup_does_not_raise_when_detection_never_ran(
    main_module, tmp_path, monkeypatch, capsys
):
    """cleanup() runs on exit; it must not crash a -m 1000 session."""
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("a" * 32 + "\n")
    (tmp_path / "hashes.txt.out").write_text("x\n")
    # raising=False: these globals (like pwdump_format before this fix) are
    # only ever assigned inside main(), so a bare, main()-never-ran test
    # module has no such attribute yet to monkeypatch over.
    monkeypatch.setattr(main_module, "hcatHashFile", str(hash_file))
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(hash_file))
    monkeypatch.setattr(main_module, "hcatHashType", "1000")

    with patch.object(main_module, "check_potfile"):
        main_module.cleanup()  # must not raise NameError

    assert "Traceback" not in capsys.readouterr().out
