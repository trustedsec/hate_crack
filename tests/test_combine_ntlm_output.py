"""combine_ntlm_output must never destroy the cracked results it reads.

Issue #195: for a non-pwdump hash file, hcatHashFileOrig == hcatHashFile, so the
function opened its own input with mode "w+" (truncating), then matched against
lines that no longer existed. A 49 KB .out became 0 bytes.
"""

from unittest.mock import patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _setup(tmp_path, main_module, monkeypatch, *, pwdump):
    """Lay out a hash file and its .out, wired the way main() would leave them."""
    if pwdump:
        orig = tmp_path / "hashes.txt"
        orig.write_text(
            f"alice:1001:{'0' * 32}:{'a' * 32}:::\nbob:1002:{'0' * 32}:{'b' * 32}:::\n"
        )
        cracked = tmp_path / "hashes.txt.nt"
        out = tmp_path / "hashes.txt.nt.out"
        out.write_text(f"{'a' * 32}:pw-a\n{'b' * 32}:pw-b\n")
        monkeypatch.setattr(main_module, "hcatHashFile", str(cracked), raising=False)
        monkeypatch.setattr(main_module, "hcatHashFileOrig", str(orig), raising=False)
        return orig, out
    # Non-pwdump: one bare hash per line, and the two globals are the same path.
    plain = tmp_path / "hashes.txt"
    plain.write_text(f"{'a' * 32}\n{'b' * 32}\n")
    out = tmp_path / "hashes.txt.out"
    out.write_text(f"{'a' * 32}:pw-a\n{'b' * 32}:pw-b\n")
    monkeypatch.setattr(main_module, "hcatHashFile", str(plain), raising=False)
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(plain), raising=False)
    return plain, out


def test_non_pwdump_out_file_is_left_byte_identical(main_module, tmp_path, monkeypatch):
    """The reported bug: same-path input must not be truncated."""
    _, out = _setup(tmp_path, main_module, monkeypatch, pwdump=False)
    before = out.read_bytes()

    with patch.object(main_module, "check_potfile"):
        main_module.combine_ntlm_output()

    assert out.read_bytes() == before


def test_pwdump_merge_still_produces_combined_lines(main_module, tmp_path, monkeypatch):
    """The feature this function exists for must keep working."""
    orig, _ = _setup(tmp_path, main_module, monkeypatch, pwdump=True)

    with patch.object(main_module, "check_potfile"):
        main_module.combine_ntlm_output()

    combined = (orig.parent / "hashes.txt.out").read_text()
    assert "alice" in combined and "pw-a" in combined
    assert "bob" in combined and "pw-b" in combined


def test_zero_matches_leaves_an_existing_destination_intact(
    main_module, tmp_path, monkeypatch
):
    """A run that matches nothing must not clobber a previous good result."""
    orig = tmp_path / "hashes.txt"
    orig.write_text(f"alice:1001:{'0' * 32}:{'c' * 32}:::\n")  # NT hash not cracked
    cracked = tmp_path / "hashes.txt.nt"
    (tmp_path / "hashes.txt.nt.out").write_text(f"{'a' * 32}:pw-a\n")
    destination = tmp_path / "hashes.txt.out"
    destination.write_text("previous good output\n")
    monkeypatch.setattr(main_module, "hcatHashFile", str(cracked), raising=False)
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(orig), raising=False)

    with patch.object(main_module, "check_potfile"):
        main_module.combine_ntlm_output()

    assert destination.read_text() == "previous good output\n"


def test_no_temp_file_is_left_behind(main_module, tmp_path, monkeypatch):
    orig, _ = _setup(tmp_path, main_module, monkeypatch, pwdump=True)

    with patch.object(main_module, "check_potfile"):
        main_module.combine_ntlm_output()

    leftovers = [p.name for p in tmp_path.iterdir() if ".combine" in p.name]
    assert leftovers == []
