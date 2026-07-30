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
        monkeypatch.setattr(main_module, "hcatHashFile", str(cracked))
        monkeypatch.setattr(main_module, "hcatHashFileOrig", str(orig))
        return orig, out
    # Non-pwdump: one bare hash per line, and the two globals are the same path.
    plain = tmp_path / "hashes.txt"
    plain.write_text(f"{'a' * 32}\n{'b' * 32}\n")
    out = tmp_path / "hashes.txt.out"
    out.write_text(f"{'a' * 32}:pw-a\n{'b' * 32}:pw-b\n")
    monkeypatch.setattr(main_module, "hcatHashFile", str(plain))
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(plain))
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
    monkeypatch.setattr(main_module, "hcatHashFile", str(cracked))
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(orig))

    with patch.object(main_module, "check_potfile"):
        main_module.combine_ntlm_output()

    assert destination.read_text() == "previous good output\n"


def test_no_temp_file_is_left_behind(main_module, tmp_path, monkeypatch):
    orig, _ = _setup(tmp_path, main_module, monkeypatch, pwdump=True)

    with patch.object(main_module, "check_potfile"):
        main_module.combine_ntlm_output()

    leftovers = [p.name for p in tmp_path.iterdir() if ".combine" in p.name]
    assert leftovers == []


def _stub_hashcat(tmp_path, main_module, monkeypatch, *, exit_code=0, stdout=""):
    """Install a stub `hcatBin` so check_potfile() can run for real.

    The existing tests above all mock check_potfile out, which is precisely the
    call that truncated the cracked output, so they cannot see the bug. These
    drive the real code path with a hashcat that reports no cracks.
    """
    stub = tmp_path / "hashcat_stub.sh"
    body = "#!/bin/sh\n"
    if stdout:
        body += f"cat <<'HCEOF'\n{stdout}HCEOF\n"
    body += f"exit {exit_code}\n"
    stub.write_text(body)
    stub.chmod(0o755)
    monkeypatch.setattr(main_module, "hcatBin", str(stub))
    monkeypatch.setattr(main_module, "hcatPotfilePath", "")
    monkeypatch.setattr(main_module, "hcatHashType", "1000")
    monkeypatch.setattr(main_module, "hcatUsernamePrefix", False, raising=False)
    return stub


def test_non_pwdump_out_survives_unmocked_check_potfile(
    main_module, tmp_path, monkeypatch
):
    """Same-path case with the real check_potfile: nothing may be truncated."""
    _, out = _setup(tmp_path, main_module, monkeypatch, pwdump=False)
    _stub_hashcat(tmp_path, main_module, monkeypatch)
    before = out.read_bytes()

    main_module.combine_ntlm_output()

    assert out.read_bytes() == before


def test_pwdump_out_survives_unmocked_check_potfile_with_no_destination_yet(
    main_module, tmp_path, monkeypatch
):
    """cleanup()'s worst case: the merged file does not exist yet, so
    `<hcatHashFile>.out` is the only copy of the cracked passwords."""
    orig, out = _setup(tmp_path, main_module, monkeypatch, pwdump=True)
    _stub_hashcat(tmp_path, main_module, monkeypatch)
    destination = tmp_path / "hashes.txt.out"
    assert not destination.exists()
    before = out.read_bytes()

    main_module.combine_ntlm_output()

    assert out.read_bytes() == before, "cracked output was destroyed"
    combined = destination.read_text()
    assert "alice" in combined and "bob" in combined


def test_hashcat_show_failure_leaves_output_intact(
    main_module, tmp_path, monkeypatch, capsys
):
    """A non-zero hashcat exit must neither truncate nor pass silently."""
    _, out = _setup(tmp_path, main_module, monkeypatch, pwdump=True)
    _stub_hashcat(tmp_path, main_module, monkeypatch, exit_code=255)
    before = out.read_bytes()

    main_module.combine_ntlm_output()

    assert out.read_bytes() == before
    assert "exited with code 255" in capsys.readouterr().out


def test_run_hashcat_show_preserves_populated_output_on_empty_result(
    main_module, tmp_path, monkeypatch
):
    _stub_hashcat(tmp_path, main_module, monkeypatch)
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text(f"{'a' * 32}\n")
    out = tmp_path / "hashes.txt.out"
    out.write_text(f"{'a' * 32}:pw-a\n")

    wrote = main_module._run_hashcat_show("1000", str(hash_file), str(out))

    assert wrote is False
    assert out.read_text() == f"{'a' * 32}:pw-a\n"


def test_run_hashcat_show_force_overwrite_still_replaces_content(
    main_module, tmp_path, monkeypatch
):
    """restore_from_potfile() asks the operator first, then means it."""
    _stub_hashcat(tmp_path, main_module, monkeypatch)
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text(f"{'a' * 32}\n")
    out = tmp_path / "hashes.txt.out"
    out.write_text(f"{'a' * 32}:pw-a\n")

    wrote = main_module._run_hashcat_show(
        "1000", str(hash_file), str(out), force_overwrite=True
    )

    assert wrote is True
    assert out.read_text() == ""


def test_run_hashcat_show_writes_results_and_leaves_no_temp_file(
    main_module, tmp_path, monkeypatch
):
    _stub_hashcat(tmp_path, main_module, monkeypatch, stdout=f"{'a' * 32}:pw-a\n")
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text(f"{'a' * 32}\n")
    out = tmp_path / "hashes.txt.out"

    assert main_module._run_hashcat_show("1000", str(hash_file), str(out)) is True
    assert out.read_text() == f"{'a' * 32}:pw-a\n"
    assert [p.name for p in tmp_path.iterdir() if ".show.tmp" in p.name] == []


def test_same_path_guard_catches_a_different_spelling(
    main_module, tmp_path, monkeypatch, capsys
):
    plain, out = _setup(tmp_path, main_module, monkeypatch, pwdump=False)
    monkeypatch.setattr(
        main_module,
        "hcatHashFileOrig",
        str(tmp_path / "." / "hashes.txt"),
        raising=False,
    )
    _stub_hashcat(tmp_path, main_module, monkeypatch)
    before = out.read_bytes()

    main_module.combine_ntlm_output()

    assert "not pwdump format" in capsys.readouterr().out
    assert out.read_bytes() == before
