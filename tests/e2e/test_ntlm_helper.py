from tests.e2e.conftest import _ntlm


def test_ntlm_known_vector_password():
    assert _ntlm("password") == "8846f7eaee8fb117ad06bdd830b7586c"


def test_ntlm_known_vector_empty_string():
    assert _ntlm("") == "31d6cfe0d16ae931b73c59d7e0c089c0"


def test_ntlm_matches_hashcat_cracking_a_known_hash(tmp_path):
    """Cross-check against real hashcat itself, not just known vectors:
    write the NTLM hash this helper computes for a password, ask hashcat
    to crack it against a one-line wordlist containing that password, and
    confirm hashcat reports a crack. This is the actual thing this whole
    suite depends on being correct."""
    import subprocess
    import shutil
    if not shutil.which("hashcat"):
        import pytest
        pytest.skip("hashcat not on PATH")
    from tests.e2e.conftest import _ntlm
    pw = "e2etestvector99"
    hash_file = tmp_path / "test.ntlm"
    hash_file.write_text(_ntlm(pw) + "\n")
    wordlist = tmp_path / "wl.txt"
    wordlist.write_text(pw + "\n")
    out_file = tmp_path / "test.ntlm.out"
    result = subprocess.run(
        ["hashcat", "-m", "1000", str(hash_file), str(wordlist),
         "-o", str(out_file), "--potfile-disable"],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode in (0, 1), result.stdout + result.stderr
    assert out_file.is_file()
    assert pw in out_file.read_text()
