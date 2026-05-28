import os


def _write_executable(path, content):
    path.write_text(content)
    os.chmod(path, 0o755)


def test_pipal_runs_and_parses_basewords(hc_module, tmp_path, capsys):
    hc = hc_module
    hc.hcatHashType = "0"
    hc.pipal_count = 3
    hc.hcatHashFile = str(tmp_path / "hashes")

    out_path = tmp_path / "hashes.out"
    out_path.write_text("hash1:password123\nhash2:$HEX[70617373313233]\n")

    pipal_stub = tmp_path / "pipal_stub.py"
    _write_executable(
        pipal_stub,
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "out = None\n"
        "if '--output' in sys.argv:\n"
        "    out = sys.argv[sys.argv.index('--output') + 1]\n"
        "if not out:\n"
        "    out = sys.argv[-1]\n"
        "with open(out, 'w') as f:\n"
        "    f.write('Top 3 base words\\n')\n"
        "    f.write('pass123 10\\n')\n"
        "    f.write('letmein 5\\n')\n"
        "    f.write('welcome 3\\n')\n",
    )
    hc.pipalPath = str(pipal_stub)

    result = hc.pipal()
    captured = capsys.readouterr()

    assert result == ["pass123", "letmein", "welcome"]
    assert "Pipal file is at" in captured.out

    passwords_file = tmp_path / "hashes.passwords"
    assert passwords_file.exists()
    content = passwords_file.read_text()
    assert "password123" in content
    assert "pass123" in content


def test_pipal_passwords_file_is_newline_separated_with_hex(hc_module, tmp_path):
    """HEX-encoded cracked passwords must not be glued to the next line.

    Regression: binascii.unhexlify().decode() drops the trailing newline that
    normal lines retain from password[-1], so HEX rows concatenated with the
    next password in the .passwords file fed to pipal.
    """
    hc = hc_module
    hc.hcatHashType = "0"
    hc.pipal_count = 3
    hc.hcatHashFile = str(tmp_path / "hashes")

    out_path = tmp_path / "hashes.out"
    out_path.write_text(
        "hash1:password123\n"
        "hash2:$HEX[70617373313233]\n"  # "pass123"
        "hash3:letmein\n"
    )

    pipal_stub = tmp_path / "pipal_stub.py"
    _write_executable(
        pipal_stub,
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "out = sys.argv[sys.argv.index('--output') + 1]\n"
        "open(out, 'w').write('Top 3 base words\\n'\n"
        "                    'pass123 1\\n'\n"
        "                    'letmein 1\\n'\n"
        "                    'welcome 1\\n')\n",
    )
    hc.pipalPath = str(pipal_stub)

    hc.pipal()

    passwords = (tmp_path / "hashes.passwords").read_text().splitlines()
    assert passwords == ["password123", "pass123", "letmein"]


def test_pipal_missing_out_returns_empty(hc_module, tmp_path, capsys):
    hc = hc_module
    hc.hcatHashType = "0"
    hc.pipal_count = 3
    hc.hcatHashFile = str(tmp_path / "hashes")

    pipal_stub = tmp_path / "pipal_stub.py"
    _write_executable(
        pipal_stub,
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "out = None\n"
        "if '--output' in sys.argv:\n"
        "    out = sys.argv[sys.argv.index('--output') + 1]\n"
        "if not out:\n"
        "    out = sys.argv[-1]\n"
        "with open(out, 'w') as f:\n"
        "    f.write('Top 3 base words\\n')\n"
        "    f.write('pass123 10\\n')\n"
        "    f.write('letmein 5\\n')\n"
        "    f.write('welcome 3\\n')\n",
    )
    hc.pipalPath = str(pipal_stub)

    result = hc.pipal()
    captured = capsys.readouterr()

    assert result == []
    assert "No hashes were cracked" in captured.out
