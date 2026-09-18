"""Opt-in proof that brain actually rejects repeated candidates.

Gated behind HATE_CRACK_RUN_E2E=1 because it needs a real hashcat and starts
a real brain server. Everything else in the brain suite asserts that the right
flags are assembled; this is the only test that asserts hashcat did something
with them.
"""

import os
import shutil
import subprocess
import time

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("HATE_CRACK_RUN_E2E") != "1" or not shutil.which("hashcat"),
    reason="needs HATE_CRACK_RUN_E2E=1 and a hashcat binary",
)

# hashcat's own example hash for mode 3200, password "hashcat".
BCRYPT = "$2a$05$MBCzKhG1KhezLh.0LRa0Kuw12nLJtpHy6DIaU.JAnqJUDYspHC.Ou"
PORT = 6871
PASSWORD = "hate-crack-e2e"


def _run(hash_file, wordlist, potfile):
    return subprocess.run(
        [
            "hashcat",
            "-m",
            "3200",
            "-O",
            str(hash_file),
            str(wordlist),
            "--potfile-path",
            str(potfile),
            "-z",
            "--brain-host",
            "127.0.0.1",
            "--brain-port",
            str(PORT),
            "--brain-password",
            PASSWORD,
            "--brain-client-features",
            "3",
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    ).stdout


def test_second_identical_run_is_rejected_by_brain(tmp_path):
    hash_file = tmp_path / "h.txt"
    hash_file.write_text(BCRYPT + "\n")
    wordlist = tmp_path / "w.txt"
    # Deliberately wrong candidates: the hash must stay uncracked so the
    # second run actually executes instead of exiting on a potfile hit.
    wordlist.write_text("alpha\nbravo\ncharlie\n")
    potfile = tmp_path / "e2e.pot"

    server = subprocess.Popen(
        [
            "hashcat",
            "--brain-server",
            "--brain-port",
            str(PORT),
            "--brain-password",
            PASSWORD,
        ],
        cwd=str(tmp_path),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(3)
        first = _run(hash_file, wordlist, potfile)
        second = _run(hash_file, wordlist, potfile)
    finally:
        server.kill()
        server.wait(timeout=10)

    assert "Rejected.........: 0/3" in first
    assert "Rejected.........: 3/3" in second
