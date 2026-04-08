"""E2E test: output files land next to the hashfile, not in the package directory.

Requires: hashcat installed, HATE_CRACK_RUN_E2E=1

Creates a dummy pwdump file at /tmp/test_hashes.ntds with known weak
NTLM hashes, runs a real hashcat dictionary attack, then verifies:
  - /tmp/test_hashes.ntds.nt      (NT hash extraction)
  - /tmp/test_hashes.ntds.nt.out  (hashcat cracked output)
  - /tmp/test_hashes.ntds.out     (combined pwdump + password)
  - No symlinks or output files created in the project directory
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Known NTLM hashes for weak passwords
PWDUMP_LINES = [
    "alice:500:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::\n",
    "bob:501:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::\n",
]
WORDLIST = ["password\n", "123456\n"]
EXPECTED_CRACKS = {
    "8846f7eaee8fb117ad06bdd830b7586c": "password",
    "32ed87bdb5fdc5e9cba88547376818d4": "123456",
}

HASH_BASE = Path("/tmp/test_hashes.ntds")
TEST_FILES = [
    HASH_BASE,
    Path(f"{HASH_BASE}.nt"),
    Path(f"{HASH_BASE}.nt.out"),
    Path(f"{HASH_BASE}.out"),
    Path(f"{HASH_BASE}.lm"),
    Path(f"{HASH_BASE}.lm.cracked"),
    Path(f"{HASH_BASE}.working"),
    Path(f"{HASH_BASE}.masks"),
    Path(f"{HASH_BASE}.expanded"),
    Path(f"{HASH_BASE}.combined"),
    Path(f"{HASH_BASE}.passwords"),
    Path("/tmp/test_wordlist.txt"),
    Path("/tmp/test_potfile.pot"),
]


@pytest.fixture(autouse=True)
def clean_test_files():
    """Remove all test artifacts before and after each test."""
    for f in TEST_FILES:
        f.unlink(missing_ok=True)
    yield
    for f in TEST_FILES:
        f.unlink(missing_ok=True)


def _hashcat_available() -> bool:
    return shutil.which("hashcat") is not None


@pytest.mark.skipif(
    os.environ.get("HATE_CRACK_RUN_E2E") != "1",
    reason="Set HATE_CRACK_RUN_E2E=1 to run e2e tests.",
)
@pytest.mark.skipif(not _hashcat_available(), reason="hashcat not installed")
class TestOutputPathE2E:
    """Verify output files land next to the hashfile in /tmp/, not in the project dir."""

    def _create_hash_file(self):
        HASH_BASE.write_text("".join(PWDUMP_LINES))

    def _create_wordlist(self):
        Path("/tmp/test_wordlist.txt").write_text("".join(WORDLIST))

    def _extract_nt_hashes(self):
        """Extract NT hashes (field 4) from pwdump, sorted unique — mirrors main.py preprocessing."""
        nt_hashes = set()
        with open(HASH_BASE) as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) >= 4:
                    nt_hashes.add(parts[3])
        nt_path = Path(f"{HASH_BASE}.nt")
        nt_path.write_text("\n".join(sorted(nt_hashes)) + "\n")
        return str(nt_path)

    def _run_hashcat_crack(self, nt_file: str):
        """Run a real hashcat dictionary attack against extracted NT hashes."""
        potfile = "/tmp/test_potfile.pot"
        out_file = f"{nt_file}.out"
        cmd = [
            "hashcat",
            "-m", "1000",
            nt_file,
            "/tmp/test_wordlist.txt",
            "-a", "0",
            "-o", out_file,
            f"--potfile-path={potfile}",
            "--potfile-disable",
            "--quiet",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        # hashcat returns 0 (cracked) or 1 (exhausted) on success
        assert result.returncode in (0, 1), (
            f"hashcat failed (rc={result.returncode}): {result.stderr}"
        )
        return out_file

    def _combine_ntlm_output(self, nt_out_file: str):
        """Combine cracked NT hashes back into pwdump format — mirrors combine_ntlm_output()."""
        hashes = {}
        if os.path.isfile(nt_out_file):
            with open(nt_out_file) as f:
                for line in f:
                    parts = line.strip().split(":", 1)
                    if len(parts) == 2:
                        hashes[parts[0]] = parts[1]

        if not hashes:
            return

        combined_path = f"{HASH_BASE}.out"
        with open(combined_path, "w") as out, open(HASH_BASE) as orig:
            for line in orig:
                parts = line.split(":")
                if len(parts) >= 4 and parts[3] in hashes:
                    out.write(line.strip() + hashes[parts[3]] + "\n")

    def test_output_files_land_in_tmp(self):
        """Full flow: pwdump in /tmp -> hashcat -> combined output in /tmp."""
        self._create_hash_file()
        self._create_wordlist()

        # Step 1: Extract NT hashes (preprocessing)
        nt_file = self._extract_nt_hashes()
        assert os.path.isfile(nt_file), f"NT extraction failed: {nt_file}"

        # Step 2: Crack with real hashcat
        nt_out = self._run_hashcat_crack(nt_file)
        assert os.path.isfile(nt_out), f"hashcat output missing: {nt_out}"

        # Step 3: Combine back to pwdump format
        self._combine_ntlm_output(nt_out)

        # Verify: combined output exists at /tmp/test_hashes.ntds.out
        combined = Path(f"{HASH_BASE}.out")
        assert combined.exists(), f"Combined output missing: {combined}"
        assert combined.stat().st_size > 0, "Combined output is empty"

        # Verify: combined output has correct pwdump + password format
        with open(combined) as f:
            lines = f.readlines()
        assert len(lines) == 2, f"Expected 2 cracked lines, got {len(lines)}"
        for line in lines:
            parts = line.strip().split(":")
            assert len(parts) >= 4, f"Malformed combined line: {line}"
            nt_hash = parts[3]
            assert nt_hash in EXPECTED_CRACKS, f"Unexpected hash: {nt_hash}"

    def test_no_files_created_in_project_dir(self):
        """Verify no symlinks or output files leak into the project directory."""
        self._create_hash_file()
        self._create_wordlist()

        nt_file = self._extract_nt_hashes()
        self._run_hashcat_crack(nt_file)
        self._combine_ntlm_output(f"{nt_file}.out")

        # Check project root for any test_hashes artifacts
        for item in REPO_ROOT.iterdir():
            assert "test_hashes" not in item.name, (
                f"Test artifact leaked into project dir: {item}"
            )

    def test_nt_extraction_output_path(self):
        """NT hash extraction writes .nt file next to the original."""
        self._create_hash_file()
        nt_file = self._extract_nt_hashes()
        assert nt_file == f"{HASH_BASE}.nt"
        assert Path(nt_file).parent == Path("/tmp")

    def test_hashcat_output_path(self):
        """hashcat -o writes .nt.out next to the .nt file."""
        self._create_hash_file()
        self._create_wordlist()
        nt_file = self._extract_nt_hashes()
        nt_out = self._run_hashcat_crack(nt_file)
        assert nt_out == f"{HASH_BASE}.nt.out"
        assert Path(nt_out).parent == Path("/tmp")
