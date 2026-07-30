"""Regression tests for #215: gzip wordlists piped to external binaries.

``_open_wordlist`` returns a ``gzip.GzipFile`` for a gzip-compressed source.
Reading that object *in Python* decompresses correctly, but
``subprocess.Popen(stdin=<that object>)`` resolves it through ``fileno()``,
and ``GzipFile.fileno()`` returns the fd of the *underlying compressed
file* -- so a child process given it as stdin reads the raw gzip stream,
not the decompressed text.

These tests catch that class of bug the only way that actually works: by
substituting a stub executable for the external binary that records the
raw bytes it receives on stdin, then asserting those bytes are the
decompressed plaintext, not a gzip stream (magic bytes ``\\x1f\\x8b``).

The three affected call sites, all now routed through ``_wordlist_path``
(which materializes a real decompressed path) instead of ``_open_wordlist``
(whose handle must never reach subprocess):

- ``hcatMarkovTrain`` -> hcstat2gen.bin
- ``hcatPrince`` -> princeprocessor
- ``hcatPermute`` -> permute.bin
"""

import gzip
import stat
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PLAINTEXT_LINES = ["alpha", "bravo", "charlie"]
PLAINTEXT_BODY = ("\n".join(PLAINTEXT_LINES) + "\n").encode()

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="stub relies on a POSIX shebang script with chmod +x",
)


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _make_gz_wordlist(tmp_path: Path, name: str = "wordlist.txt") -> Path:
    """Write a gzip body under a plain (non-.gz) name.

    Deliberately not named *.gz: the point is to exercise the magic-byte
    detection path in ``_is_gzipped`` / ``_wordlist_path``, independent of
    naming convention.
    """
    path = tmp_path / name
    with gzip.open(path, "wb") as f:
        f.write(PLAINTEXT_BODY)
    return path


def _make_capture_stub(
    tmp_path: Path, name: str, capture_path: Path, out_file_arg: bool = False
) -> Path:
    """A stub executable that records its stdin bytes to *capture_path*.

    When ``out_file_arg`` is set, also writes a small non-empty file to
    argv[1] -- ``hcstat2gen`` takes its output path as a positional arg,
    so that call site needs a plausible output file to exist afterward.
    princeprocessor/permute.bin take no such arg (their output is stdout,
    piped onward), so leave it off there to avoid writing a stray file
    under a flag-shaped name like ``--case-permute``.
    """
    script = tmp_path / name
    body = f'#!/bin/sh\ncat > "{capture_path}"\n'
    if out_file_arg:
        body += 'if [ -n "$1" ]; then\n  printf "stub-hcstat2-data" > "$1"\nfi\n'
    script.write_text(body)
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return script


class TestMarkovTrainStdin:
    def test_hcstat2gen_receives_decompressed_bytes(self, main_module, tmp_path):
        gz_wordlist = _make_gz_wordlist(tmp_path)
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("dummy")
        capture = tmp_path / "captured_stdin.bin"

        bin_dir = tmp_path / "hcbin"
        bin_dir.mkdir()
        stub = _make_capture_stub(bin_dir, "hcstat2gen.bin", capture, out_file_arg=True)

        with (
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatHcstat2genBin", "hcstat2gen.bin"),
        ):
            # hate_path/hashcat-utils/bin/<hcatHcstat2genBin> is the real
            # lookup path; point it at our stub via a symlink-free layout.
            real_bin_dir = tmp_path / "hashcat-utils" / "bin"
            real_bin_dir.mkdir(parents=True)
            real_stub = real_bin_dir / "hcstat2gen.bin"
            real_stub.write_bytes(stub.read_bytes())
            real_stub.chmod(
                real_stub.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )

            result = main_module.hcatMarkovTrain(str(gz_wordlist), str(hash_file))

        assert result is True
        captured = capture.read_bytes()
        assert not captured.startswith(b"\x1f\x8b"), (
            "hcstat2gen received raw gzip bytes instead of decompressed text"
        )
        assert captured == PLAINTEXT_BODY


class TestPrinceStdin:
    def test_princeprocessor_receives_decompressed_bytes(self, main_module, tmp_path):
        gz_wordlist = _make_gz_wordlist(tmp_path, "prince_base.txt")
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("dummy")
        capture = tmp_path / "captured_stdin.bin"

        prince_dir = tmp_path / "princeprocessor"
        prince_dir.mkdir()
        _make_capture_stub(prince_dir, "pp64.bin", capture)

        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 99
        mock_hashcat_proc.stdout = None

        real_popen = main_module.subprocess.Popen
        call_count = {"n": 0}

        def popen_side_effect(cmd, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return real_popen(cmd, **kwargs)
            return mock_hashcat_proc

        with (
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatPrinceBin", "pp64.bin"),
            patch.object(main_module, "hcatPrinceBaseList", str(gz_wordlist)),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "get_rule_path", return_value="/tmp/prince.rule"),
            patch.object(main_module, "generate_session_id", return_value="sess1"),
            patch.object(main_module, "lineCount", return_value=0),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect),
        ):
            main_module.hcatPrince("1000", str(hash_file))

        captured = capture.read_bytes()
        assert not captured.startswith(b"\x1f\x8b"), (
            "princeprocessor received raw gzip bytes instead of decompressed text"
        )
        assert captured == PLAINTEXT_BODY


class TestPermuteStdin:
    def test_permute_bin_receives_decompressed_bytes(self, main_module, tmp_path):
        gz_wordlist = _make_gz_wordlist(tmp_path, "permute_input.txt")
        hash_file = tmp_path / "hashes.txt"
        hash_file.write_text("dummy")
        capture = tmp_path / "captured_stdin.bin"

        bin_dir = tmp_path / "hashcat-utils" / "bin"
        bin_dir.mkdir(parents=True)
        _make_capture_stub(bin_dir, "permute.bin", capture)

        mock_hashcat_proc = MagicMock()
        mock_hashcat_proc.wait.return_value = None
        mock_hashcat_proc.pid = 99
        mock_hashcat_proc.stdout = None

        real_popen = main_module.subprocess.Popen
        call_count = {"n": 0}

        def popen_side_effect(cmd, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return real_popen(cmd, **kwargs)
            return mock_hashcat_proc

        with (
            patch.object(main_module, "hate_path", str(tmp_path)),
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", ""),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "generate_session_id", return_value="sess1"),
            patch.object(main_module, "lineCount", return_value=0),
            patch.object(main_module, "hcatHashCracked", 0, create=True),
            patch("hate_crack.main.subprocess.Popen", side_effect=popen_side_effect),
        ):
            main_module.hcatPermute("1000", str(hash_file), str(gz_wordlist))

        captured = capture.read_bytes()
        assert not captured.startswith(b"\x1f\x8b"), (
            "permute.bin received raw gzip bytes instead of decompressed text"
        )
        assert captured == PLAINTEXT_BODY
