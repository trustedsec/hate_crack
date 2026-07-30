"""Regression tests for issue #215.

Five sites used to decide whether to gunzip a wordlist by checking the
*filename* for a ``.gz`` suffix. hate_crack downloads wordlists as gzip and
names them from a server-supplied ``Content-Disposition`` header, so a gzip
body routinely lands under a plain ``.txt`` name — and a filename check misses
it every time. Each test here writes a real gzip file under a plain ``.txt``
name (no ``.gz`` suffix) and asserts the site decompresses it anyway, by
magic bytes rather than extension.
"""

import gzip
import importlib
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_main():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    import hate_crack.main as m  # noqa: PLC0415

    return importlib.reload(m)


def _load_attacks():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    import hate_crack.attacks as attacks  # noqa: PLC0415

    return attacks


def _write_gzip_body(path: Path, text: str) -> None:
    """Write a gzip stream to *path*, deliberately not naming it .gz."""
    with gzip.open(str(path), "wt") as f:
        f.write(text)


class TestIsGzippedSharedHelper:
    """hate_crack.plaintext.is_gzipped is now the single implementation."""

    def test_detects_gzip_body_under_plain_txt_name(self, tmp_path):
        from hate_crack.plaintext import is_gzipped

        corpus = tmp_path / "corpus.txt"
        _write_gzip_body(corpus, "aaa:Spring2026\n")

        assert is_gzipped(str(corpus)) is True

    def test_plain_text_under_txt_name_not_flagged(self, tmp_path):
        from hate_crack.plaintext import is_gzipped

        corpus = tmp_path / "corpus.txt"
        corpus.write_text("aaa:Spring2026\n")

        assert is_gzipped(str(corpus)) is False

    def test_main_is_gzipped_delegates_to_shared_helper(self, tmp_path):
        """main._is_gzipped is kept as a thin alias for existing callers/tests."""
        m = _load_main()
        corpus = tmp_path / "corpus.txt"
        _write_gzip_body(corpus, "aaa:Spring2026\n")

        assert m._is_gzipped(str(corpus)) is True


class TestOpenWordlistDispatch:
    """main._open_wordlist is the shared chokepoint for three of the five
    sites (hcatMarkovTrain, hcatPrince, hcatPermute all call it)."""

    @pytest.mark.parametrize("suffix", [".txt", ".dict", ""])
    def test_decompresses_gzip_body_regardless_of_extension(self, tmp_path, suffix):
        m = _load_main()
        corpus = tmp_path / f"corpus{suffix}"
        _write_gzip_body(corpus, "aaa:Spring2026\nbbb:Summer2026\n")

        with m._open_wordlist(str(corpus)) as fh:
            content = fh.read()

        assert content == b"aaa:Spring2026\nbbb:Summer2026\n"

    def test_plain_file_under_txt_name_read_as_is(self, tmp_path):
        m = _load_main()
        corpus = tmp_path / "corpus.txt"
        corpus.write_bytes(b"aaa:Spring2026\n")

        with m._open_wordlist(str(corpus)) as fh:
            content = fh.read()

        assert content == b"aaa:Spring2026\n"


class TestCombipowCrackPreflight:
    """attacks.combipow_crack's pre-flight line count (site 4).

    The line-count cap (63) is what makes this observable: 64 real words,
    gzip-compressed, named ``.txt``. Correct behaviour decompresses first and
    counts 64 real newlines, so it must reject and never call hcatCombipow.
    Reading the raw gzip bytes as if they were text counts newline bytes
    (0x0a) that happen to occur in the compressed stream — for a payload this
    small there are only a handful, nowhere near 64 — so the old,
    extension-based code sails under the cap and calls hcatCombipow anyway.
    """

    def test_rejects_64_lines_hidden_in_a_gzip_body_under_plain_txt_name(
        self, tmp_path
    ):
        attacks = _load_attacks()
        m = _load_main()
        ctx = MagicMock()
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        ctx._open_wordlist = m._open_wordlist

        corpus = tmp_path / "corpus.txt"
        _write_gzip_body(corpus, "\n".join(f"word{i}" for i in range(64)) + "\n")
        ctx.select_file_with_autocomplete.side_effect = [str(corpus)]

        with (
            patch(
                "hate_crack.attacks._notify.prompt_notify_for_attack",
                return_value=False,
            ),
            patch("builtins.input", side_effect=[]),
        ):
            attacks.combipow_crack(ctx)

        ctx.hcatCombipow.assert_not_called()


class TestHcatCombipowWordlistPath:
    """hcatCombipow (site 3) now goes through _wordlist_path."""

    def _popen_side_effect(self, fake_combipow, fake_hashcat):
        return [fake_combipow, fake_hashcat]

    def test_gzip_body_under_plain_txt_name_is_decompressed(self, tmp_path):
        m = _load_main()
        hash_file = str(tmp_path / "hashes.txt")
        combipow_bin = tmp_path / "hashcat-utils" / "bin" / "combipow.bin"
        combipow_bin.parent.mkdir(parents=True, exist_ok=True)
        combipow_bin.touch()

        wl = tmp_path / "words.txt"
        _write_gzip_body(wl, "word1\nword2\n")

        fake_combipow = MagicMock()
        fake_combipow.stdout = MagicMock()
        fake_hashcat = MagicMock()
        fake_hashcat.pid = 9999

        with (
            patch.object(m, "hate_path", str(tmp_path)),
            patch.object(m, "hcatBin", "hashcat"),
            patch.object(m, "hcatTuning", ""),
            patch("hate_crack.main.hcatHashFile", hash_file, create=True),
            patch(
                "hate_crack.main.subprocess.Popen",
                side_effect=[fake_combipow, fake_hashcat],
            ) as mock_popen,
        ):
            m.hcatCombipow("1000", hash_file, str(wl), use_space_sep=True)

        generator_cmd = mock_popen.call_args_list[0][0][0]
        wordlist_arg = generator_cmd[-1]
        # The path handed to the generator binary must not be the raw gzip
        # file: _wordlist_path decompresses it to a distinct temp path.
        assert wordlist_arg != str(wl)
        assert not os.path.exists(wordlist_arg), (
            "temp file should be cleaned up once the with-block exits"
        )

    def test_interrupt_path_cleans_up_temp_file_and_skips_stdout_close(self, tmp_path):
        """The Ctrl-C path: if _run_hcat_cmd raises, the temp file made by
        _wordlist_path must still be removed, and (matching prior behaviour)
        generator_proc.stdout.close() must NOT run, since the exception skips
        the rest of the with-block body exactly as it skipped the rest of the
        old try body.
        """
        m = _load_main()
        hash_file = str(tmp_path / "hashes.txt")
        combipow_bin = tmp_path / "hashcat-utils" / "bin" / "combipow.bin"
        combipow_bin.parent.mkdir(parents=True, exist_ok=True)
        combipow_bin.touch()

        wl = tmp_path / "words.txt"
        _write_gzip_body(wl, "word1\nword2\n")

        fake_combipow = MagicMock()
        fake_combipow.stdout = MagicMock()
        fake_hashcat = MagicMock()
        fake_hashcat.pid = 9999

        captured_tmp_path = {}
        orig_wordlist_path = m._wordlist_path

        import contextlib as _contextlib

        @_contextlib.contextmanager
        def spying_wordlist_path(path):
            with orig_wordlist_path(path) as resolved:
                captured_tmp_path["path"] = resolved
                yield resolved

        with (
            patch.object(m, "hate_path", str(tmp_path)),
            patch.object(m, "hcatBin", "hashcat"),
            patch.object(m, "hcatTuning", ""),
            patch.object(m, "_wordlist_path", spying_wordlist_path),
            patch("hate_crack.main.hcatHashFile", hash_file, create=True),
            patch(
                "hate_crack.main.subprocess.Popen",
                side_effect=[fake_combipow, fake_hashcat],
            ),
            patch.object(m, "_run_hcat_cmd", side_effect=KeyboardInterrupt),
            pytest.raises(KeyboardInterrupt),
        ):
            m.hcatCombipow("1000", hash_file, str(wl), use_space_sep=True)

        assert "path" in captured_tmp_path
        assert not os.path.exists(captured_tmp_path["path"]), (
            "temp file must be cleaned up by _wordlist_path.__exit__ even "
            "when _run_hcat_cmd raises"
        )
        fake_combipow.stdout.close.assert_not_called()
