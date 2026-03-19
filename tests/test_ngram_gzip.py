import gzip
import os
from unittest.mock import MagicMock, patch

from hate_crack.attacks import ngram_attack


def _make_ctx(hash_type="1000", hash_file="/tmp/hashes.txt"):
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


class TestNgramAttack:
    def test_calls_hcatNgramX_with_corpus_and_group_size(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("password\nletmein\n")
        ctx.select_file_with_autocomplete.return_value = str(corpus)

        with patch("builtins.input", return_value="3"):
            ngram_attack(ctx)

        ctx.hcatNgramX.assert_called_once_with(
            ctx.hcatHashType, ctx.hcatHashFile, str(corpus), 3
        )

    def test_default_group_size_is_3(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("password\n")
        ctx.select_file_with_autocomplete.return_value = str(corpus)

        with patch("builtins.input", return_value=""):
            ngram_attack(ctx)

        ctx.hcatNgramX.assert_called_once()
        assert ctx.hcatNgramX.call_args[0][3] == 3

    def test_invalid_group_size_defaults_to_3(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("password\n")
        ctx.select_file_with_autocomplete.return_value = str(corpus)

        with patch("builtins.input", return_value="abc"):
            ngram_attack(ctx)

        ctx.hcatNgramX.assert_called_once()
        assert ctx.hcatNgramX.call_args[0][3] == 3

    def test_aborts_when_no_corpus_selected(self):
        ctx = _make_ctx()
        ctx.select_file_with_autocomplete.return_value = None

        ngram_attack(ctx)

        ctx.hcatNgramX.assert_not_called()

    def test_custom_group_size_passed_through(self, tmp_path):
        ctx = _make_ctx()
        corpus = tmp_path / "corpus.txt"
        corpus.write_text("password\n")
        ctx.select_file_with_autocomplete.return_value = str(corpus)

        with patch("builtins.input", return_value="5"):
            ngram_attack(ctx)

        assert ctx.hcatNgramX.call_args[0][3] == 5


class TestIsGzipped:
    def test_detects_gzip_file(self, tmp_path):
        from hate_crack.main import _is_gzipped

        gz_file = tmp_path / "test.txt.gz"
        with gzip.open(str(gz_file), "wb") as f:
            f.write(b"password\n")

        assert _is_gzipped(str(gz_file)) is True

    def test_plain_file_not_detected_as_gzip(self, tmp_path):
        from hate_crack.main import _is_gzipped

        plain = tmp_path / "test.txt"
        plain.write_bytes(b"password\n")

        assert _is_gzipped(str(plain)) is False

    def test_missing_file_returns_false(self, tmp_path):
        from hate_crack.main import _is_gzipped

        assert _is_gzipped(str(tmp_path / "nonexistent.txt")) is False

    def test_empty_file_returns_false(self, tmp_path):
        from hate_crack.main import _is_gzipped

        empty = tmp_path / "empty.txt"
        empty.write_bytes(b"")

        assert _is_gzipped(str(empty)) is False


class TestWordlistPath:
    def test_plain_file_yields_original_path(self, tmp_path):
        from hate_crack.main import _wordlist_path

        plain = tmp_path / "words.txt"
        plain.write_text("password\n")

        with _wordlist_path(str(plain)) as result:
            assert result == str(plain)

    def test_gzip_file_yields_temp_file_with_content(self, tmp_path):
        from hate_crack.main import _wordlist_path

        gz_file = tmp_path / "words.txt.gz"
        with gzip.open(str(gz_file), "wb") as f:
            f.write(b"password\nletmein\n")

        with _wordlist_path(str(gz_file)) as result:
            assert result != str(gz_file)
            assert os.path.isfile(result)
            with open(result, "rb") as f:
                assert f.read() == b"password\nletmein\n"

    def test_gzip_temp_file_removed_after_context(self, tmp_path):
        from hate_crack.main import _wordlist_path

        gz_file = tmp_path / "words.txt.gz"
        with gzip.open(str(gz_file), "wb") as f:
            f.write(b"password\n")

        with _wordlist_path(str(gz_file)) as result:
            tmp_path_used = result

        assert not os.path.exists(tmp_path_used)

    def test_plain_file_not_deleted_after_context(self, tmp_path):
        from hate_crack.main import _wordlist_path

        plain = tmp_path / "words.txt"
        plain.write_text("password\n")

        with _wordlist_path(str(plain)) as result:
            assert result == str(plain)

        assert plain.exists()
