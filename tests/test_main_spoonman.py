"""Tests for hcatSpoonman and the Spoonman Attack handler (#169)."""

import gzip
import json
import os
import tracemalloc
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import attacks, rulegen


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


@pytest.fixture
def corpus(tmp_path):
    path = tmp_path / "cracked.txt"
    path.write_text("Password1!\npassword\nSummer2026\n", encoding="latin-1")
    return str(path)


class TestHcatSpoonman:
    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    def _run(self, main_module, tmp_path, corpus, monkeypatch, **kwargs):
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman(
                "1000", self._hash_file(tmp_path), corpus, **kwargs
            )
        return quick

    def test_derives_then_delegates_to_quick_dictionary(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)

        quick.assert_called_once()
        args, kwargs = quick.call_args
        assert args[0] == "1000"
        assert args[1] == self._hash_file(tmp_path)
        assert args[2].startswith("-r ")
        assert args[2].endswith("rules.full.rule")
        assert args[3].endswith("basewords.txt")
        assert kwargs["attack_name"] == "Spoonman"
        assert os.path.isfile(args[3])

    def test_coverage_selects_capped_rule_file(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch, coverage=95)
        assert quick.call_args[0][2].endswith("rules.top95.rule")

    def test_output_lives_beside_the_hash_file(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)
        expected_dir = self._hash_file(tmp_path) + ".spoonman"
        assert os.path.dirname(quick.call_args[0][3]) == expected_dir
        assert os.path.isdir(expected_dir)

    def test_cleanup_removes_derived_output(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        hash_file = self._hash_file(tmp_path)
        self._run(main_module, tmp_path, corpus, monkeypatch)
        assert os.path.isdir(hash_file + ".spoonman")

        monkeypatch.setattr(main_module, "hcatHashFile", hash_file)
        monkeypatch.setattr(main_module, "hcatHashFileOrig", hash_file)
        monkeypatch.setattr(main_module, "hcatHashType", "1000")
        monkeypatch.setattr(main_module, "pwdump_format", False)
        main_module.cleanup()
        assert not os.path.exists(hash_file + ".spoonman")

    def test_missing_corpus_reports_and_does_not_run_hashcat(
        self, main_module, tmp_path, monkeypatch, capsys
    ):
        quick = self._run(
            main_module, tmp_path, str(tmp_path / "nope.txt"), monkeypatch
        )
        quick.assert_not_called()
        assert "corpus not found" in capsys.readouterr().out

    def test_empty_corpus_reports_and_does_not_run_hashcat(
        self, main_module, tmp_path, monkeypatch, capsys
    ):
        empty = tmp_path / "empty.txt"
        empty.write_text("", encoding="latin-1")
        quick = self._run(main_module, tmp_path, str(empty), monkeypatch)
        quick.assert_not_called()
        assert "Rule derivation failed" in capsys.readouterr().out

    def test_reuses_cache_when_corpus_unchanged(
        self, main_module, tmp_path, corpus, monkeypatch, capsys
    ):
        self._run(main_module, tmp_path, corpus, monkeypatch)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            self._run(main_module, tmp_path, corpus, monkeypatch)
        generate.assert_not_called()
        assert "Reusing derived" in capsys.readouterr().out

    def test_regenerates_when_corpus_is_newer_than_cache(
        self, main_module, tmp_path, corpus, monkeypatch, capsys
    ):
        quick = self._run(main_module, tmp_path, corpus, monkeypatch)
        basewords = quick.call_args[0][3]
        # Corpus modified after the cache was written.
        os.utime(corpus, (os.path.getmtime(basewords) + 10,) * 2)
        capsys.readouterr()

        self._run(main_module, tmp_path, corpus, monkeypatch)
        assert "Deriving basewords" in capsys.readouterr().out

    def test_cached_run_still_honours_coverage(
        self, main_module, tmp_path, corpus, monkeypatch
    ):
        self._run(main_module, tmp_path, corpus, monkeypatch)
        quick = self._run(main_module, tmp_path, corpus, monkeypatch, coverage=99)
        assert quick.call_args[0][2].endswith("rules.top99.rule")


class TestSpoonmanCacheProvenance:
    """The derived-output cache must be keyed on the corpus, not just the hash file.

    The cache directory is named after the *hash* file, so before the
    provenance file the corpus identity never entered the key at all: derive
    from corpus A, then invoke with corpus B whose mtime happens to be older
    than the cache, and the attack reused A's basewords while announcing a
    cache hit.
    """

    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    def _corpus(self, tmp_path, name, words):
        path = tmp_path / name
        path.write_text("".join(f"{word}\n" for word in words), encoding="latin-1")
        return str(path)

    def _run(self, main_module, tmp_path, corpus, **kwargs):
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman(
                "1000", self._hash_file(tmp_path), corpus, **kwargs
            )
        return quick

    def _basewords(self, quick):
        with open(quick.call_args[0][3], encoding="latin-1") as handle:
            return {line.strip() for line in handle if line.strip()}

    def _provenance_path(self, tmp_path):
        return os.path.join(self._hash_file(tmp_path) + ".spoonman", "corpus.json")

    def test_same_corpus_twice_reuses_the_cache(
        self, main_module, tmp_path, corpus, capsys
    ):
        first = self._run(main_module, tmp_path, corpus)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            second = self._run(main_module, tmp_path, corpus)

        generate.assert_not_called()
        assert "Reusing derived" in capsys.readouterr().out
        assert second.call_args[0][2] == first.call_args[0][2]
        assert second.call_args[0][3] == first.call_args[0][3]

    def test_different_corpus_with_older_mtime_regenerates(
        self, main_module, tmp_path, capsys
    ):
        """The confirmed bug: B's basewords must be used, not A's."""
        corpus_a = self._corpus(tmp_path, "a.txt", ["quibblefox", "quibblefox1"])
        corpus_b = self._corpus(tmp_path, "b.txt", ["zarplewidget", "zarplewidget1"])

        first = self._run(main_module, tmp_path, corpus_a)
        assert "quibblefox" in self._basewords(first)
        capsys.readouterr()

        # B looks older than the cache A wrote, so the mtime check alone passes.
        cache_mtime = os.path.getmtime(first.call_args[0][3])
        os.utime(corpus_b, (cache_mtime - 100,) * 2)
        assert os.path.getmtime(corpus_b) < cache_mtime

        second = self._run(main_module, tmp_path, corpus_b)
        out = capsys.readouterr().out

        words = self._basewords(second)
        assert "zarplewidget" in words
        assert "quibblefox" not in words
        assert "Reusing derived" not in out
        assert "different corpus" in out

    def test_corpus_modified_in_place_regenerates(self, main_module, tmp_path, capsys):
        corpus = self._corpus(tmp_path, "a.txt", ["quibblefox", "quibblefox1"])
        first = self._run(main_module, tmp_path, corpus)
        cache_mtime = os.path.getmtime(first.call_args[0][3])
        capsys.readouterr()

        with open(corpus, "w", encoding="latin-1") as handle:
            handle.write("zarplewidget\nzarplewidget1\n")
        os.utime(corpus, (cache_mtime + 10,) * 2)

        second = self._run(main_module, tmp_path, corpus)
        assert "Deriving basewords" in capsys.readouterr().out
        assert "zarplewidget" in self._basewords(second)

    def test_same_mtime_but_different_size_regenerates(
        self, main_module, tmp_path, capsys
    ):
        """Two corpora can share a path and an mtime and still differ."""
        corpus = self._corpus(tmp_path, "a.txt", ["quibblefox", "quibblefox1"])
        first = self._run(main_module, tmp_path, corpus)
        original_mtime = os.path.getmtime(corpus)
        assert os.path.getmtime(first.call_args[0][3]) >= original_mtime
        capsys.readouterr()

        with open(corpus, "w", encoding="latin-1") as handle:
            handle.write("zarplewidget\nzarplewidget1\nzarplewidget2\n")
        # Restore the mtime the cache was written against: only the size differs.
        os.utime(corpus, (original_mtime,) * 2)

        second = self._run(main_module, tmp_path, corpus)
        out = capsys.readouterr().out
        assert "Reusing derived" not in out
        assert "zarplewidget" in self._basewords(second)

    @pytest.mark.parametrize(
        ("label", "contents"),
        [
            ("missing", None),
            ("empty", ""),
            ("malformed", "{not json at all"),
            ("wrong type", '["a", "b"]'),
            ("older version", '{"corpus": "/tmp/a.txt"}'),
        ],
    )
    def test_unusable_provenance_regenerates_without_raising(
        self, main_module, tmp_path, corpus, capsys, label, contents
    ):
        self._run(main_module, tmp_path, corpus)
        provenance = self._provenance_path(tmp_path)
        assert os.path.isfile(provenance)
        if contents is None:
            os.remove(provenance)
        else:
            with open(provenance, "w", encoding="utf-8") as handle:
                handle.write(contents)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate", wraps=rulegen.generate) as generate:
            quick = self._run(main_module, tmp_path, corpus)

        generate.assert_called_once()
        assert "Reusing derived" not in capsys.readouterr().out
        assert os.path.isfile(quick.call_args[0][3])
        # And the record is rewritten, so the next run is a hit again.
        with patch("hate_crack.rulegen.generate") as generate_again:
            self._run(main_module, tmp_path, corpus)
        generate_again.assert_not_called()

    @pytest.mark.parametrize(
        ("label", "overrides"),
        [
            ("string size", {"size": "12"}),
            ("null size", {"size": None}),
            ("string mtime", {"mtime": "1700000000.0"}),
            ("null mtime", {"mtime": None}),
        ],
    )
    def test_wrong_typed_provenance_fields_regenerate(
        self, main_module, tmp_path, corpus, capsys, label, overrides
    ):
        """A field of the right name but the wrong type is not a match.

        Safe today because the comparison is ``!=``, which a string can never
        satisfy against an int. Pinned so that a later change to coerce or
        numerically compare these cannot start honouring a record it should
        reject -- the corpus path is left correct here, so nothing but the
        typed field can decide the outcome.
        """
        self._run(main_module, tmp_path, corpus)
        provenance = self._provenance_path(tmp_path)
        with open(provenance, encoding="utf-8") as handle:
            recorded = json.load(handle)
        recorded.update(overrides)
        assert recorded["corpus"] == os.path.abspath(corpus)
        with open(provenance, "w", encoding="utf-8") as handle:
            json.dump(recorded, handle)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate", wraps=rulegen.generate) as generate:
            self._run(main_module, tmp_path, corpus)

        generate.assert_called_once()
        assert "Reusing derived" not in capsys.readouterr().out

    def test_interrupted_derivation_does_not_leave_a_matching_record(
        self, main_module, tmp_path, capsys
    ):
        """Ctrl-C mid-derivation must not resurrect the wrong-corpus bug.

        rulegen.generate() rewrites basewords.txt in place and
        non-atomically, and KeyboardInterrupt is not caught by hcatSpoonman.
        So an interrupt after the new basewords are on disk but before the new
        record is written used to leave corpus A's record beside corpus B's
        basewords -- and the next run against A matched the record, passed the
        mtime check, announced a cache hit and cracked with B's basewords.
        """
        corpus_a = self._corpus(tmp_path, "a.txt", ["quibblefox", "quibblefox1"])
        corpus_b = self._corpus(tmp_path, "b.txt", ["zarplewidget", "zarplewidget1"])

        first = self._run(main_module, tmp_path, corpus_a)
        basewords = first.call_args[0][3]
        assert "quibblefox" in self._basewords(first)

        real_generate = rulegen.generate

        def interrupt_after_writing(*args, **kwargs):
            # Write the real output, then interrupt exactly as a Ctrl-C during
            # the coverage report or a capped-rule write would.
            real_generate(*args, **kwargs)
            raise KeyboardInterrupt

        with (
            patch.object(main_module, "hcatQuickDictionary") as quick,
            patch("hate_crack.rulegen.generate", interrupt_after_writing),
            pytest.raises(KeyboardInterrupt),
        ):
            main_module.hcatSpoonman("1000", self._hash_file(tmp_path), corpus_b)
        quick.assert_not_called()

        # State check: B's basewords are on disk under A's cache directory.
        with open(basewords, encoding="latin-1") as handle:
            words = {line.strip() for line in handle if line.strip()}
        assert "zarplewidget" in words
        capsys.readouterr()

        # Now the run that used to crack with the wrong corpus.
        third = self._run(main_module, tmp_path, corpus_a)
        out = capsys.readouterr().out
        assert "Reusing derived" not in out
        assert "quibblefox" in self._basewords(third)
        assert "zarplewidget" not in self._basewords(third)

    def test_failed_derivation_leaves_no_record(self, main_module, tmp_path, corpus):
        """The OSError/ValueError path returns early; the record must be gone."""
        self._run(main_module, tmp_path, corpus)
        provenance = self._provenance_path(tmp_path)
        assert os.path.isfile(provenance)

        empty = tmp_path / "empty.txt"
        empty.write_text("", encoding="latin-1")
        quick = self._run(main_module, tmp_path, str(empty))

        quick.assert_not_called()
        assert not os.path.exists(provenance)

    def test_switching_coverage_tier_does_not_invalidate_the_cache(
        self, main_module, tmp_path, corpus, capsys
    ):
        self._run(main_module, tmp_path, corpus)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            quick = self._run(main_module, tmp_path, corpus, coverage=75)

        generate.assert_not_called()
        assert "Reusing derived" in capsys.readouterr().out
        assert quick.call_args[0][2].endswith("rules.top75.rule")

    def test_provenance_records_the_corpus_it_derived_from(
        self, main_module, tmp_path, corpus
    ):
        self._run(main_module, tmp_path, corpus)
        with open(self._provenance_path(tmp_path), encoding="utf-8") as handle:
            recorded = json.load(handle)

        assert recorded["corpus"] == os.path.abspath(corpus)
        assert recorded["size"] == os.path.getsize(corpus)
        assert recorded["mtime"] == os.path.getmtime(corpus)


class TestHcatSpoonmanGzip:
    """#214: a gzipped corpus must be decompressed before derivation, not read
    as latin-1 mojibake — the tool downloads wordlists gzipped as a matter of
    course (Hashmob, Weakpass), so this is a normal input, not an exotic one.
    """

    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    # A 32-character digest: hash fields are recognized by digest length, so
    # a short stand-in like "hash1" is treated as part of the password.
    _NTLM = "31d6cfe0d16ae931b73c59d7e0c089c0"

    def _gzip_corpus(self, tmp_path, name="cracked.txt.gz"):
        path = tmp_path / name
        with gzip.open(str(path), "wt", encoding="latin-1") as f:
            f.write(f"{self._NTLM}:Spring2026\n{self._NTLM}:Summer2026\n")
        return str(path)

    def test_derives_real_basewords_not_mojibake(self, main_module, tmp_path):
        corpus = self._gzip_corpus(tmp_path)
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman("1000", self._hash_file(tmp_path), corpus)

        basewords_path = quick.call_args[0][3]
        with open(basewords_path, encoding="latin-1") as f:
            words = {line.strip() for line in f if line.strip()}

        assert words == {"spring", "summer"}
        # This is the assertion that alone would have caught the original
        # bug: a gzip stream decodes cleanly as latin-1 (every byte 0x00-0xFF
        # is valid), so without decompression these bytes would be non-ASCII
        # mojibake rather than raising.
        for word in words:
            assert all(0x20 <= ord(c) <= 0x7E for c in word), word

    def test_leet_restoration_is_enabled_and_actually_restores(
        self, main_module, tmp_path
    ):
        """hcatSpoonman asks for leet restoration, and the run performs it.

        Wraps the real generate() instead of replacing it, so this checks the
        argument reached rulegen *and* that the derived basewords changed --
        a mock's call_args alone would pass even if generate ignored the flag.
        """
        corpus = tmp_path / "cracked.txt"
        # Three attestations of an invented compound, plus a leet-mangled form.
        corpus.write_text(
            "quibblefox\nquibblefox\nquibblefox\nQu1bblefox\n", encoding="latin-1"
        )
        seen = {}
        real_generate = rulegen.generate

        def spy(*args, **kwargs):
            seen.update(kwargs)
            return real_generate(*args, **kwargs)

        with (
            patch.object(main_module, "hcatQuickDictionary") as quick,
            patch("hate_crack.rulegen.generate", spy),
        ):
            main_module.hcatSpoonman("1000", self._hash_file(tmp_path), str(corpus))

        assert seen.get("leet_restore") is True
        with open(quick.call_args[0][3], encoding="latin-1") as f:
            words = [line.strip() for line in f if line.strip()]
        # Without restoration this would also contain "qubblefox".
        assert words == ["quibblefox"]

    def test_staleness_check_compares_original_corpus_not_temp_file(
        self, main_module, tmp_path
    ):
        """The trap: getmtime(corpus) must stay pinned to the gzip path.

        Every decompressed temp file is newly created, so if the staleness
        check were pointed at the temp file instead of the original gzip
        path, the cache would invalidate on every single run.
        """
        corpus = self._gzip_corpus(tmp_path)
        hash_file = self._hash_file(tmp_path)

        with patch.object(main_module, "hcatQuickDictionary"):
            main_module.hcatSpoonman("1000", hash_file, corpus)

        with (
            patch.object(main_module, "hcatQuickDictionary"),
            patch("hate_crack.rulegen.generate") as generate,
        ):
            main_module.hcatSpoonman("1000", hash_file, corpus)

        generate.assert_not_called()


class TestSpoonmanOptimizedKernelLengthWarning:
    """``-O`` drops over-long candidates without saying anything.

    Verified against hashcat v7.1.2 in mode 0: with ``-O`` a 31-character
    plaintext cracks and a 32-character one does not, with no warning and a
    clean exit. Spoonman's baseword list is full of whole literal passwords, so
    a corpus with long entries loses them silently -- hence the warning.
    """

    # Invented tokens only, assembled to run past the cap.
    LONG = "wibble" * 7  # 42 characters
    ALSO_LONG = "quibblefox" + "zarplewidget" + "grumbleknobbler"  # 37

    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    def _corpus(self, tmp_path, words):
        path = tmp_path / "cracked.txt"
        path.write_text("".join(f"{word}\n" for word in words), encoding="latin-1")
        return str(path)

    def _run(self, main_module, tmp_path, words):
        corpus = self._corpus(tmp_path, words)
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman("1000", self._hash_file(tmp_path), corpus)
        return quick

    def test_cap_is_the_verified_mode_zero_figure(self, main_module):
        assert main_module.OPTIMIZED_KERNEL_MAX_PLAIN_LENGTH == 31

    def test_warns_and_names_the_count(self, main_module, tmp_path, capsys):
        quick = self._run(
            main_module, tmp_path, [self.LONG, self.ALSO_LONG, "shortword"]
        )
        out = capsys.readouterr().out

        # The two long entries really are in the list handed to hashcat, and
        # they really are over the cap -- otherwise the count means nothing.
        with open(quick.call_args[0][3], encoding="latin-1") as handle:
            words = [line.rstrip("\n") for line in handle if line.strip()]
        over = [word for word in words if len(word) > 31]
        assert sorted(over) == sorted([self.LONG, self.ALSO_LONG])

        assert "2 baseword(s) exceed 31 characters" in out
        assert "-O" in out
        assert "--no-optimized-kernel" in out

    def test_no_warning_when_every_baseword_is_short(
        self, main_module, tmp_path, capsys
    ):
        self._run(main_module, tmp_path, ["shortword", "otherword1", "Thirdword!"])
        assert "exceed" not in capsys.readouterr().out

    def test_no_warning_when_optimized_kernel_is_disabled(
        self, main_module, tmp_path, capsys, monkeypatch
    ):
        """Exactly what --no-optimized-kernel sets, so nothing is dropped."""
        monkeypatch.setattr(main_module, "_optimized_kernel_disabled", True)
        self._run(main_module, tmp_path, [self.LONG, self.ALSO_LONG, "shortword"])
        assert "exceed" not in capsys.readouterr().out

    def test_no_warning_when_attack_is_not_in_the_optimized_set(
        self, main_module, tmp_path, capsys, monkeypatch
    ):
        monkeypatch.setattr(
            main_module,
            "_optimized_kernel_attacks",
            frozenset(main_module.DEFAULT_OPTIMIZED_ATTACKS) - {"hcatQuickDictionary"},
        )
        self._run(main_module, tmp_path, [self.LONG, self.ALSO_LONG, "shortword"])
        assert "exceed" not in capsys.readouterr().out

    def test_attack_still_runs_when_the_warning_fires(self, main_module, tmp_path):
        """The warning is informational: same delegation, same paths."""
        quick = self._run(main_module, tmp_path, [self.LONG, "shortword"])
        quick.assert_called_once()
        assert quick.call_args[0][3].endswith("basewords.txt")

    @pytest.mark.parametrize("kind", ["missing", "directory"])
    def test_unreadable_basewords_file_is_skipped_silently(
        self, main_module, tmp_path, capsys, kind
    ):
        target = str(tmp_path / "nope.txt")
        if kind == "directory":
            target = str(tmp_path)
        assert main_module._count_over_long_basewords(target) is None
        # And the caller neither raises nor prints.
        main_module._warn_optimized_kernel_length_loss(target)
        assert capsys.readouterr().out == ""

    def test_counts_lines_regardless_of_line_ending(self, main_module, tmp_path):
        path = tmp_path / "basewords.txt"
        # A trailing \r must not be counted as part of the baseword: a 31-char
        # entry written CRLF is 32 bytes on the line but still fits.
        path.write_bytes(b"w" * 31 + b"\r\n" + b"w" * 32 + b"\n")
        assert main_module._count_over_long_basewords(str(path)) == 1

    def test_does_not_read_the_whole_file_into_memory(self, main_module, tmp_path):
        """A baseword list is corpus-sized; counting it must stream.

        Measured, not asserted on the implementation's shape: a
        read()/readlines() implementation has to hold the whole file, so its
        peak allocation tracks the file size. 24 MB of basewords against a
        2 MB ceiling separates the two unambiguously.
        """
        path = tmp_path / "basewords.txt"
        line = ("wibble" * 10 + "\n").encode("latin-1")  # 61 bytes
        chunk = line * 4096
        with open(path, "wb") as handle:
            for _ in range(96):
                handle.write(chunk)
        size = path.stat().st_size
        assert size > 20 * 1024 * 1024

        tracemalloc.start()
        try:
            count = main_module._count_over_long_basewords(str(path))
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        assert count == 96 * 4096  # every line is 60 characters, all over 31
        assert peak < 2 * 1024 * 1024, f"peak {peak} against a {size}-byte file"


class TestSpoonmanAttackHandler:
    def _ctx(self, tmp_path, corpus):
        ctx = MagicMock()
        ctx.hcatWordlists = str(tmp_path)
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "hashes.txt"
        ctx.select_file_with_autocomplete.return_value = corpus
        return ctx

    def test_passes_corpus_and_full_coverage(self, tmp_path, corpus):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", return_value="5"):
            attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", "hashes.txt", corpus, coverage=None
        )

    @pytest.mark.parametrize(
        ("choice", "expected"), [("1", 50), ("2", 75), ("3", 95), ("4", 99)]
    )
    def test_passes_capped_coverage(self, tmp_path, corpus, choice, expected):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", return_value=choice):
            attacks.spoonman_attack(ctx)
        assert ctx.hcatSpoonman.call_args.kwargs["coverage"] == expected

    def test_blank_corpus_aborts(self, tmp_path, corpus, capsys):
        ctx = self._ctx(tmp_path, corpus)
        ctx.select_file_with_autocomplete.return_value = "  "
        attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()
        assert "No corpus specified" in capsys.readouterr().out

    def test_nonexistent_corpus_aborts(self, tmp_path, capsys):
        ctx = self._ctx(tmp_path, str(tmp_path / "missing.txt"))
        attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()
        assert "Corpus not found" in capsys.readouterr().out

    @pytest.mark.parametrize("choice", ["99", None])
    def test_back_out_of_rule_set_menu(self, tmp_path, corpus, choice):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", return_value=choice):
            attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()


class TestSpoonmanCorpusSourceMenu:
    """#219: offer the session's own cracked output as a corpus source.

    The single hard requirement is the no-cracked path: it must stay
    byte-identical to today (straight to the path prompt, no menu, no extra
    output), because every existing user without cracked output yet hits it.
    """

    def _ctx(self, tmp_path, corpus, hash_file):
        ctx = MagicMock()
        ctx.hcatWordlists = str(tmp_path)
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = str(hash_file)
        ctx.select_file_with_autocomplete.return_value = corpus
        return ctx

    def _with_cracked_out(self, tmp_path, contents="hash1:Synthetic-Alpha1\n"):
        hash_file = tmp_path / "hashes.txt"
        out_path = tmp_path / "hashes.txt.out"
        out_path.write_text(contents, encoding="latin-1")
        return hash_file, str(out_path)

    def test_menu_offers_session_cracked_when_out_nonempty(self, tmp_path, corpus):
        hash_file, out_path = self._with_cracked_out(tmp_path)
        ctx = self._ctx(tmp_path, corpus, hash_file)

        menu_calls = []

        def fake_menu(items, **kwargs):
            menu_calls.append(items)
            # First call is the corpus-source picker, second is rule-set size.
            return "1" if len(menu_calls) == 1 else "5"

        with patch("hate_crack.attacks.interactive_menu", side_effect=fake_menu):
            attacks.spoonman_attack(ctx)

        assert any(
            ("1", "Cracked passwords (current session)") in items
            for items in menu_calls
        )
        ctx.select_file_with_autocomplete.assert_not_called()
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", str(hash_file), out_path, coverage=None
        )

    def test_choosing_file_option_falls_through_to_path_prompt(self, tmp_path, corpus):
        hash_file, _out_path = self._with_cracked_out(tmp_path)
        ctx = self._ctx(tmp_path, corpus, hash_file)

        calls = {"n": 0}

        def fake_menu(items, **kwargs):
            calls["n"] += 1
            return "2" if calls["n"] == 1 else "5"

        with patch("hate_crack.attacks.interactive_menu", side_effect=fake_menu):
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", str(hash_file), corpus, coverage=None
        )

    @pytest.mark.parametrize("choice", ["99", None])
    def test_cancel_at_corpus_source_menu_derives_nothing(
        self, tmp_path, corpus, choice
    ):
        hash_file, _out_path = self._with_cracked_out(tmp_path)
        ctx = self._ctx(tmp_path, corpus, hash_file)

        with patch("hate_crack.attacks.interactive_menu", return_value=choice):
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_not_called()
        ctx.hcatSpoonman.assert_not_called()

    def test_no_out_file_skips_menu_and_prompts_directly(self, tmp_path, corpus):
        """Regression guard: no `.out` -> today's behaviour, unchanged."""
        hash_file = tmp_path / "hashes.txt"
        ctx = self._ctx(tmp_path, corpus, hash_file)

        # side_effect, not return_value: if a regression ever makes the
        # corpus-source menu appear here, its invalid-selection loop would spin
        # forever against a fixed return and hang the suite instead of failing.
        # A finite sequence raises StopIteration on the second call, so the
        # guard fails loudly and fast.
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5"]) as menu:
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        # Only the rule-set-size menu should run; no corpus-source menu.
        assert menu.call_count == 1
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", str(hash_file), corpus, coverage=None
        )

    def test_empty_out_file_counts_as_absent(self, tmp_path, corpus):
        """A zero-byte `.out` derives nothing, so it must be treated as absent."""
        hash_file = tmp_path / "hashes.txt"
        out_path = tmp_path / "hashes.txt.out"
        out_path.write_text("", encoding="latin-1")
        ctx = self._ctx(tmp_path, corpus, hash_file)

        # Finite side_effect for the same reason as the sibling guard above:
        # a regression that shows the corpus-source menu here must fail, not hang.
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5"]) as menu:
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        assert menu.call_count == 1
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", str(hash_file), corpus, coverage=None
        )

    def test_invalid_selection_reprompts_the_corpus_source_menu(
        self, tmp_path, corpus, capsys
    ):
        hash_file, out_path = self._with_cracked_out(tmp_path)
        ctx = self._ctx(tmp_path, corpus, hash_file)

        calls = {"n": 0}

        def fake_menu(items, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                return "bogus"
            if calls["n"] == 2:
                return "1"
            return "5"

        with patch("hate_crack.attacks.interactive_menu", side_effect=fake_menu):
            attacks.spoonman_attack(ctx)

        assert "Invalid selection" in capsys.readouterr().out
        ctx.hcatSpoonman.assert_called_once_with(
            "1000", str(hash_file), out_path, coverage=None
        )


# --------------------------------------------------------------------------
# validate_rule — screens rule text this module did not write
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule",
    [
        ":",
        "l",
        "c$2$0$2$5",
        "$!",
        "^a",
        "T3",
        "TA",
        "sao",
        "i3x",
        "x12",
        "p2",
        "c $2 $0",  # spaces are legal function separators
        "$ ",  # ...and a space is also a legal argument
        "[]",
        "u$1$2$3",
        "d",
        "r",
    ],
)
def test_validate_rule_accepts(rule):
    assert rulegen.validate_rule(rule) is True


@pytest.mark.parametrize(
    "rule",
    [
        "",
        None,
        123,
        "QQQ",  # not a hashcat op
        "$",  # argument runs off the end
        "i3",  # second argument missing
        "M",  # memory op: documented, but this hashcat will not run it
        "<5",  # reject-plain op: same
        "X123",  # memory extract: same
        "# comment",
        "c\t$1",  # non-printable
        "c$é",  # non-ASCII
        "   ",  # separators only, no functions
        "$1" * (rulegen.MAX_RULE_FUNCTIONS + 1),  # over the function ceiling
        "l" * (rulegen.MAX_RULE_LENGTH + 1),  # over the line-length ceiling
    ],
)
def test_validate_rule_rejects(rule):
    assert rulegen.validate_rule(rule) is False


def test_validate_rule_accepts_everything_derive_emits():
    """derive's output must survive the screen it shares a module with."""
    for pw in ["alpha", "Alpha2024!", "!!Delta-99", "sTuVwX", "12345", "a"]:
        _, rule = rulegen.derive(pw)
        assert rulegen.validate_rule(rule) is True, pw


@pytest.mark.parametrize("rule", ["h", "H", "S", "v23", "B23"])
def test_validate_rule_rejects_v7_only_ops(rule):
    """Deliberate: hashcat v7 runs these, v6 does not, and v6 drops them silently."""
    assert rulegen.validate_rule(rule) is False


@pytest.mark.parametrize(
    "rule",
    ["Ta", "T!", "Tz", "z!", "D!", "'!", "i!x", "x!2", "*!2", "y!", "O!2", "p!", "3!x"],
)
def test_validate_rule_rejects_bad_position_arguments(rule):
    """Counting arguments is not enough: a position must come from POS.

    hashcat rejects 'Ta' exactly as silently as it rejects an unknown op, so an
    arity-only check would let this class straight through to the rule file.
    """
    assert rulegen.validate_rule(rule) is False


@pytest.mark.parametrize("rule", ["e!", "@!", "s!x", "i2!", "o2!", "32!", "$!", "^!"])
def test_validate_rule_allows_any_literal_character_argument(rule):
    """The other half of the same rule: literal-argument slots take punctuation."""
    assert rulegen.validate_rule(rule) is True
