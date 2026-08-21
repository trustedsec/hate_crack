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


def _wordlists(quick):
    """The dictionary list hcatQuickDictionary was called with.

    hcatSpoonman always passes a list now that it can append extra wordlists
    (task 6a), so the shape is asserted here once instead of in every caller.
    """
    passed = quick.call_args[0][3]
    assert isinstance(passed, list), f"expected a list of wordlists, got {passed!r}"
    return passed


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
        assert len(args[3]) == 1
        assert args[3][0].endswith("basewords.txt")
        assert kwargs["attack_name"] == "Spoonman"
        assert os.path.isfile(args[3][0])

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
        assert os.path.dirname(_wordlists(quick)[0]) == expected_dir
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
        basewords = _wordlists(quick)[0]
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
        with open(_wordlists(quick)[0], encoding="latin-1") as handle:
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
        assert _wordlists(second)[0] == _wordlists(first)[0]

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
        cache_mtime = os.path.getmtime(_wordlists(first)[0])
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
        cache_mtime = os.path.getmtime(_wordlists(first)[0])
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
        assert os.path.getmtime(_wordlists(first)[0]) >= original_mtime
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
        assert os.path.isfile(_wordlists(quick)[0])
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
        basewords = _wordlists(first)[0]
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

        basewords_path = _wordlists(quick)[0]
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
        with open(_wordlists(quick)[0], encoding="latin-1") as f:
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


class TestSpoonmanExtraWordlists:
    """Task 6a: cross the derived rules against additional wordlists.

    The derived rule set saturates almost immediately against unseen
    passwords, while roughly half the misses are a missing baseword -- so the
    dictionary side is the one worth widening. hashcat reads straight-mode
    dictionaries sequentially, so the order handed to it is the order they are
    tried in and the derived basewords must come first.
    """

    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    def _wordlist(self, tmp_path, name):
        path = tmp_path / name
        path.write_text("quibblefox\nzarplewidget\n", encoding="latin-1")
        return str(path)

    def _run(self, main_module, tmp_path, corpus, **kwargs):
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman(
                "1000", self._hash_file(tmp_path), corpus, **kwargs
            )
        return quick

    def test_derived_basewords_come_first_then_the_extras_in_order(
        self, main_module, tmp_path, corpus
    ):
        first = self._wordlist(tmp_path, "alpha.txt")
        second = self._wordlist(tmp_path, "beta.txt")

        quick = self._run(
            main_module, tmp_path, corpus, extra_wordlists=[first, second]
        )

        passed = _wordlists(quick)
        assert passed[0].endswith("basewords.txt")
        assert passed == [passed[0], first, second]

    def test_no_extras_passes_the_basewords_alone(self, main_module, tmp_path, corpus):
        quick = self._run(main_module, tmp_path, corpus)
        assert len(_wordlists(quick)) == 1

    @pytest.mark.parametrize("empty", [None, []])
    def test_empty_extra_list_is_the_same_as_none(
        self, main_module, tmp_path, corpus, empty
    ):
        quick = self._run(main_module, tmp_path, corpus, extra_wordlists=empty)
        assert len(_wordlists(quick)) == 1

    def test_missing_extra_is_named_and_skipped_without_aborting(
        self, main_module, tmp_path, corpus, capsys
    ):
        real = self._wordlist(tmp_path, "alpha.txt")
        missing = str(tmp_path / "nope.txt")

        quick = self._run(
            main_module, tmp_path, corpus, extra_wordlists=[missing, real]
        )
        out = capsys.readouterr().out

        assert "nope.txt" in out
        assert "not found" in out
        # The attack still runs, and hashcat never sees the missing path.
        quick.assert_called_once()
        passed = _wordlists(quick)
        assert missing not in passed
        assert passed == [passed[0], real]

    def test_all_extras_missing_still_runs_with_the_derived_basewords(
        self, main_module, tmp_path, corpus, capsys
    ):
        quick = self._run(
            main_module,
            tmp_path,
            corpus,
            extra_wordlists=[str(tmp_path / "a.txt"), str(tmp_path / "b.txt")],
        )
        assert capsys.readouterr().out.count("not found") == 2
        quick.assert_called_once()
        passed = _wordlists(quick)
        assert len(passed) == 1
        assert os.path.isfile(passed[0])

    def test_a_directory_is_an_acceptable_extra(self, main_module, tmp_path, corpus):
        """hashcat consumes a directory operand in straight mode, so existence
        is the test rather than isfile."""
        directory = tmp_path / "lists"
        directory.mkdir()
        quick = self._run(
            main_module, tmp_path, corpus, extra_wordlists=[str(directory)]
        )
        assert _wordlists(quick)[1] == str(directory)

    def test_the_corpus_itself_is_skipped_if_it_turns_up_among_the_extras(
        self, main_module, tmp_path, capsys
    ):
        """The corpus commonly lives *in* the configured wordlist directory.

        The corpus prompt's base_dir is hcatWordlists, so the directory the
        recommended baseword-source option enumerates is usually the one the
        corpus was picked from. Handing it back to hashcat as a dictionary is
        pure waste -- every line is a <digest>:<plaintext> record, which cannot
        be a candidate -- and on a large corpus it is the dominant cost of the
        run with nothing on screen to explain it.
        """
        wordlists = tmp_path / "wordlists"
        wordlists.mkdir()
        corpus = wordlists / "prev_engagement_cracked.txt"
        corpus.write_text("quibblefox\nQuibblefox1\n", encoding="latin-1")
        other = self._wordlist(wordlists, "other.txt")

        quick = self._run(
            main_module,
            tmp_path,
            str(corpus),
            extra_wordlists=[other, str(corpus)],
        )
        out = capsys.readouterr().out

        assert "prev_engagement_cracked.txt" in out
        assert "it is the corpus this attack derived from" in out
        passed = _wordlists(quick)
        assert passed == [passed[0], other]

    @pytest.mark.parametrize(
        "style", ["symlink", "dot_prefix", "parent_traversal", "case_differing"]
    )
    def test_the_corpus_is_recognized_through_a_symlink_or_a_relative_form(
        self, main_module, tmp_path, monkeypatch, style
    ):
        """identity, not a string compare: the two paths arrive separately.

        One is typed or picked by the operator, the other is joined onto a
        directory listing, so the same file reaching the two sides spelled two
        ways is ordinary -- including, on a case-insensitive filesystem, two
        spellings differing only in case (#291).
        """
        wordlists = tmp_path / "wordlists"
        wordlists.mkdir()
        corpus = wordlists / "prev_engagement_cracked.txt"
        corpus.write_text("quibblefox\nQuibblefox1\n", encoding="latin-1")

        if style == "symlink":
            alias = wordlists / "corpus_link.txt"
            alias.symlink_to(corpus)
            spelling = str(alias)
        elif style == "dot_prefix":
            monkeypatch.chdir(wordlists)
            spelling = os.path.join(".", "prev_engagement_cracked.txt")
        elif style == "case_differing":
            # A real filesystem probe, not sys.platform: skip cleanly on a
            # case-sensitive filesystem (Linux CI, a case-sensitive macOS
            # volume) rather than asserting something the filesystem itself
            # does not do.
            alt = wordlists / "Prev_Engagement_Cracked.txt"
            if not (alt.exists() and os.path.samefile(str(corpus), str(alt))):
                pytest.skip("filesystem is case-sensitive")
            spelling = str(alt)
        else:
            # A form that really does exist, so the existence check cannot be
            # what makes this pass.
            spelling = os.path.join(
                str(wordlists), "..", "wordlists", "prev_engagement_cracked.txt"
            )
        assert os.path.exists(spelling)

        quick = self._run(
            main_module, tmp_path, str(corpus), extra_wordlists=[spelling]
        )

        # Nothing but the derived basewords: the alias was recognized.
        assert len(_wordlists(quick)) == 1

    def test_a_different_file_in_the_corpus_directory_is_not_skipped(
        self, main_module, tmp_path, capsys
    ):
        """Control for the skip above: only the corpus itself is dropped."""
        wordlists = tmp_path / "wordlists"
        wordlists.mkdir()
        corpus = wordlists / "prev_engagement_cracked.txt"
        corpus.write_text("quibblefox\nQuibblefox1\n", encoding="latin-1")
        sibling = self._wordlist(wordlists, "prev_engagement_cracked_2.txt")

        quick = self._run(main_module, tmp_path, str(corpus), extra_wordlists=[sibling])
        assert "it is the corpus" not in capsys.readouterr().out
        assert _wordlists(quick)[1] == sibling

    def test_a_directory_containing_the_corpus_is_skipped(
        self, main_module, tmp_path, capsys
    ):
        """The extras include directories, so the guard cannot be depth-blind.

        list_wordlist_entries deliberately offers directories (hashcat walks a
        directory operand), so the common shape is a wordlist collection with
        the corpus unpacked into a subdirectory of its own. Comparing only the
        top-level entry against the corpus would hand hashcat the directory
        holding it and enumerate every <digest>:<plaintext> record in it.
        """
        wordlists = tmp_path / "wordlists"
        corpus_dir = wordlists / "cracked_dump"
        corpus_dir.mkdir(parents=True)
        corpus = corpus_dir / "found.txt"
        corpus.write_text("quibblefox\nQuibblefox1\n", encoding="latin-1")
        other = self._wordlist(wordlists, "other.txt")
        assert os.path.isdir(corpus_dir) and os.path.isfile(corpus)
        assert os.path.isfile(other)

        quick = self._run(
            main_module,
            tmp_path,
            str(corpus),
            extra_wordlists=[str(corpus_dir), other],
        )
        out = capsys.readouterr().out

        assert "directory containing the corpus" in out
        assert "cracked_dump" in out
        passed = _wordlists(quick)
        assert str(corpus_dir) not in passed
        assert passed == [passed[0], other]

    @pytest.mark.parametrize(
        ("corpus_dir_name", "offered_name"),
        [
            ("cracked_dump", "sibling"),
            # The string-prefix trap, and the direction that matters: the
            # offered directory's path is a bare prefix of the corpus's path,
            # so a startswith test without a separator would "contain" it and
            # silently drop a directory holding nothing but ordinary wordlists.
            ("cracked_dump2", "cracked_dump"),
        ],
    )
    def test_a_directory_that_does_not_contain_the_corpus_is_passed_through(
        self, main_module, tmp_path, capsys, corpus_dir_name, offered_name
    ):
        """Control for the skip above: do not over-skip."""
        wordlists = tmp_path / "wordlists"
        corpus_dir = wordlists / corpus_dir_name
        corpus_dir.mkdir(parents=True)
        corpus = corpus_dir / "found.txt"
        corpus.write_text("quibblefox\nQuibblefox1\n", encoding="latin-1")
        sibling = wordlists / offered_name
        sibling.mkdir()
        self._wordlist(sibling, "words.txt")
        assert os.path.isdir(sibling) and os.path.isfile(corpus)
        assert str(corpus).startswith(str(sibling)) == (offered_name == "cracked_dump")

        quick = self._run(
            main_module, tmp_path, str(corpus), extra_wordlists=[str(sibling)]
        )

        assert "the corpus" not in capsys.readouterr().out
        assert _wordlists(quick)[1] == str(sibling)

    def test_a_symlinked_directory_whose_target_holds_the_corpus_is_skipped(
        self, main_module, tmp_path, capsys
    ):
        """Both sides resolve through realpath, so an aliased parent is caught."""
        wordlists = tmp_path / "wordlists"
        corpus_dir = wordlists / "cracked_dump"
        corpus_dir.mkdir(parents=True)
        corpus = corpus_dir / "found.txt"
        corpus.write_text("quibblefox\nQuibblefox1\n", encoding="latin-1")
        alias = wordlists / "dump_link"
        alias.symlink_to(corpus_dir, target_is_directory=True)
        assert os.path.isdir(alias) and os.path.isfile(alias / "found.txt")

        quick = self._run(
            main_module, tmp_path, str(corpus), extra_wordlists=[str(alias)]
        )

        assert "directory containing the corpus" in capsys.readouterr().out
        assert len(_wordlists(quick)) == 1

    def test_extras_do_not_change_the_rule_file_or_the_cache(
        self, main_module, tmp_path, corpus, capsys
    ):
        first = self._run(main_module, tmp_path, corpus)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            second = self._run(
                main_module,
                tmp_path,
                corpus,
                extra_wordlists=[self._wordlist(tmp_path, "alpha.txt")],
            )

        generate.assert_not_called()
        assert second.call_args[0][2] == first.call_args[0][2]
        assert _wordlists(second)[0] == _wordlists(first)[0]


class TestSpoonmanCorpusGuards:
    """#291 + #292: identity-based guards, independent of ordering.

    _same_path and _path_contains moved from realpath string comparison to
    os.stat/os.path.samestat identity, so a corpus offered back under a
    different capitalization is still recognized on a case-insensitive
    filesystem (#291), and _path_contains is naturally True for an exact
    match so it no longer depends on _same_path running first to catch that
    case (#292). These exercise both functions directly rather than through
    hcatSpoonman, so each guard's correctness is a plain fact about the
    function rather than something that happens to hold given the current
    branch order in _spoonman_wordlists.
    """

    def test_exact_match_is_true_for_both_guards_independently(
        self, main_module, tmp_path
    ):
        """The #292 crux: neither guard depends on the other running first."""
        corpus = tmp_path / "found.txt"
        corpus.write_text("quibblefox\n", encoding="latin-1")

        assert main_module._same_path(str(corpus), str(corpus)) is True
        assert main_module._path_contains(str(corpus), str(corpus)) is True

    def test_containment_at_depth_and_the_reverse(self, main_module, tmp_path):
        root = tmp_path / "root"
        nested = root / "a" / "b"
        nested.mkdir(parents=True)
        found = nested / "found.txt"
        found.write_text("quibblefox\n", encoding="latin-1")

        assert main_module._path_contains(str(root), str(found)) is True
        assert main_module._path_contains(str(found), str(root)) is False

    def test_sibling_prefix_trap(self, main_module, tmp_path):
        """The unit-level twin of the integration string-prefix-trap test."""
        lists = tmp_path / "lists"
        lists.mkdir()
        lists2 = tmp_path / "lists2"
        lists2.mkdir()
        found = lists2 / "found.txt"
        found.write_text("quibblefox\n", encoding="latin-1")

        assert main_module._path_contains(str(lists), str(found)) is False

    def test_plain_file_container_contains_only_itself(self, main_module, tmp_path):
        plain = tmp_path / "plain.txt"
        plain.write_text("quibblefox\n", encoding="latin-1")
        other = tmp_path / "other.txt"
        other.write_text("zarplewidget\n", encoding="latin-1")

        assert main_module._path_contains(str(plain), str(plain)) is True
        assert main_module._path_contains(str(plain), str(other)) is False

    def test_missing_path_answers_false_never_raises(self, main_module, tmp_path):
        missing = str(tmp_path / "nope.txt")
        other_missing = str(tmp_path / "also_nope.txt")
        existing = tmp_path / "found.txt"
        existing.write_text("quibblefox\n", encoding="latin-1")

        assert main_module._same_path(missing, str(existing)) is False
        assert main_module._same_path(str(existing), missing) is False
        assert main_module._same_path(missing, other_missing) is False
        assert main_module._path_contains(missing, str(existing)) is False
        assert main_module._path_contains(str(existing), missing) is False
        assert main_module._path_contains(missing, other_missing) is False

    def test_relative_target_containment_is_load_bearing(
        self, main_module, tmp_path, monkeypatch
    ):
        """Fails without the abspath fix -- see _path_contains's docstring."""
        directory = tmp_path / "wordlists"
        directory.mkdir()
        found = directory / "found.txt"
        found.write_text("quibblefox\n", encoding="latin-1")
        monkeypatch.chdir(directory)

        assert main_module._path_contains(".", "found.txt") is True

    def test_case_differing_path_is_recognized_as_the_corpus(
        self, main_module, tmp_path
    ):
        corpus = tmp_path / "Prev_Engagement_Cracked.txt"
        corpus.write_text("quibblefox\n", encoding="latin-1")
        alt_spelling = tmp_path / "prev_engagement_cracked.txt"
        # A real filesystem probe, not sys.platform: skip cleanly on a
        # case-sensitive filesystem (Linux CI, a case-sensitive macOS volume).
        if not (
            alt_spelling.exists() and os.path.samefile(str(corpus), str(alt_spelling))
        ):
            pytest.skip("filesystem is case-sensitive")
        # The #291 premise, asserted explicitly so this cannot pass vacuously
        # if samefile's own behavior ever changes: realpath does not fold case.
        assert os.path.realpath(str(corpus)) != os.path.realpath(str(alt_spelling))

        assert main_module._same_path(str(corpus), str(alt_spelling)) is True
        assert main_module._path_contains(str(tmp_path), str(alt_spelling)) is True

    def test_spoonman_wordlists_skips_the_corpus_offered_as_an_extra(
        self, main_module, tmp_path
    ):
        """#292's own "option 1", done at the function level.

        Asserts the outcome rather than which branch caught it, so this
        survives any future refactor of the two guards inside
        _spoonman_wordlists.
        """
        basewords = tmp_path / "basewords.txt"
        basewords.write_text("quibblefox\n", encoding="latin-1")
        corpus = tmp_path / "cracked.txt"
        corpus.write_text("quibblefox\n", encoding="latin-1")

        result = main_module._spoonman_wordlists(
            str(basewords), [str(corpus)], corpus=str(corpus)
        )

        assert result == [str(basewords)]


class TestSpoonmanBasewordCap:
    """Task 6b: run only the N most frequent derived basewords.

    Honestly a keyspace budget rather than an accuracy setting: the audit
    measured the top-50% rules against a 5,000-baseword cap at 0.4% reach for
    0.011e9 candidates, versus 1.6% for 0.338e9 uncapped.
    """

    def _hash_file(self, tmp_path):
        return str(tmp_path / "hashes.txt")

    # Distinct frequencies so the retained set is decided by counts alone.
    CORPUS = [
        "quibblefox",
        "Quibblefox",
        "quibblefox1",
        "zarplewidget",
        "Zarplewidget",
        "grumbleknob",
    ]

    def _corpus(self, tmp_path, words=None):
        path = tmp_path / "cracked.txt"
        words = self.CORPUS if words is None else words
        path.write_text("".join(f"{w}\n" for w in words), encoding="latin-1")
        return str(path)

    def _run(self, main_module, tmp_path, corpus, **kwargs):
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatSpoonman(
                "1000", self._hash_file(tmp_path), corpus, **kwargs
            )
        return quick

    def _lines(self, path):
        with open(path, encoding="latin-1") as handle:
            return handle.read().splitlines()

    def test_cap_runs_the_capped_file_and_it_holds_the_top_n(
        self, main_module, tmp_path
    ):
        corpus = self._corpus(tmp_path)
        quick = self._run(main_module, tmp_path, corpus, baseword_cap=2)

        passed = _wordlists(quick)[0]
        assert passed.endswith("basewords.top2.txt")
        assert os.path.isfile(passed)
        assert self._lines(passed) == ["quibblefox", "zarplewidget"]
        # And the uncapped list is still on disk beside it, unused.
        full = os.path.join(os.path.dirname(passed), "basewords.txt")
        assert self._lines(full) == ["quibblefox", "zarplewidget", "grumbleknob"]

    def test_no_cap_runs_the_uncapped_file(self, main_module, tmp_path):
        quick = self._run(main_module, tmp_path, self._corpus(tmp_path))
        assert _wordlists(quick)[0].endswith("basewords.txt")

    def test_cap_and_coverage_combine(self, main_module, tmp_path):
        quick = self._run(
            main_module, tmp_path, self._corpus(tmp_path), coverage=95, baseword_cap=2
        )
        assert quick.call_args[0][2].endswith("rules.top95.rule")
        assert _wordlists(quick)[0].endswith("basewords.top2.txt")

    def test_cap_and_extra_wordlists_combine(self, main_module, tmp_path):
        extra = tmp_path / "alpha.txt"
        extra.write_text("flimberdoodle\n", encoding="latin-1")
        quick = self._run(
            main_module,
            tmp_path,
            self._corpus(tmp_path),
            baseword_cap=1,
            extra_wordlists=[str(extra)],
        )
        passed = _wordlists(quick)
        assert passed[0].endswith("basewords.top1.txt")
        assert passed[1] == str(extra)

    def test_cached_run_with_the_same_cap_reuses_the_capped_file(
        self, main_module, tmp_path, capsys
    ):
        corpus = self._corpus(tmp_path)
        first = self._run(main_module, tmp_path, corpus, baseword_cap=2)
        capped = _wordlists(first)[0]
        # Pin the ordering rather than relying on filesystem timestamp
        # resolution: reuse requires the capped file to be *strictly* newer than
        # the list it was cut from, so on a coarse-mtime filesystem a derivation
        # that wrote both within one tick would compare equal and rebuild.
        full = os.path.join(os.path.dirname(capped), "basewords.txt")
        os.utime(capped, (os.path.getmtime(full) + 10,) * 2)
        written_at = os.path.getmtime(capped)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            second = self._run(main_module, tmp_path, corpus, baseword_cap=2)
        out = capsys.readouterr().out

        generate.assert_not_called()
        assert "Reusing derived" in out
        assert _wordlists(second)[0] == capped
        # Reused as it stands: an up-to-date capped file is not rewritten.
        assert os.path.getmtime(capped) == written_at
        assert "Capped the cached baseword list" not in out

    def test_cap_on_a_warm_cache_truncates_instead_of_re_deriving(
        self, main_module, tmp_path, capsys
    ):
        """A new N must not cost a two-pass read of the whole corpus.

        N is operator-chosen, so a warm cache will usually not hold
        basewords.top{N}.txt -- and re-deriving to get one would be hours on a
        large corpus for a knob that invites "toggle it and see". The capped
        file is a prefix of basewords.txt, so it is truncated out of the cached
        list instead.
        """
        corpus = self._corpus(tmp_path)
        self._run(main_module, tmp_path, corpus)
        cache_dir = self._hash_file(tmp_path) + ".spoonman"
        assert not os.path.exists(os.path.join(cache_dir, "basewords.top2.txt"))
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate", wraps=rulegen.generate) as generate:
            quick = self._run(main_module, tmp_path, corpus, baseword_cap=2)
        out = capsys.readouterr().out

        generate.assert_not_called()
        assert "Reusing derived" in out
        assert "Capped the cached baseword list" in out
        passed = _wordlists(quick)[0]
        assert passed.endswith("basewords.top2.txt")
        assert self._lines(passed) == ["quibblefox", "zarplewidget"]

    def test_truncated_file_is_byte_identical_to_a_derived_one(
        self, main_module, tmp_path
    ):
        """The shortcut is only sound if it produces the same bytes.

        generate() ranks the basewords once and writes every capped file as a
        prefix of basewords.txt, so truncating the cached list must give
        exactly what a cold derivation for that cap would have written.
        """
        corpus = self._corpus(tmp_path)
        # Cold cache with the cap: generate() writes the file itself.
        derived = _wordlists(self._run(main_module, tmp_path, corpus, baseword_cap=2))[
            0
        ]
        expected = open(derived, "rb").read()

        # Now force the truncation path: drop the capped file, keep the cache.
        os.remove(derived)
        with patch("hate_crack.rulegen.generate") as generate:
            truncated = _wordlists(
                self._run(main_module, tmp_path, corpus, baseword_cap=2)
            )[0]
        generate.assert_not_called()

        assert truncated == derived
        assert open(truncated, "rb").read() == expected

    def test_switching_cap_on_a_warm_cache_never_re_derives(
        self, main_module, tmp_path, capsys
    ):
        corpus = self._corpus(tmp_path)
        self._run(main_module, tmp_path, corpus, baseword_cap=2)
        capsys.readouterr()

        with patch("hate_crack.rulegen.generate") as generate:
            one = self._run(main_module, tmp_path, corpus, baseword_cap=1)
            three = self._run(main_module, tmp_path, corpus, baseword_cap=3)
            again = self._run(main_module, tmp_path, corpus, baseword_cap=2)

        generate.assert_not_called()
        assert "Deriving basewords" not in capsys.readouterr().out
        assert self._lines(_wordlists(one)[0]) == ["quibblefox"]
        assert self._lines(_wordlists(three)[0]) == [
            "quibblefox",
            "zarplewidget",
            "grumbleknob",
        ]
        assert self._lines(_wordlists(again)[0]) == ["quibblefox", "zarplewidget"]

    def test_truncation_does_not_touch_the_provenance_record(
        self, main_module, tmp_path
    ):
        """Truncating is not a derivation, so Task 5's marker must be untouched.

        The record is deleted before a derivation and rewritten after it. A
        truncation that went through either half would either break the
        validity invariant or rewrite a record it did not earn.
        """
        corpus = self._corpus(tmp_path)
        self._run(main_module, tmp_path, corpus)
        provenance = os.path.join(
            self._hash_file(tmp_path) + ".spoonman", "corpus.json"
        )
        before = open(provenance, "rb").read()
        before_mtime = os.path.getmtime(provenance)

        self._run(main_module, tmp_path, corpus, baseword_cap=2)

        assert open(provenance, "rb").read() == before
        assert os.path.getmtime(provenance) == before_mtime

    def test_a_capped_file_older_than_the_cached_list_is_rebuilt(
        self, main_module, tmp_path, capsys
    ):
        """A capped file survives a derivation it was not part of.

        generate() only writes the caps it was asked for, so a top-N file from
        an earlier corpus stays on disk when a later derivation replaces
        basewords.txt. Reusing it would crack with the wrong corpus's
        basewords -- exactly the class of bug Task 5 exists to prevent -- so
        anything older than basewords.txt is rebuilt.
        """
        corpus = self._corpus(tmp_path)
        first = self._run(main_module, tmp_path, corpus, baseword_cap=2)
        capped = _wordlists(first)[0]
        assert self._lines(capped) == ["quibblefox", "zarplewidget"]

        # A different corpus, derived without a cap: basewords.txt is replaced
        # and the stale top-2 file is left behind.
        other = tmp_path / "other.txt"
        other.write_text(
            "flimberdoodle\nFlimberdoodle\nflimberdoodle1\nwibblesprocket\n",
            encoding="latin-1",
        )
        self._run(main_module, tmp_path, str(other))
        assert os.path.isfile(capped)
        assert self._lines(capped) == ["quibblefox", "zarplewidget"]
        # Pin the ordering rather than relying on filesystem timestamp
        # resolution: the stale file is unambiguously older than the list it
        # no longer belongs to.
        full = os.path.join(os.path.dirname(capped), "basewords.txt")
        os.utime(capped, (os.path.getmtime(full) - 10,) * 2)
        capsys.readouterr()

        # Asking for the same cap again must rebuild it from the new list.
        third = self._run(main_module, tmp_path, str(other), baseword_cap=2)
        assert self._lines(_wordlists(third)[0]) == [
            "flimberdoodle",
            "wibblesprocket",
        ]

    def test_a_capped_file_stamped_the_same_as_the_list_is_rebuilt(
        self, main_module, tmp_path
    ):
        """Equality is not freshness.

        A coarse-mtime filesystem (HFS+, FAT, some NFS) cannot distinguish a
        capped file written just *before* a derivation from one written just
        after it, so reusing on equality would serve a stale prefix of a corpus
        that is no longer there -- the Task 5 bug class. Only strictly newer
        counts as current; a needless rebuild is byte-identical and cheap.
        """
        corpus = self._corpus(tmp_path)
        self._run(main_module, tmp_path, corpus)
        cache_dir = self._hash_file(tmp_path) + ".spoonman"
        full = os.path.join(cache_dir, "basewords.txt")
        capped = os.path.join(cache_dir, "basewords.top2.txt")
        assert os.path.isfile(full) and not os.path.exists(capped)
        with open(capped, "w", encoding="latin-1") as handle:
            handle.write("staleword\n")
        stamp = os.path.getmtime(full)
        os.utime(capped, (stamp, stamp))
        assert os.path.getmtime(capped) == os.path.getmtime(full)

        with patch("hate_crack.rulegen.generate") as generate:
            quick = self._run(main_module, tmp_path, corpus, baseword_cap=2)

        generate.assert_not_called()
        assert self._lines(_wordlists(quick)[0]) == ["quibblefox", "zarplewidget"]

    def test_unwritable_capped_file_falls_back_to_the_full_list(
        self, main_module, tmp_path, capsys
    ):
        """A cap is a preference; failing to write one must not fail the run."""
        corpus = self._corpus(tmp_path)
        self._run(main_module, tmp_path, corpus)
        cache_dir = self._hash_file(tmp_path) + ".spoonman"
        # A directory where the capped file wants to be: open(..., "w") raises.
        os.mkdir(os.path.join(cache_dir, "basewords.top2.txt"))
        capsys.readouterr()

        quick = self._run(main_module, tmp_path, corpus, baseword_cap=2)
        out = capsys.readouterr().out

        assert "Could not write the capped baseword list" in out
        assert "Continuing with the full derived baseword list" in out
        quick.assert_called_once()
        assert _wordlists(quick)[0].endswith("basewords.txt")

    @pytest.mark.parametrize("cap", [0, None])
    @pytest.mark.parametrize("cache", ["cold", "warm"])
    def test_zero_or_none_cap_means_no_cap(self, main_module, tmp_path, cap, cache):
        """A cap of 0 would otherwise be an empty dictionary.

        Unreachable from the menu, which maps 0 to None, but reachable by any
        other caller -- and an empty baseword file makes hashcat try nothing.
        Both cache states are covered because the cap is consulted twice, once
        per branch, and each needs its own guard.
        """
        corpus = self._corpus(tmp_path)
        if cache == "warm":
            self._run(main_module, tmp_path, corpus)

        quick = self._run(main_module, tmp_path, corpus, baseword_cap=cap)

        passed = _wordlists(quick)[0]
        assert passed.endswith("basewords.txt")
        assert self._lines(passed) == ["quibblefox", "zarplewidget", "grumbleknob"]
        # And no degenerate empty file was produced on the way.
        cache_dir = self._hash_file(tmp_path) + ".spoonman"
        assert not os.path.exists(os.path.join(cache_dir, "basewords.top0.txt"))

    def test_capped_run_writes_the_provenance_record(self, main_module, tmp_path):
        """Task 5's validity marker must survive the capped path."""
        corpus = self._corpus(tmp_path)
        self._run(main_module, tmp_path, corpus, baseword_cap=2)
        provenance = os.path.join(
            self._hash_file(tmp_path) + ".spoonman", "corpus.json"
        )
        with open(provenance, encoding="utf-8") as handle:
            recorded = json.load(handle)
        assert recorded["corpus"] == os.path.abspath(corpus)

    def test_optimized_kernel_warning_scans_the_capped_file(
        self, main_module, tmp_path, capsys
    ):
        """Task 7's warning must count the list actually being run.

        The long entry here is the *least* frequent baseword, so a cap of 1
        excludes it -- a warning that scanned basewords.txt regardless would
        report a loss that cannot happen on this run.
        """
        long_word = "wibble" * 7  # 42 characters, over the mode-0 -O cap
        corpus = self._corpus(
            tmp_path, ["quibblefox", "Quibblefox", "quibblefox1", long_word]
        )

        quick = self._run(main_module, tmp_path, corpus, baseword_cap=1)
        capped_out = capsys.readouterr().out
        assert self._lines(_wordlists(quick)[0]) == ["quibblefox"]
        assert "At least" not in capped_out

        # Control: the same corpus uncapped does warn, so the assertion above
        # is about the cap and not about the corpus.
        self._run(main_module, tmp_path, corpus)
        assert "At least 1 baseword(s)" in capsys.readouterr().out


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
        with open(_wordlists(quick)[0], encoding="latin-1") as handle:
            words = [line.rstrip("\n") for line in handle if line.strip()]
        over = [word for word in words if len(word) > 31]
        assert sorted(over) == sorted([self.LONG, self.ALSO_LONG])

        assert "At least 2 baseword(s) exceed 31 characters" in out
        assert "-O" in out
        assert "--no-optimized-kernel" in out

    def test_warning_does_not_present_the_count_as_exact(
        self, main_module, tmp_path, capsys
    ):
        """The count is a floor in two directions and must read that way.

        Spoonman runs at any hash mode -- these tests use 1000/NTLM -- and the
        real -O cap is mode-dependent, and a rule that appends characters can
        carry a baseword that fits here past the cap. An operator must not read
        the number as the total loss, nor 31 as a universal limit.
        """
        self._run(main_module, tmp_path, [self.LONG, "shortword"])
        out = capsys.readouterr().out
        assert "At least" in out
        assert "mode 0" in out
        assert "varies by hash mode" in out
        assert "appends characters" in out

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
        assert _wordlists(quick)[0].endswith("basewords.txt")

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

    def test_announces_the_scan_for_a_large_baseword_list(
        self, main_module, tmp_path, capsys, monkeypatch
    ):
        """A corpus-sized list takes long enough that silence looks like a hang."""
        path = tmp_path / "basewords.txt"
        path.write_text("shortword\n" * 1000, encoding="latin-1")
        monkeypatch.setattr(
            main_module, "SPOONMAN_BASEWORD_SCAN_NOTICE_BYTES", path.stat().st_size
        )

        main_module._warn_optimized_kernel_length_loss(str(path))
        out = capsys.readouterr().out
        assert "Scanning" in out
        assert "basewords" in out
        # Nothing was over the cap, so only the notice is printed.
        assert "At least" not in out

    def test_small_baseword_list_scans_without_announcing(
        self, main_module, tmp_path, capsys
    ):
        path = tmp_path / "basewords.txt"
        path.write_text(f"{self.LONG}\nshortword\n", encoding="latin-1")
        main_module._warn_optimized_kernel_length_loss(str(path))
        out = capsys.readouterr().out
        assert "Scanning" not in out
        assert "At least 1 baseword(s)" in out

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
        # Rule-set menu, then the baseword-source menu ("1" = derived only,
        # today's behaviour). Finite side_effect throughout this class: a
        # regression that adds or drops a menu must fail, not spin.
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", "1"]):
            attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_called_once_with(
            "1000",
            "hashes.txt",
            corpus,
            coverage=None,
            extra_wordlists=None,
            baseword_cap=None,
        )

    @pytest.mark.parametrize(
        ("choice", "expected"), [("1", 50), ("2", 75), ("3", 95), ("4", 99)]
    )
    def test_passes_capped_coverage(self, tmp_path, corpus, choice, expected):
        ctx = self._ctx(tmp_path, corpus)
        with patch("hate_crack.attacks.interactive_menu", side_effect=[choice, "1"]):
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
            # Corpus-source picker, then rule-set size, then baseword source.
            return {1: "1", 2: "5"}.get(len(menu_calls), "1")

        with patch("hate_crack.attacks.interactive_menu", side_effect=fake_menu):
            attacks.spoonman_attack(ctx)

        assert any(
            ("1", "Cracked passwords (current session)") in items
            for items in menu_calls
        )
        ctx.select_file_with_autocomplete.assert_not_called()
        ctx.hcatSpoonman.assert_called_once_with(
            "1000",
            str(hash_file),
            out_path,
            coverage=None,
            extra_wordlists=None,
            baseword_cap=None,
        )

    def test_choosing_file_option_falls_through_to_path_prompt(self, tmp_path, corpus):
        hash_file, _out_path = self._with_cracked_out(tmp_path)
        ctx = self._ctx(tmp_path, corpus, hash_file)

        calls = {"n": 0}

        def fake_menu(items, **kwargs):
            calls["n"] += 1
            return {1: "2", 2: "5"}.get(calls["n"], "1")

        with patch("hate_crack.attacks.interactive_menu", side_effect=fake_menu):
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        ctx.hcatSpoonman.assert_called_once_with(
            "1000",
            str(hash_file),
            corpus,
            coverage=None,
            extra_wordlists=None,
            baseword_cap=None,
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
        with patch(
            "hate_crack.attacks.interactive_menu", side_effect=["5", "1"]
        ) as menu:
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        # Only the rule-set-size and baseword-source menus; no corpus-source menu.
        assert menu.call_count == 2
        ctx.hcatSpoonman.assert_called_once_with(
            "1000",
            str(hash_file),
            corpus,
            coverage=None,
            extra_wordlists=None,
            baseword_cap=None,
        )

    def test_empty_out_file_counts_as_absent(self, tmp_path, corpus):
        """A zero-byte `.out` derives nothing, so it must be treated as absent."""
        hash_file = tmp_path / "hashes.txt"
        out_path = tmp_path / "hashes.txt.out"
        out_path.write_text("", encoding="latin-1")
        ctx = self._ctx(tmp_path, corpus, hash_file)

        # Finite side_effect for the same reason as the sibling guard above:
        # a regression that shows the corpus-source menu here must fail, not hang.
        with patch(
            "hate_crack.attacks.interactive_menu", side_effect=["5", "1"]
        ) as menu:
            attacks.spoonman_attack(ctx)

        ctx.select_file_with_autocomplete.assert_called_once()
        assert menu.call_count == 2
        ctx.hcatSpoonman.assert_called_once_with(
            "1000",
            str(hash_file),
            corpus,
            coverage=None,
            extra_wordlists=None,
            baseword_cap=None,
        )

    def test_invalid_selection_reprompts_the_corpus_source_menu(
        self, tmp_path, corpus, capsys
    ):
        hash_file, out_path = self._with_cracked_out(tmp_path)
        ctx = self._ctx(tmp_path, corpus, hash_file)

        calls = {"n": 0}

        def fake_menu(items, **kwargs):
            calls["n"] += 1
            return {1: "bogus", 2: "1", 3: "5"}.get(calls["n"], "1")

        with patch("hate_crack.attacks.interactive_menu", side_effect=fake_menu):
            attacks.spoonman_attack(ctx)

        assert "Invalid selection" in capsys.readouterr().out
        ctx.hcatSpoonman.assert_called_once_with(
            "1000",
            str(hash_file),
            out_path,
            coverage=None,
            extra_wordlists=None,
            baseword_cap=None,
        )


class TestSpoonmanBasewordSourceMenu:
    """Task 6c: the baseword side is the one worth choosing.

    The rule-tier menu caps the dimension that barely moves reach; this menu
    exists because 47-57% of misses were a missing baseword. Every test here
    uses a finite ``side_effect``, so a regression that adds, drops or
    reorders a menu fails instead of spinning on the invalid-selection loop.
    """

    def _ctx(self, tmp_path, corpus, main_module, wordlists=()):
        """A ctx whose wordlist listing is the real one over a real directory.

        A name ending in "/" becomes a subdirectory, which is how a wordlist
        collection actually arrives, and the listing helper is the module's own
        rather than a stub -- stubbing it is what let the files-only variant
        look correct while dropping every subdirectory.
        """
        wordlists_dir = tmp_path / "wordlists"
        wordlists_dir.mkdir(exist_ok=True)
        for name in wordlists:
            if name.endswith("/"):
                (wordlists_dir / name.rstrip("/")).mkdir()
            else:
                (wordlists_dir / name).write_text("quibblefox\n", encoding="latin-1")

        ctx = MagicMock()
        ctx.hcatWordlists = str(wordlists_dir)
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = str(tmp_path / "hashes.txt")
        ctx.select_file_with_autocomplete.return_value = corpus
        ctx.list_wordlist_entries = main_module.list_wordlist_entries
        return ctx

    def _menu_items(self, menu):
        """Every (key, label) pair the baseword-source menu offered."""
        return [items for (items,), _kwargs in menu.call_args_list][-1]

    def test_derived_only_passes_no_extras_and_no_cap(
        self, tmp_path, corpus, main_module
    ):
        ctx = self._ctx(tmp_path, corpus, main_module)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", "1"]):
            attacks.spoonman_attack(ctx)
        kwargs = ctx.hcatSpoonman.call_args.kwargs
        assert kwargs["extra_wordlists"] is None
        assert kwargs["baseword_cap"] is None

    def test_configured_wordlists_are_passed_as_absolute_paths(
        self, tmp_path, corpus, main_module
    ):
        ctx = self._ctx(
            tmp_path, corpus, main_module, wordlists=["alpha.txt", "beta.txt"]
        )
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", "2"]):
            attacks.spoonman_attack(ctx)

        assert ctx.hcatSpoonman.call_args.kwargs["extra_wordlists"] == [
            os.path.join(ctx.hcatWordlists, "alpha.txt"),
            os.path.join(ctx.hcatWordlists, "beta.txt"),
        ]
        assert ctx.hcatSpoonman.call_args.kwargs["baseword_cap"] is None

    def test_wordlist_subdirectories_are_included(self, tmp_path, corpus, main_module):
        """A wordlist collection arrives as a subdirectory, not a loose file.

        hashcat accepts a directory in the dictionary position of a straight
        attack and walks it, so filtering subdirectories out would silently
        narrow the one dimension this menu exists to widen -- an operator whose
        wordlists live in rockyou/ and weakpass/ would pick the *recommended*
        option and get almost nothing.
        """
        ctx = self._ctx(
            tmp_path,
            corpus,
            main_module,
            wordlists=["other.txt", "rockyou/", "weakpass/"],
        )
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", "2"]):
            attacks.spoonman_attack(ctx)

        passed = ctx.hcatSpoonman.call_args.kwargs["extra_wordlists"]
        assert sorted(os.path.basename(p) for p in passed) == [
            "other.txt",
            "rockyou",
            "weakpass",
        ]
        # And they really are directories, so hashcat's own walking is what
        # consumes them.
        for path in passed:
            if path.endswith(("rockyou", "weakpass")):
                assert os.path.isdir(path)

    def test_recommended_option_is_the_wordlist_one(
        self, tmp_path, corpus, main_module
    ):
        """The attack is baseword-limited, so option 2 carries the marker."""
        ctx = self._ctx(tmp_path, corpus, main_module)
        with patch(
            "hate_crack.attacks.interactive_menu", side_effect=["5", "1"]
        ) as menu:
            attacks.spoonman_attack(ctx)

        items = dict(self._menu_items(menu))
        assert "recommended" in items["2"].lower()
        assert "recommended" not in items["1"].lower()
        assert "recommended" not in items["3"].lower()

    def test_empty_wordlist_directory_says_so_and_still_attacks(
        self, tmp_path, corpus, main_module, capsys
    ):
        ctx = self._ctx(tmp_path, corpus, main_module, wordlists=[])
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", "2"]):
            attacks.spoonman_attack(ctx)

        assert "No wordlists found" in capsys.readouterr().out
        ctx.hcatSpoonman.assert_called_once()
        assert ctx.hcatSpoonman.call_args.kwargs["extra_wordlists"] == []

    def test_cap_choice_prompts_for_n_and_passes_it(
        self, tmp_path, corpus, main_module
    ):
        ctx = self._ctx(tmp_path, corpus, main_module)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["5", "3"]),
            patch("builtins.input", return_value="5000"),
        ):
            attacks.spoonman_attack(ctx)

        kwargs = ctx.hcatSpoonman.call_args.kwargs
        assert kwargs["baseword_cap"] == 5000
        assert kwargs["extra_wordlists"] is None

    def test_cap_prompt_does_not_present_the_cap_as_more_accurate(
        self, tmp_path, corpus, main_module, capsys
    ):
        """Measured: a 5,000-baseword cap reached 0.4% against 1.6% uncapped.

        So the prompt must frame it as a keyspace trade, not an improvement.
        """
        ctx = self._ctx(tmp_path, corpus, main_module)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["5", "3"]),
            patch("builtins.input", return_value="5000"),
        ):
            attacks.spoonman_attack(ctx)

        out = capsys.readouterr().out.lower()
        assert "trades reach for keyspace" in out
        assert "not to make it more accurate" in out

    @pytest.mark.parametrize("entered", ["", "0"])
    def test_blank_or_zero_cap_means_no_cap(
        self, tmp_path, corpus, main_module, capsys, entered
    ):
        ctx = self._ctx(tmp_path, corpus, main_module)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["5", "3"]),
            patch("builtins.input", return_value=entered),
        ):
            attacks.spoonman_attack(ctx)

        assert "No cap applied" in capsys.readouterr().out
        assert ctx.hcatSpoonman.call_args.kwargs["baseword_cap"] is None

    @pytest.mark.parametrize("choice", ["99", None])
    def test_backing_out_of_the_baseword_menu_attacks_nothing(
        self, tmp_path, corpus, main_module, choice
    ):
        ctx = self._ctx(tmp_path, corpus, main_module)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", choice]):
            attacks.spoonman_attack(ctx)
        ctx.hcatSpoonman.assert_not_called()

    def test_invalid_selection_reprompts(self, tmp_path, corpus, main_module, capsys):
        ctx = self._ctx(tmp_path, corpus, main_module)
        with patch(
            "hate_crack.attacks.interactive_menu", side_effect=["5", "bogus", "1"]
        ) as menu:
            attacks.spoonman_attack(ctx)

        assert "Invalid selection" in capsys.readouterr().out
        assert menu.call_count == 3
        ctx.hcatSpoonman.assert_called_once()

    def test_intro_no_longer_claims_a_capped_rule_set_gets_most_coverage(
        self, tmp_path, corpus, main_module, capsys
    ):
        """The old wording was contradicted by the measurement on new targets."""
        ctx = self._ctx(tmp_path, corpus, main_module)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["5", "1"]):
            attacks.spoonman_attack(ctx)

        out = capsys.readouterr().out
        assert "fraction of the keyspace" not in out
        assert "missing baseword" in out


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
