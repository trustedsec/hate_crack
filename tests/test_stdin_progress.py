"""Piped (stdin-mode) hashcat runs get --stdin-count / --stdin-timeout-flush.

The hashcat command is captured at ``_run_hcat_cmd``; ``hashcat --help`` is
faked through ``help_mentions`` and no real binary is ever run.
"""

import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def mm(hc_module):
    return hc_module._main


def _probe(supported):
    """Fake help_mentions: True for flags in *supported* (regex source text)."""

    def fake(_bin, pattern):
        return any(flag in pattern for flag in supported)

    return fake


V8 = ("--stdin-count", "--stdin-timeout-flush")
V8_NO_FLUSH = ("--stdin-count",)
V7 = ()


def _run(mm, tmp_path, supported, call):
    """Run *call(hash_file)* with everything faked; return the hashcat cmd."""
    hash_file = str(tmp_path / "hashes.txt")
    captured = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = list(cmd)
        captured["kwargs"] = kwargs

    proc = MagicMock()
    with (
        patch.object(mm, "hate_path", str(tmp_path)),
        patch.object(mm, "hcatBin", "hashcat"),
        patch.object(mm, "hcatTuning", ""),
        patch.object(mm, "hcatPotfilePath", ""),
        patch.object(mm, "generate_session_id", return_value="sess"),
        patch.object(mm, "lineCount", wraps=mm.lineCount),
        patch.object(mm, "_run_hcat_cmd", side_effect=fake_run),
        patch.object(mm, "_add_debug_mode_for_rules", side_effect=lambda c: c),
        patch.object(mm._hashcat_paths, "help_mentions", _probe(supported)),
        patch("hate_crack.main.subprocess.Popen", return_value=proc),
    ):
        call(hash_file)
    return captured["cmd"]


def _flags(cmd):
    return {
        "count": cmd[cmd.index("--stdin-count") + 1]
        if "--stdin-count" in cmd
        else None,
        "flush": cmd[cmd.index("--stdin-timeout-flush") + 1]
        if "--stdin-timeout-flush" in cmd
        else None,
    }


class TestHelper:
    def test_all_supported(self, mm):
        with patch.object(mm._hashcat_paths, "help_mentions", _probe(V8)):
            assert mm._stdin_progress_flags("hc", 5) == [
                "--stdin-count",
                "5",
                "--stdin-timeout-flush",
                "10",
            ]

    def test_no_count_only_flush(self, mm):
        with patch.object(mm._hashcat_paths, "help_mentions", _probe(V8)):
            assert mm._stdin_progress_flags("hc") == ["--stdin-timeout-flush", "10"]

    def test_flush_absent_when_probe_false(self, mm):
        with patch.object(mm._hashcat_paths, "help_mentions", _probe(V8_NO_FLUSH)):
            assert mm._stdin_progress_flags("hc", 7) == ["--stdin-count", "7"]

    def test_nothing_on_seven(self, mm):
        with patch.object(mm._hashcat_paths, "help_mentions", _probe(V7)):
            assert mm._stdin_progress_flags("hc", 7) == []

    def test_zero_or_none_count_omitted(self, mm):
        with patch.object(mm._hashcat_paths, "help_mentions", _probe(V8)):
            assert "--stdin-count" not in mm._stdin_progress_flags("hc", 0)
            assert "--stdin-count" not in mm._stdin_progress_flags("hc", None)


class TestCombinators:
    def _lists(self, tmp_path):
        a = tmp_path / "a.txt"
        b = tmp_path / "b.txt"
        c = tmp_path / "c.txt"
        a.write_text("x\ny\n")
        b.write_text("1\n2\n3\n")
        c.write_text("p\nq\nr\ns")  # unterminated last line still counts
        return [str(a), str(b), str(c)]

    def test_combinator3_exact_product(self, mm, tmp_path):
        lists = self._lists(tmp_path)
        cmd = _run(mm, tmp_path, V8, lambda h: mm.hcatCombinator3("0", h, lists))
        assert _flags(cmd) == {"count": "24", "flush": "10"}

    def test_combinatorx_exact_product(self, mm, tmp_path):
        lists = self._lists(tmp_path)[:2]
        cmd = _run(mm, tmp_path, V8, lambda h: mm.hcatCombinatorX("0", h, lists))
        assert _flags(cmd) == {"count": "6", "flush": "10"}

    def test_empty_list_omits_count(self, mm, tmp_path):
        lists = self._lists(tmp_path)
        (tmp_path / "b.txt").write_text("")
        cmd = _run(mm, tmp_path, V8, lambda h: mm.hcatCombinator3("0", h, lists))
        assert _flags(cmd) == {"count": None, "flush": "10"}

    def test_absent_on_seven(self, mm, tmp_path):
        lists = self._lists(tmp_path)
        cmd = _run(mm, tmp_path, V7, lambda h: mm.hcatCombinator3("0", h, lists))
        assert _flags(cmd) == {"count": None, "flush": None}


class TestCombipow:
    def test_count_formula(self, mm, tmp_path):
        wl = tmp_path / "w.txt"
        wl.write_text("a\nb\n\nc\nd\n")  # 4 non-empty lines -> 15
        cmd = _run(mm, tmp_path, V8, lambda h: mm.hcatCombipow("0", h, str(wl)))
        assert _flags(cmd) == {"count": "15", "flush": "10"}

    def test_over_63_lines_omits_count(self, mm, tmp_path):
        wl = tmp_path / "w.txt"
        wl.write_text("".join(f"w{i}\n" for i in range(64)))
        assert mm._combipow_count(str(wl)) is None

    def test_long_line_omits_count(self, mm, tmp_path):
        wl = tmp_path / "w.txt"
        wl.write_text("a" * 80 + "\nb\n")
        assert mm._combipow_count(str(wl)) is None

    def test_absent_on_seven(self, mm, tmp_path):
        wl = tmp_path / "w.txt"
        wl.write_text("a\nb\n")
        cmd = _run(mm, tmp_path, V7, lambda h: mm.hcatCombipow("0", h, str(wl)))
        assert "--stdin-count" not in cmd and "--stdin-timeout-flush" not in cmd

    @pytest.mark.skipif(
        not os.path.isfile(
            os.path.join(
                os.path.dirname(__file__), "..", "hashcat-utils", "bin", "combipow.bin"
            )
        ),
        reason="combipow.bin not built",
    )
    def test_formula_matches_real_binary(self, mm, tmp_path):
        import subprocess

        wl = tmp_path / "w.txt"
        wl.write_text("a\nb\n\nc\nd\ne")
        binary = os.path.join(
            os.path.dirname(__file__), "..", "hashcat-utils", "bin", "combipow.bin"
        )
        out = subprocess.run([binary, str(wl)], capture_output=True, check=True)
        assert len(out.stdout.splitlines()) == mm._combipow_count(str(wl))


class TestFlushOnly:
    def test_ngram(self, mm, tmp_path):
        corpus = tmp_path / "c.txt"
        corpus.write_text("a b c\n")
        cmd = _run(mm, tmp_path, V8, lambda h: mm.hcatNgramX("0", h, str(corpus), 3))
        assert _flags(cmd) == {"count": None, "flush": "10"}

    def test_permute(self, mm, tmp_path):
        (tmp_path / "hashcat-utils" / "bin").mkdir(parents=True)
        (tmp_path / "hashcat-utils" / "bin" / "permute.bin").touch()
        wl = tmp_path / "w.txt"
        wl.write_text("abc\n")
        cmd = _run(mm, tmp_path, V8, lambda h: mm.hcatPermute("0", h, str(wl)))
        assert _flags(cmd) == {"count": None, "flush": "10"}

    def test_permute_absent_on_seven(self, mm, tmp_path):
        (tmp_path / "hashcat-utils" / "bin").mkdir(parents=True)
        (tmp_path / "hashcat-utils" / "bin" / "permute.bin").touch()
        wl = tmp_path / "w.txt"
        wl.write_text("abc\n")
        cmd = _run(mm, tmp_path, V7, lambda h: mm.hcatPermute("0", h, str(wl)))
        assert "--stdin-timeout-flush" not in cmd

    def test_prince(self, mm, tmp_path):
        base = tmp_path / "base.txt"
        base.write_text("password\n")
        (tmp_path / "princeprocessor").mkdir()

        def call(h):
            with (
                patch.object(mm, "hcatPrinceBin", "pp64.bin"),
                patch.object(mm, "hcatPrinceBaseList", [str(base)]),
                patch.object(mm, "get_rule_path", return_value="/fake.rule"),
            ):
                mm.hcatPrince("0", h)

        cmd = _run(mm, tmp_path, V8, call)
        assert _flags(cmd) == {"count": None, "flush": "10"}


class TestUpperBounds:
    def test_pcfg_legacy_uses_max_candidates(self, mm, tmp_path):
        script = tmp_path / "pcfg_cracker" / "pcfg_guesser.py"
        (tmp_path / "pcfg_cracker" / "Rules" / "Default").mkdir(parents=True)
        script.write_text("")

        def call(h):
            with (
                patch.object(mm, "pcfgRuleset", "Default"),
                patch.object(mm, "pcfgMaxCandidates", 1234),
            ):
                mm.hcatPCFG("0", h)

        cmd = _run(mm, tmp_path, V8, call)
        assert _flags(cmd) == {"count": "1234", "flush": "10"}

    def test_omen_uses_max_candidates(self, mm, tmp_path):
        omen = tmp_path / "omen"
        omen.mkdir()
        (omen / "enumNG").touch()
        model = tmp_path / "model"
        model.mkdir()
        (model / "createConfig").write_text("x")

        def call(h):
            with (
                patch.object(mm, "_omen_dir", str(omen)),
                patch.object(mm, "hcatOmenEnumBin", "enumNG"),
                patch.object(mm, "_omen_model_dir", return_value=str(model)),
            ):
                mm.hcatOmen("0", h, 5000)

        cmd = _run(mm, tmp_path, V8, call)
        assert _flags(cmd) == {"count": "5000", "flush": "10"}

    def test_omen_absent_on_seven(self, mm, tmp_path):
        omen = tmp_path / "omen"
        omen.mkdir()
        (omen / "enumNG").touch()
        model = tmp_path / "model"
        model.mkdir()
        (model / "createConfig").write_text("x")

        def call(h):
            with (
                patch.object(mm, "_omen_dir", str(omen)),
                patch.object(mm, "hcatOmenEnumBin", "enumNG"),
                patch.object(mm, "_omen_model_dir", return_value=str(model)),
            ):
                mm.hcatOmen("0", h, 5000)

        cmd = _run(mm, tmp_path, V7, call)
        assert "--stdin-count" not in cmd
