"""Tests for hcatRosetta and the Rosetta Attack handler.

The attack mines hashcat debug logs. hate_crack writes mode 5
(``baseword:rule:candidate:wordlist``); mode 4 logs written before that switch
are still readable, and the space-separated fixtures below exercise that path.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import attacks
from hate_crack import main as _hate_crack_main


def _rosetta_unavailable_reason():
    """Return why HashcatRosetta is unusable, or None when it imported fine.

    Reported once for the whole module rather than as a wall of unrelated
    assertion failures in every test that needs the analyzer (#231).
    """
    if _hate_crack_main.DebugAnalyzer is not None:
        return None
    package_dir = os.path.join(_hate_crack_main.ROSETTA_DIR, "hashcat_rosetta")
    if not os.path.isdir(package_dir):
        return (
            "HashcatRosetta submodule is not checked out "
            f"({package_dir} does not exist). "
            "Run: git submodule update --init HashcatRosetta"
        )
    # Checked out but still not importable: a real breakage, not a bare
    # worktree. Skipping this would hide it in CI, so fail loudly instead.
    raise AssertionError(
        "HashcatRosetta is checked out at "
        f"{_hate_crack_main.ROSETTA_DIR} but failed to import: "
        f"{_hate_crack_main.ROSETTA_IMPORT_ERROR!r}"
    )


_ROSETTA_SKIP_REASON = _rosetta_unavailable_reason()
if _ROSETTA_SKIP_REASON is not None:
    pytest.skip(_ROSETTA_SKIP_REASON, allow_module_level=True)


@pytest.fixture(autouse=True, scope="module")
def _require_rosetta():
    """Catch a HashcatRosetta that went away after this module was imported."""
    reason = _rosetta_unavailable_reason()
    if reason is not None:
        pytest.skip(reason)


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


DEBUG_LOG = "\n".join(
    [
        "alpha $1 alpha1",
        "alpha c Alpha",
        "alpha u ALPHA",
        "bravo $1 bravo1",
        "bravo c Bravo",
        "charlie $1 charlie1",
        "delta ] delt",
    ]
)


@pytest.fixture
def debug_log(tmp_path):
    path = tmp_path / "hashcat_debug.log"
    path.write_text(DEBUG_LOG + "\n", encoding="utf-8")
    return str(path)


def _read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read().splitlines()


class TestRosettaDerive:
    def test_extracts_basewords_and_rules(self, main_module, tmp_path, debug_log):
        out = str(tmp_path / "out")
        result = main_module.rosetta_derive([debug_log], out)

        assert sorted(_read(result["basewords"])) == [
            "alpha",
            "bravo",
            "charlie",
            "delta",
        ]
        assert sorted(_read(result["rules"])) == ["$1", "]", "c", "u"]
        assert result["baseword_count"] == 4
        assert result["rule_count"] == 4
        assert result["entries"] == 7

    def test_frequency_metric_orders_most_applied_first(
        self, main_module, tmp_path, debug_log
    ):
        result = main_module.rosetta_derive(
            [debug_log], str(tmp_path / "out"), top_rules=1
        )
        assert _read(result["rules"]) == ["$1"]
        assert result["rule_count"] == 1
        assert result["total_rules"] == 4

    def test_baseword_cap_keeps_most_frequent(self, main_module, tmp_path, debug_log):
        result = main_module.rosetta_derive(
            [debug_log], str(tmp_path / "out"), top_basewords=1
        )
        assert _read(result["basewords"]) == ["alpha"]
        assert result["total_basewords"] == 4

    @pytest.mark.parametrize("metric", ["frequency", "basewords", "candidates"])
    def test_every_advertised_metric_works(
        self, main_module, tmp_path, debug_log, metric
    ):
        result = main_module.rosetta_derive(
            [debug_log], str(tmp_path / metric), metric=metric, top_rules=2
        )
        assert result["rule_count"] == 2

    def test_unknown_metric_rejected(self, main_module, tmp_path, debug_log):
        with pytest.raises(ValueError, match="unknown rule metric"):
            main_module.rosetta_derive(
                [debug_log], str(tmp_path / "out"), metric="nonsense"
            )

    def test_merges_multiple_logs(self, main_module, tmp_path, debug_log):
        second = tmp_path / "other.log"
        second.write_text("echo $9 echo9\n", encoding="utf-8")
        result = main_module.rosetta_derive(
            [debug_log, str(second)], str(tmp_path / "out")
        )
        assert "echo" in _read(result["basewords"])
        assert "$9" in _read(result["rules"])

    def test_merges_mixed_debug_mode_logs(self, main_module, tmp_path):
        """A mode-4 colon log and a mode-5 colon log in the same batch must
        each keep their own format detection (regression: merging their raw
        lines before parsing let one file's sample decide the mode for both,
        logging the other file's lines as malformed and dropping them)."""
        mode_four = tmp_path / "mode4.log"
        mode_four.write_text(
            "Moldmastersmmkr:r i45 i52 r:Moldmasters25mmkr\n", encoding="utf-8"
        )
        mode_five = tmp_path / "mode5.log"
        mode_five.write_text("password:c:Password:rockyou.txt\n", encoding="utf-8")

        result = main_module.rosetta_derive(
            [str(mode_four), str(mode_five)], str(tmp_path / "out")
        )

        assert result["entries"] == 2
        assert "Moldmastersmmkr" in _read(result["basewords"])
        assert "password" in _read(result["basewords"])

    def test_empty_log_rejected(self, main_module, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="empty"):
            main_module.rosetta_derive([str(empty)], str(tmp_path / "out"))

    def test_unparseable_log_rejected(self, main_module, tmp_path):
        junk = tmp_path / "junk.log"
        junk.write_text("Session..........: hashcat\nRecovered........: 0/1\n")
        with pytest.raises(ValueError, match="hashcat debug entries"):
            main_module.rosetta_derive([str(junk)], str(tmp_path / "out"))

    def test_reads_logs_without_a_line_cap(self, main_module, tmp_path, capsys):
        big = tmp_path / "big.log"
        big.write_text("echo $9 echo9\n" * 5000, encoding="utf-8")
        result = main_module.rosetta_derive([str(big)], str(tmp_path / "out"))
        assert result["entries"] == 5000
        assert "Stopped at" not in capsys.readouterr().out

    def test_missing_rosetta_dependency_reports_clearly(
        self, main_module, tmp_path, debug_log, monkeypatch
    ):
        monkeypatch.setattr(main_module, "DebugAnalyzer", None, raising=False)
        with pytest.raises(RuntimeError, match="submodule update"):
            main_module.rosetta_derive([debug_log], str(tmp_path / "out"))


class TestRosettaDebugLogs:
    def test_lists_newest_first(self, main_module, tmp_path, monkeypatch):
        older = tmp_path / "old.log"
        newer = tmp_path / "new.log"
        older.write_text("a\n")
        newer.write_text("b\n")
        os.utime(older, (1_600_000_000, 1_600_000_000))
        os.utime(newer, (1_700_000_000, 1_700_000_000))
        (tmp_path / "subdir").mkdir()

        monkeypatch.setattr(main_module, "hcatDebugLogPath", str(tmp_path))
        assert main_module.rosetta_debug_logs() == [str(newer), str(older)]

    def test_missing_directory_is_not_an_error(self, main_module, tmp_path):
        assert main_module.rosetta_debug_logs(str(tmp_path / "nope")) == []

    def test_skips_empty_logs(self, main_module, tmp_path):
        # hashcat opens the debug file up front but only writes on a crack, so an
        # attack that cracks nothing leaves a zero-byte log with nothing to mine.
        empty = tmp_path / "empty.log"
        empty.touch()
        populated = tmp_path / "populated.log"
        populated.write_text("word:rule:candidate\n")

        assert main_module.rosetta_debug_logs(str(tmp_path)) == [str(populated)]

    def test_all_empty_reads_as_no_logs(self, main_module, tmp_path):
        (tmp_path / "a.log").touch()
        (tmp_path / "b.log").touch()

        assert main_module.rosetta_debug_logs(str(tmp_path)) == []


class TestHcatRosetta:
    def _run(self, main_module, tmp_path, debug_files, **kwargs):
        with patch.object(main_module, "hcatQuickDictionary") as quick:
            main_module.hcatRosetta(
                "1000", str(tmp_path / "hashes.txt"), debug_files, **kwargs
            )
        return quick

    def test_delegates_to_quick_dictionary(self, main_module, tmp_path, debug_log):
        quick = self._run(main_module, tmp_path, [debug_log])

        quick.assert_called_once()
        args, kwargs = quick.call_args
        assert args[0] == "1000"
        assert args[1] == str(tmp_path / "hashes.txt")
        assert args[2].startswith("-r ")
        assert args[2].endswith("rules.rule")
        assert args[3].endswith("basewords.txt")
        assert kwargs["attack_name"] == "Rosetta"
        assert os.path.isfile(args[3])

    def test_output_lives_beside_the_hash_file(self, main_module, tmp_path, debug_log):
        quick = self._run(main_module, tmp_path, [debug_log])
        expected = str(tmp_path / "hashes.txt") + ".rosetta"
        assert os.path.dirname(quick.call_args[0][3]) == expected
        assert os.path.isdir(expected)

    def test_cleanup_removes_derived_output(
        self, main_module, tmp_path, debug_log, monkeypatch
    ):
        hash_file = str(tmp_path / "hashes.txt")
        self._run(main_module, tmp_path, [debug_log])
        assert os.path.isdir(hash_file + ".rosetta")

        monkeypatch.setattr(main_module, "hcatHashFile", hash_file)
        monkeypatch.setattr(main_module, "hcatHashFileOrig", hash_file)
        monkeypatch.setattr(main_module, "hcatHashType", "1000")
        monkeypatch.setattr(main_module, "pwdump_format", False)
        main_module.cleanup()
        assert not os.path.exists(hash_file + ".rosetta")

    def test_no_logs_reports_and_does_not_run_hashcat(
        self, main_module, tmp_path, capsys
    ):
        quick = self._run(main_module, tmp_path, [])
        quick.assert_not_called()
        assert "no debug logs selected" in capsys.readouterr().out

    def test_missing_log_reports_and_does_not_run_hashcat(
        self, main_module, tmp_path, capsys
    ):
        quick = self._run(main_module, tmp_path, [str(tmp_path / "gone.log")])
        quick.assert_not_called()
        assert "debug log not found" in capsys.readouterr().out

    def test_derivation_failure_does_not_run_hashcat(
        self, main_module, tmp_path, capsys
    ):
        junk = tmp_path / "junk.log"
        junk.write_text("Recovered........: 0/1\n")
        quick = self._run(main_module, tmp_path, [str(junk)])
        quick.assert_not_called()
        assert "Rosetta derivation failed" in capsys.readouterr().out

    def test_reports_the_cross_product_keyspace(
        self, main_module, tmp_path, debug_log, capsys
    ):
        self._run(main_module, tmp_path, [debug_log])
        # 4 basewords x 4 rules, not the 7 pairs the log recorded.
        assert "16 candidates" in capsys.readouterr().out


class TestRosettaAttackHandler:
    def _ctx(self, tmp_path, debug_log):
        ctx = MagicMock()
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "hashes.txt"
        ctx.hcatDebugLogPath = str(tmp_path)
        ctx.rosetta_debug_logs.return_value = [debug_log]
        ctx.select_file_with_autocomplete.return_value = debug_log
        return ctx

    def test_selects_a_listed_log_and_passes_defaults(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "1"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)

        ctx.hcatRosetta.assert_called_once_with(
            "1000",
            "hashes.txt",
            [debug_log],
            metric="frequency",
            top_rules=None,
            top_basewords=None,
        )

    def test_all_logs_option(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        ctx.rosetta_debug_logs.return_value = [debug_log, debug_log]
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "a"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args[0][2] == [debug_log, debug_log]

    def test_manual_path_option(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "p"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args[0][2] == [debug_log]

    def test_manual_path_that_does_not_exist_aborts(self, tmp_path, debug_log, capsys):
        ctx = self._ctx(tmp_path, debug_log)
        ctx.select_file_with_autocomplete.return_value = str(tmp_path / "missing.log")
        with patch("hate_crack.attacks.interactive_menu", side_effect=["1", "p"]):
            attacks.rosetta_attack(ctx)
        ctx.hcatRosetta.assert_not_called()
        assert "Debug log not found" in capsys.readouterr().out

    def test_log_rotated_away_before_stat_still_lists(self, tmp_path, debug_log):
        """A vanished log must not blow up the menu it is being listed in."""
        ctx = self._ctx(tmp_path, debug_log)
        ctx.rosetta_debug_logs.return_value = [str(tmp_path / "vanished.log")]
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "1"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args[0][2] == [str(tmp_path / "vanished.log")]

    @pytest.mark.parametrize(
        ("choice", "expected"),
        [("1", "frequency"), ("2", "basewords"), ("3", "candidates")],
    )
    def test_metric_choices(self, tmp_path, debug_log, choice, expected):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=[choice, "1"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args.kwargs["metric"] == expected

    def test_zero_means_unlimited(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "1"]),
            patch("builtins.input", side_effect=["0", "0"]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args.kwargs["top_rules"] is None
        assert ctx.hcatRosetta.call_args.kwargs["top_basewords"] is None

    def test_explicit_caps_are_passed_through(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "1"]),
            patch("builtins.input", side_effect=["25", "500"]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args.kwargs["top_rules"] == 25
        assert ctx.hcatRosetta.call_args.kwargs["top_basewords"] == 500

    def test_non_numeric_cap_reprompts(self, tmp_path, debug_log, capsys):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "1"]),
            patch("builtins.input", side_effect=["abc", "-3", "10", ""]),
        ):
            attacks.rosetta_attack(ctx)
        out = capsys.readouterr().out
        assert "Enter a number" in out
        assert "positive number" in out
        assert ctx.hcatRosetta.call_args.kwargs["top_rules"] == 10

    @pytest.mark.parametrize("choice", ["99", None])
    def test_back_out_of_log_menu(self, tmp_path, debug_log, choice):
        ctx = self._ctx(tmp_path, debug_log)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["1", choice]):
            attacks.rosetta_attack(ctx)
        ctx.hcatRosetta.assert_not_called()

    @pytest.mark.parametrize("choice", ["99", None])
    def test_back_out_of_metric_menu(self, tmp_path, debug_log, choice):
        ctx = self._ctx(tmp_path, debug_log)
        with patch("hate_crack.attacks.interactive_menu", side_effect=[choice]):
            attacks.rosetta_attack(ctx)
        ctx.hcatRosetta.assert_not_called()

    def test_out_of_range_log_selection_aborts(self, tmp_path, debug_log, capsys):
        ctx = self._ctx(tmp_path, debug_log)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["1", "7"]):
            attacks.rosetta_attack(ctx)
        ctx.hcatRosetta.assert_not_called()
        assert "Invalid selection" in capsys.readouterr().out


class TestRosettaMenuWiring:
    def test_registered_in_both_menu_maps(self, hc_module):
        assert hc_module.get_main_menu_options()["23"] is not None
        assert hc_module._main.get_main_menu_options()["23"] is not None

    def test_listed_in_the_menu_display(self, hc_module):
        labels = dict(hc_module._main.get_main_menu_items())
        assert labels["23"] == "Rosetta Attack"


class TestDebugModeFive:
    """hate_crack writes --debug-mode 5; HashcatRosetta parses it natively.

    The sample lines here are verbatim hashcat output, captured by cracking a
    known md5 with a one-rule file under --debug-mode 4 and 5 in turn.
    """

    MODE_5 = "orangecrate:$1 $2:orangecrate12:wl.txt"
    MODE_4 = "orangecrate:$1 $2:orangecrate12"

    def test_writer_requests_mode_5(self, main_module, tmp_path, monkeypatch):
        monkeypatch.setattr(main_module, "hcatDebugLogPath", str(tmp_path))
        monkeypatch.setattr(main_module, "_debug_mode_level", 5)
        cmd = main_module._add_debug_mode_for_rules(["hashcat", "-r", "best64.rule"])

        assert cmd[cmd.index("--debug-mode") + 1] == "5"

    def test_disabled_via_rule_debug_mode_flag_adds_nothing(
        self, main_module, tmp_path, monkeypatch
    ):
        monkeypatch.setattr(main_module, "hcatDebugLogPath", str(tmp_path))
        monkeypatch.setattr(main_module, "_rule_debug_mode_enabled", False)
        cmd = main_module._add_debug_mode_for_rules(["hashcat", "-r", "best64.rule"])

        assert "--debug-mode" not in cmd
        assert "--debug-file" not in cmd

    def test_writer_honors_a_prior_fallback_to_mode_4(
        self, main_module, tmp_path, monkeypatch
    ):
        # _run_hcat_cmd drops the module-level level to 4 once it observes
        # hashcat reject mode 5; every later rule-based attack in the
        # process must request 4 directly rather than failing again first.
        monkeypatch.setattr(main_module, "hcatDebugLogPath", str(tmp_path))
        monkeypatch.setattr(main_module, "_debug_mode_level", 4)
        cmd = main_module._add_debug_mode_for_rules(["hashcat", "-r", "best64.rule"])

        assert cmd[cmd.index("--debug-mode") + 1] == "4"

    def test_wordlist_field_is_parsed_not_glued_to_the_candidate(self, main_module):
        # HashcatRosetta < 0.3.0 split on the first two colons only, so the
        # wordlist silently became part of the candidate. Pins the submodule
        # bump: an accidental downgrade fails here rather than quietly
        # corrupting the unique-candidate metric.
        entry = main_module.DebugAnalyzer().parser.parse_debug_lines([self.MODE_5])[0]

        assert entry["candidate"] == "orangecrate12"
        assert entry["wordlist"] == "wl.txt"

    def test_mode_4_logs_still_parse(self, main_module):
        entry = main_module.DebugAnalyzer().parser.parse_debug_lines([self.MODE_4])[0]

        assert entry["candidate"] == "orangecrate12"
        assert entry["baseword"] == "orangecrate"

    def test_candidate_survives_the_round_trip(self, main_module, tmp_path):
        log = tmp_path / "mode5.log"
        log.write_text(
            "\n".join(
                [
                    "orangecrate:$1 $2:orangecrate12:wl.txt",
                    "orangecrate:c:Orangecrate:wl.txt",
                    "bluecrate:$1 $2:bluecrate12:wl.txt",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        result = main_module.rosetta_derive([str(log)], str(tmp_path / "out"))

        assert "orangecrate" in _read(result["basewords"])
        assert "wl.txt" not in _read(result["rules"])
        assert "wl.txt" not in _read(result["basewords"])

    def test_unique_candidate_metric_is_not_inflated_across_wordlists(
        self, main_module, tmp_path
    ):
        # The same rule reaching the same candidate from two wordlists is one
        # unique candidate, not two.
        log = tmp_path / "two_lists.log"
        log.write_text(
            "orangecrate:$1 $2:orangecrate12:a.txt\n"
            "orangecrate:$1 $2:orangecrate12:b.txt\n",
            encoding="utf-8",
        )
        analyzer = main_module.DebugAnalyzer()
        analyzer.analyze_debug_lines(log.read_text(encoding="utf-8").splitlines())

        assert analyzer.get_top_rules_by_unique_candidates(1) == [("$1 $2", 1)]

    def test_mixed_mode_logs_are_read_together(self, main_module, tmp_path):
        mode5 = tmp_path / "new.log"
        mode5.write_text("alpha:$1:alpha1:wl.txt\n" * 3, encoding="utf-8")
        mode4 = tmp_path / "old.log"
        mode4.write_text("bravo:$1:bravo1\n" * 3, encoding="utf-8")

        result = main_module.rosetta_derive(
            [str(mode5), str(mode4)], str(tmp_path / "out")
        )

        basewords = _read(result["basewords"])
        assert "alpha" in basewords and "bravo" in basewords
        assert "wl.txt" not in basewords
