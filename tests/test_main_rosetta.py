"""Tests for hcatRosetta and the Rosetta Attack handler.

The attack mines hashcat --debug-mode 4 logs, so the fixtures below are
synthetic logs in that format: ``baseword rule candidate``, one per line.
"""

import os
from unittest.mock import MagicMock, patch

import pytest

from hate_crack import attacks


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

    def test_empty_log_rejected(self, main_module, tmp_path):
        empty = tmp_path / "empty.log"
        empty.write_text("", encoding="utf-8")
        with pytest.raises(ValueError, match="empty"):
            main_module.rosetta_derive([str(empty)], str(tmp_path / "out"))

    def test_unparseable_log_rejected(self, main_module, tmp_path):
        junk = tmp_path / "junk.log"
        junk.write_text("Session..........: hashcat\nRecovered........: 0/1\n")
        with pytest.raises(ValueError, match="debug-mode 4"):
            main_module.rosetta_derive([str(junk)], str(tmp_path / "out"))

    def test_max_lines_truncates_and_says_so(
        self, main_module, tmp_path, debug_log, capsys
    ):
        result = main_module.rosetta_derive(
            [debug_log], str(tmp_path / "out"), max_lines=2
        )
        assert result["entries"] == 2
        assert "Stopped at 2 debug lines" in capsys.readouterr().out

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

        monkeypatch.setattr(
            main_module, "hcatDebugLogPath", str(tmp_path), raising=False
        )
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

        monkeypatch.setattr(main_module, "hcatHashFile", hash_file, raising=False)
        monkeypatch.setattr(main_module, "hcatHashFileOrig", hash_file, raising=False)
        monkeypatch.setattr(main_module, "hcatHashType", "1000", raising=False)
        monkeypatch.setattr(main_module, "pwdump_format", False, raising=False)
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
            top_rules=100,
            top_basewords=None,
        )

    def test_all_logs_option(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        ctx.rosetta_debug_logs.return_value = [debug_log, debug_log]
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["a", "1"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args[0][2] == [debug_log, debug_log]

    def test_manual_path_option(self, tmp_path, debug_log):
        ctx = self._ctx(tmp_path, debug_log)
        with (
            patch("hate_crack.attacks.interactive_menu", side_effect=["p", "1"]),
            patch("builtins.input", side_effect=["", ""]),
        ):
            attacks.rosetta_attack(ctx)
        assert ctx.hcatRosetta.call_args[0][2] == [debug_log]

    def test_manual_path_that_does_not_exist_aborts(self, tmp_path, debug_log, capsys):
        ctx = self._ctx(tmp_path, debug_log)
        ctx.select_file_with_autocomplete.return_value = str(tmp_path / "missing.log")
        with patch("hate_crack.attacks.interactive_menu", side_effect=["p"]):
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
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", choice]),
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
        with patch("hate_crack.attacks.interactive_menu", side_effect=[choice]):
            attacks.rosetta_attack(ctx)
        ctx.hcatRosetta.assert_not_called()

    @pytest.mark.parametrize("choice", ["99", None])
    def test_back_out_of_metric_menu(self, tmp_path, debug_log, choice):
        ctx = self._ctx(tmp_path, debug_log)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["1", choice]):
            attacks.rosetta_attack(ctx)
        ctx.hcatRosetta.assert_not_called()

    def test_out_of_range_log_selection_aborts(self, tmp_path, debug_log, capsys):
        ctx = self._ctx(tmp_path, debug_log)
        with patch("hate_crack.attacks.interactive_menu", side_effect=["7"]):
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
