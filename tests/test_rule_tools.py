import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hate_crack.attacks import (
    rule_cleanup_and_optimize_handler,
    rule_cleanup_handler,
    rule_optimize_handler,
    rule_tools_submenu,
)


def _make_ctx():
    ctx = MagicMock()
    ctx.rules_cleanup.return_value = True
    ctx.rules_optimize.return_value = True
    ctx.rulesDirectory = "/tmp/rules"
    return ctx


class TestRuleCleanupHandler:
    def test_calls_rules_cleanup_with_correct_paths(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\nu\n")
        outfile = tmp_path / "clean.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_handler(ctx)
        ctx.rules_cleanup.assert_called_once_with(str(infile), str(outfile))

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        with patch("builtins.input", return_value="/nonexistent.rule"):
            rule_cleanup_handler(ctx)
        ctx.rules_cleanup.assert_not_called()

    def test_rejects_empty_outfile(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        with patch("builtins.input", side_effect=[str(infile), ""]):
            rule_cleanup_handler(ctx)
        ctx.rules_cleanup.assert_not_called()

    def test_prints_done_on_success(self, tmp_path, capsys):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "clean.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_handler(ctx)
        assert "[+] Done." in capsys.readouterr().out

    def test_prints_failure_on_error(self, tmp_path, capsys):
        ctx = _make_ctx()
        ctx.rules_cleanup.return_value = False
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "clean.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_handler(ctx)
        assert "[!] Cleanup failed." in capsys.readouterr().out


class TestRuleOptimizeHandler:
    def test_calls_rules_optimize_with_correct_paths(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\nu\n")
        outfile = tmp_path / "optimized.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_optimize_handler(ctx)
        ctx.rules_optimize.assert_called_once_with(str(infile), str(outfile))

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        with patch("builtins.input", return_value="/nonexistent.rule"):
            rule_optimize_handler(ctx)
        ctx.rules_optimize.assert_not_called()

    def test_rejects_empty_outfile(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        with patch("builtins.input", side_effect=[str(infile), ""]):
            rule_optimize_handler(ctx)
        ctx.rules_optimize.assert_not_called()

    def test_prints_done_on_success(self, tmp_path, capsys):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "optimized.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_optimize_handler(ctx)
        assert "[+] Done." in capsys.readouterr().out

    def test_prints_failure_on_error(self, tmp_path, capsys):
        ctx = _make_ctx()
        ctx.rules_optimize.return_value = False
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "optimized.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_optimize_handler(ctx)
        assert "[!] Optimize failed." in capsys.readouterr().out


class TestRuleCleanupAndOptimize:
    def test_calls_cleanup_then_optimize(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\nu\n")
        outfile = tmp_path / "final.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_and_optimize_handler(ctx)
        ctx.rules_cleanup.assert_called_once()
        ctx.rules_optimize.assert_called_once()

    def test_stops_if_cleanup_fails(self, tmp_path):
        ctx = _make_ctx()
        ctx.rules_cleanup.return_value = False
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "out.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_and_optimize_handler(ctx)
        ctx.rules_optimize.assert_not_called()

    def test_rejects_nonexistent_infile(self, tmp_path):
        ctx = _make_ctx()
        with patch("builtins.input", return_value="/nonexistent.rule"):
            rule_cleanup_and_optimize_handler(ctx)
        ctx.rules_cleanup.assert_not_called()

    def test_rejects_empty_outfile(self, tmp_path):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        with patch("builtins.input", side_effect=[str(infile), ""]):
            rule_cleanup_and_optimize_handler(ctx)
        ctx.rules_cleanup.assert_not_called()

    def test_temp_file_cleaned_up_on_success(self, tmp_path):
        ctx = _make_ctx()
        captured_tmp = []

        def capture_cleanup(infile, tmpfile):
            captured_tmp.append(tmpfile)
            return True

        ctx.rules_cleanup.side_effect = capture_cleanup
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "final.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_and_optimize_handler(ctx)
        assert captured_tmp, "rules_cleanup should have been called"
        assert not os.path.exists(captured_tmp[0]), "temp file should be cleaned up"

    def test_temp_file_cleaned_up_on_cleanup_failure(self, tmp_path):
        ctx = _make_ctx()
        captured_tmp = []

        def capture_cleanup(infile, tmpfile):
            captured_tmp.append(tmpfile)
            return False

        ctx.rules_cleanup.side_effect = capture_cleanup
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "out.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_and_optimize_handler(ctx)
        if captured_tmp:
            assert not os.path.exists(captured_tmp[0]), "temp file should be cleaned up"

    def test_prints_done_on_full_success(self, tmp_path, capsys):
        ctx = _make_ctx()
        infile = tmp_path / "test.rule"
        infile.write_text("l\n")
        outfile = tmp_path / "final.rule"
        with patch("builtins.input", side_effect=[str(infile), str(outfile)]):
            rule_cleanup_and_optimize_handler(ctx)
        assert "[+] Done." in capsys.readouterr().out


class TestRuleToolsSubmenu:
    def test_dispatches_to_cleanup(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.rule_cleanup_handler") as mock_fn,
            patch(
                "hate_crack.menu.interactive_menu", side_effect=["1", "99"]
            ),
        ):
            rule_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_dispatches_to_optimize(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.rule_optimize_handler") as mock_fn,
            patch(
                "hate_crack.menu.interactive_menu", side_effect=["2", "99"]
            ),
        ):
            rule_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_dispatches_to_cleanup_and_optimize(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.rule_cleanup_and_optimize_handler") as mock_fn,
            patch(
                "hate_crack.menu.interactive_menu", side_effect=["3", "99"]
            ),
        ):
            rule_tools_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_exits_on_99(self):
        ctx = _make_ctx()
        with patch("hate_crack.menu.interactive_menu", return_value="99"):
            rule_tools_submenu(ctx)

    def test_exits_on_none(self):
        ctx = _make_ctx()
        with patch("hate_crack.menu.interactive_menu", return_value=None):
            rule_tools_submenu(ctx)

    def test_loops_until_exit(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.rule_cleanup_handler") as mock_fn,
            patch(
                "hate_crack.menu.interactive_menu",
                side_effect=["1", "1", "99"],
            ),
        ):
            rule_tools_submenu(ctx)
        assert mock_fn.call_count == 2
