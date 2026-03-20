import os
from unittest.mock import MagicMock, patch

from hate_crack.api import list_and_download_hashmob_rules


def _make_rules(names):
    return [{"file_name": n} for n in names]


def _patch_stdin_tty():
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = True
    return patch("hate_crack.api.sys.stdin", mock_stdin)


class TestListAndDownloadHashmobRulesAllFiles:
    def test_downloads_all_rules_when_selection_is_a(self, tmp_path):
        rules = _make_rules(["a.rule", "b.rule", "c.rule", "d.rule", "e.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl, \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        assert mock_dl.call_count == 5
        downloaded = {call.args[0] for call in mock_dl.call_args_list}
        assert downloaded == {"a.rule", "b.rule", "c.rule", "d.rule", "e.rule"}

    def test_output_path_is_inside_rules_dir(self, tmp_path):
        rules = _make_rules(["sample.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        captured_paths = []

        def capture(file_name, out_path):
            captured_paths.append(out_path)

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule", side_effect=capture), \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        assert len(captured_paths) == 1
        assert captured_paths[0].startswith(rules_dir)

    def test_success_count_reported(self, tmp_path, capsys):
        rules = _make_rules(["x.rule", "y.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule"), \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        out = capsys.readouterr().out
        assert "2 succeeded" in out
        assert "0 failed" in out


class TestListAndDownloadHashmobRulesSkipping:
    def test_skips_already_downloaded_files(self, tmp_path):
        rules = _make_rules(["existing.rule", "new1.rule", "new2.rule", "also_existing.rule", "new3.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        (tmp_path / "rules" / "existing.rule").touch()
        (tmp_path / "rules" / "also_existing.rule").touch()

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl, \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        assert mock_dl.call_count == 3
        downloaded = {call.args[0] for call in mock_dl.call_args_list}
        assert downloaded == {"new1.rule", "new2.rule", "new3.rule"}

    def test_skip_prints_message(self, tmp_path, capsys):
        rules = _make_rules(["existing.rule", "new.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        (tmp_path / "rules" / "existing.rule").touch()

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule"), \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        out = capsys.readouterr().out
        assert "Skipping" in out
        assert "existing.rule" in out

    def test_all_already_downloaded_does_nothing(self, tmp_path):
        rules = _make_rules(["r1.rule", "r2.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        (tmp_path / "rules" / "r1.rule").touch()
        (tmp_path / "rules" / "r2.rule").touch()

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl, \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        mock_dl.assert_not_called()


class TestListAndDownloadHashmobRulesFailures:
    def test_failed_download_reported_in_count(self, tmp_path, capsys):
        rules = _make_rules(["good.rule", "bad.rule", "also_good.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        def side_effect(file_name, out_path):
            if file_name == "bad.rule":
                raise RuntimeError("network error")

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule", side_effect=side_effect), \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        out = capsys.readouterr().out
        assert "2 succeeded" in out
        assert "1 failed" in out

    def test_failure_does_not_block_other_downloads(self, tmp_path):
        rules = _make_rules(["good1.rule", "bad.rule", "good2.rule", "good3.rule", "good4.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)
        completed = []

        def side_effect(file_name, out_path):
            if file_name == "bad.rule":
                raise RuntimeError("fail")
            completed.append(file_name)

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule", side_effect=side_effect), \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="a"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        assert len(completed) == 4
        assert "bad.rule" not in completed


class TestListAndDownloadHashmobRulesEmptyAndQuit:
    def test_returns_early_when_rules_list_empty(self, tmp_path):
        with patch("hate_crack.api.download_hashmob_rule_list", return_value=[]), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl:
            list_and_download_hashmob_rules(rules_dir=str(tmp_path))

        mock_dl.assert_not_called()

    def test_quit_selection_downloads_nothing(self, tmp_path):
        rules = _make_rules(["r.rule"])
        rules_dir = str(tmp_path / "rules")
        os.makedirs(rules_dir)

        with patch("hate_crack.api.download_hashmob_rule_list", return_value=rules), \
             patch("hate_crack.api.download_hashmob_rule") as mock_dl, \
             _patch_stdin_tty(), \
             patch("builtins.input", return_value="q"):
            list_and_download_hashmob_rules(rules_dir=rules_dir)

        mock_dl.assert_not_called()
