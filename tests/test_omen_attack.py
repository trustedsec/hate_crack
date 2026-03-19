import json
import os
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


class TestHcatOmenTrain:
    def test_builds_correct_command(self, main_module, tmp_path):
        training_file = tmp_path / "passwords.txt"
        training_file.write_text("password123\nletmein\n")
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()
        create_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "_omen_dir", str(omen_dir)
        ), patch.object(
            main_module, "hcatOmenCreateBin", "createNG"
        ), patch(
            "hate_crack.main._omen_model_dir", return_value=str(model_dir)
        ), patch(
            "hate_crack.main.subprocess.Popen"
        ) as mock_popen:
            mock_proc = MagicMock()
            mock_proc.wait.return_value = None
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            main_module.hcatOmenTrain(str(training_file))

            mock_popen.assert_called_once()
            cmd = mock_popen.call_args[0][0]
            assert cmd[0] == str(create_bin)
            assert "--iPwdList" in cmd
            assert str(training_file) in cmd
            # Verify explicit output paths are passed
            assert "-C" in cmd
            assert str(model_dir / "createConfig") in cmd
            assert "-c" in cmd
            assert str(model_dir / "CP") in cmd
            assert "-i" in cmd
            assert str(model_dir / "IP") in cmd
            assert "-e" in cmd
            assert str(model_dir / "EP") in cmd
            assert "-l" in cmd
            assert str(model_dir / "LN") in cmd

    def test_returns_true_and_writes_metadata_on_success(self, main_module, tmp_path):
        training_file = tmp_path / "passwords.txt"
        training_file.write_text("password123\nletmein\n")
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()
        create_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.wait.return_value = None
            mock_proc.returncode = 0
            mock_popen.return_value = mock_proc

            result = main_module.hcatOmenTrain(str(training_file))

        assert result is True
        info_path = model_dir / "model_info.json"
        assert info_path.exists()
        info = json.loads(info_path.read_text())
        assert info["training_file"] == str(training_file)
        assert "trained_at" in info

    def test_returns_false_on_failure(self, main_module, tmp_path):
        training_file = tmp_path / "passwords.txt"
        training_file.write_text("test\n")
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()
        create_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.wait.return_value = None
            mock_proc.returncode = 1
            mock_popen.return_value = mock_proc

            result = main_module.hcatOmenTrain(str(training_file))

        assert result is False

    def test_missing_binary_returns_false(self, main_module, tmp_path):
        with patch.object(main_module, "_omen_dir", str(tmp_path / "omen")), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"):
            result = main_module.hcatOmenTrain("/nonexistent/file.txt")
        assert result is False

    def test_missing_training_file_returns_false(self, main_module, tmp_path):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()
        model_dir = tmp_path / "model"
        model_dir.mkdir()

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenCreateBin", "createNG"), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)):
            result = main_module.hcatOmenTrain("/nonexistent/file.txt")
        assert result is False


class TestHcatOmen:
    def test_builds_correct_pipe_commands(self, main_module, tmp_path):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "_omen_dir", str(omen_dir)
        ), patch.object(
            main_module, "hcatOmenEnumBin", "enumNG"
        ), patch.object(main_module, "hcatBin", "hashcat"), patch.object(
            main_module, "hcatTuning", "--force"
        ), patch.object(
            main_module, "hcatPotfilePath", ""
        ), patch.object(
            main_module, "hcatHashFile", "/tmp/hashes.txt", create=True
        ), patch(
            "hate_crack.main._omen_model_dir", return_value=str(model_dir)
        ), patch(
            "hate_crack.main.subprocess.Popen"
        ) as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
            mock_enum_proc.returncode = 0
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_enum_proc.wait.return_value = None
            mock_popen.side_effect = [mock_enum_proc, mock_hashcat_proc]

            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)

            assert mock_popen.call_count == 2
            # First call: enumNG
            enum_cmd = mock_popen.call_args_list[0][0][0]
            assert enum_cmd[0] == str(enum_bin)
            assert "-p" in enum_cmd
            assert "-m" in enum_cmd
            assert "500000" in enum_cmd
            assert "-C" in enum_cmd
            assert str(model_dir / "createConfig") in enum_cmd
            # cwd should be model_dir
            assert mock_popen.call_args_list[0][1]["cwd"] == str(model_dir)
            # Second call: hashcat
            hashcat_cmd = mock_popen.call_args_list[1][0][0]
            assert hashcat_cmd[0] == "hashcat"
            assert "1000" in hashcat_cmd
            assert "/tmp/hashes.txt" in hashcat_cmd

    def test_missing_binary(self, main_module, tmp_path, capsys):
        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "_omen_dir", str(tmp_path / "omen")
        ), patch.object(main_module, "hcatOmenEnumBin", "enumNG"):
            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)
            captured = capsys.readouterr()
            assert "enumNG binary not found" in captured.out

    def test_missing_model(self, main_module, tmp_path, capsys):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        # No createConfig in model_dir

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "_omen_dir", str(omen_dir)
        ), patch.object(
            main_module, "hcatOmenEnumBin", "enumNG"
        ), patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)):
            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)
            captured = capsys.readouterr()
            assert "OMEN model not found" in captured.out

    def test_prints_enumng_stderr_on_failure(self, main_module, tmp_path, capsys):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenEnumBin", "enumNG"), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatHashFile", "/tmp/hashes.txt", create=True), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
            mock_enum_proc.stderr.read.return_value = b"ERROR: Could not open CP.level"
            mock_enum_proc.wait.return_value = None
            mock_enum_proc.returncode = 1
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_popen.side_effect = [mock_enum_proc, mock_hashcat_proc]

            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)

        captured = capsys.readouterr()
        assert "enumNG failed" in captured.out
        assert "Could not open CP.level" in captured.out


class TestOmenAttackHandler:
    def _make_ctx(self, tmp_path, model_valid=True):
        ctx = MagicMock()
        ctx.hate_path = str(tmp_path)
        ctx._omen_dir = str(tmp_path / "omen")
        ctx.hcatOmenCreateBin = "createNG"
        ctx.hcatOmenEnumBin = "enumNG"
        ctx.omenTrainingList = "/default/rockyou.txt"
        ctx.omenMaxCandidates = 50000000
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        ctx.hcatWordlists = str(tmp_path / "wordlists")
        ctx.rulesDirectory = str(tmp_path / "rules")
        ctx._omen_model_is_valid.return_value = model_valid
        ctx._omen_model_info.return_value = (
            {"training_file": "/old/rockyou.txt"} if model_valid else None
        )
        ctx._omen_model_dir.return_value = str(tmp_path / "model")
        ctx.hcatOmenTrain.return_value = True
        ctx.list_wordlist_files.return_value = ["rockyou.txt", "custom.txt"]
        return ctx

    def _setup_rules_dir(self, tmp_path, rule_names=None):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir(exist_ok=True)
        if rule_names:
            for name in rule_names:
                (rules_dir / name).write_text(":")
        return rules_dir

    def test_use_existing_model(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        self._setup_rules_dir(tmp_path)
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1", "", "0"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_not_called()
        ctx.hcatOmen.assert_called_once()

    def test_train_new_model_with_wordlist_pick(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        self._setup_rules_dir(tmp_path)
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["2", "1", "", "0"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_called_once()
        training_arg = ctx.hcatOmenTrain.call_args[0][0]
        assert "rockyou.txt" in training_arg
        ctx.hcatOmen.assert_called_once()

    def test_cancel_aborts(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["3"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_not_called()
        ctx.hcatOmen.assert_not_called()

    def test_no_model_goes_straight_to_training(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=False)
        self._setup_rules_dir(tmp_path)
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1", "", "0"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_called_once()
        ctx.hcatOmen.assert_called_once()

    def test_training_failure_aborts_enumeration(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=False)
        ctx.hcatOmenTrain.return_value = False
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmen.assert_not_called()

    def test_custom_path_for_training(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=False)
        self._setup_rules_dir(tmp_path)
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["p", "/custom/wordlist.txt", "", "0"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmenTrain.assert_called_once_with("/custom/wordlist.txt")

    def test_rules_passed_to_hcatOmen(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        self._setup_rules_dir(tmp_path, ["best64.rule"])
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1", "", "1"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        call_args = ctx.hcatOmen.call_args
        assert "-r" in call_args[0][3]
        assert "best64.rule" in call_args[0][3]

    def test_multiple_rule_chains_spawn_multiple_calls(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        self._setup_rules_dir(tmp_path, ["best64.rule", "dive.rule"])
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1", "", "1,2"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        assert ctx.hcatOmen.call_count == 2

    def test_cancel_from_rules_aborts(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        self._setup_rules_dir(tmp_path, ["best64.rule"])
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1", "", "99"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmen.assert_not_called()

    def test_no_rules_passes_empty_chain(self, tmp_path):
        ctx = self._make_ctx(tmp_path, model_valid=True)
        self._setup_rules_dir(tmp_path, ["best64.rule"])
        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", side_effect=["1", "", "0"]
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)
        ctx.hcatOmen.assert_called_once()
        assert ctx.hcatOmen.call_args[0][3] == ""


class TestHcatOmenWithRules:
    def test_rule_flags_appear_in_hashcat_command(self, main_module, tmp_path):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenEnumBin", "enumNG"), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatDebugLogPath", str(tmp_path / "debug")), \
             patch.object(main_module, "hcatHashFile", "/tmp/hashes.txt", create=True), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
            mock_enum_proc.stderr = MagicMock()
            mock_enum_proc.stderr.read.return_value = b""
            mock_enum_proc.returncode = 0
            mock_enum_proc.wait.return_value = None
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_popen.side_effect = [mock_enum_proc, mock_hashcat_proc]

            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000, "-r /tmp/best64.rule")

        hashcat_cmd = mock_popen.call_args_list[1][0][0]
        assert "-r" in hashcat_cmd
        assert "/tmp/best64.rule" in hashcat_cmd

    def test_debug_mode_added_when_rules_present(self, main_module, tmp_path):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenEnumBin", "enumNG"), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatDebugLogPath", str(tmp_path / "debug")), \
             patch.object(main_module, "hcatHashFile", "/tmp/hashes.txt", create=True), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
            mock_enum_proc.stderr = MagicMock()
            mock_enum_proc.stderr.read.return_value = b""
            mock_enum_proc.returncode = 0
            mock_enum_proc.wait.return_value = None
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_popen.side_effect = [mock_enum_proc, mock_hashcat_proc]

            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000, "-r /tmp/best64.rule")

        hashcat_cmd = mock_popen.call_args_list[1][0][0]
        assert "--debug-mode" in hashcat_cmd

    def test_no_rules_no_debug_mode(self, main_module, tmp_path):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "createConfig").write_text("# test config\n")

        with patch.object(main_module, "_omen_dir", str(omen_dir)), \
             patch.object(main_module, "hcatOmenEnumBin", "enumNG"), \
             patch.object(main_module, "hcatBin", "hashcat"), \
             patch.object(main_module, "hcatTuning", ""), \
             patch.object(main_module, "hcatPotfilePath", ""), \
             patch.object(main_module, "hcatHashFile", "/tmp/hashes.txt", create=True), \
             patch("hate_crack.main._omen_model_dir", return_value=str(model_dir)), \
             patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
            mock_enum_proc.stderr = MagicMock()
            mock_enum_proc.stderr.read.return_value = b""
            mock_enum_proc.returncode = 0
            mock_enum_proc.wait.return_value = None
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_popen.side_effect = [mock_enum_proc, mock_hashcat_proc]

            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)

        hashcat_cmd = mock_popen.call_args_list[1][0][0]
        assert "--debug-mode" not in hashcat_cmd


class TestOmenModelValidation:
    @pytest.fixture
    def model_dir(self, tmp_path):
        d = tmp_path / "model"
        d.mkdir()
        return d

    def _create_valid_model(self, model_dir):
        for name in ["createConfig", "CP.level", "IP.level", "EP.level", "LN.level"]:
            (model_dir / name).write_text("data")

    def test_valid_model_returns_true(self, main_module, model_dir):
        self._create_valid_model(model_dir)
        assert main_module._omen_model_is_valid(str(model_dir)) is True

    def test_missing_level_file_returns_false(self, main_module, model_dir):
        self._create_valid_model(model_dir)
        (model_dir / "CP.level").unlink()
        assert main_module._omen_model_is_valid(str(model_dir)) is False

    def test_empty_file_returns_false(self, main_module, model_dir):
        self._create_valid_model(model_dir)
        (model_dir / "EP.level").write_text("")
        assert main_module._omen_model_is_valid(str(model_dir)) is False

    def test_missing_dir_returns_false(self, main_module, tmp_path):
        assert main_module._omen_model_is_valid(str(tmp_path / "nonexistent")) is False

    def test_config_only_returns_false(self, main_module, model_dir):
        (model_dir / "createConfig").write_text("data")
        assert main_module._omen_model_is_valid(str(model_dir)) is False


class TestOmenModelInfo:
    def test_returns_info_when_metadata_exists(self, main_module, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        info = {"training_file": "/path/to/rockyou.txt", "trained_at": "2026-03-17T12:00:00"}
        (model_dir / "model_info.json").write_text(json.dumps(info))
        result = main_module._omen_model_info(str(model_dir))
        assert result["training_file"] == "/path/to/rockyou.txt"

    def test_returns_none_when_no_metadata(self, main_module, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        assert main_module._omen_model_info(str(model_dir)) is None

    def test_returns_none_on_corrupt_json(self, main_module, tmp_path):
        model_dir = tmp_path / "model"
        model_dir.mkdir()
        (model_dir / "model_info.json").write_text("not json")
        assert main_module._omen_model_info(str(model_dir)) is None
