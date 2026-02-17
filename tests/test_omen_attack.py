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

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "hcatOmenCreateBin", "createNG"
        ), patch("hate_crack.main.subprocess.Popen") as mock_popen:
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

    def test_missing_binary(self, main_module, tmp_path, capsys):
        training_file = tmp_path / "passwords.txt"
        training_file.write_text("test\n")

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "hcatOmenCreateBin", "createNG"
        ):
            main_module.hcatOmenTrain(str(training_file))
            captured = capsys.readouterr()
            assert "createNG binary not found" in captured.out

    def test_missing_training_file(self, main_module, tmp_path, capsys):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        create_bin = omen_dir / "createNG"
        create_bin.touch()

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "hcatOmenCreateBin", "createNG"
        ):
            main_module.hcatOmenTrain("/nonexistent/file.txt")
            captured = capsys.readouterr()
            assert "Training file not found" in captured.out


class TestHcatOmen:
    def test_builds_correct_pipe_commands(self, main_module, tmp_path):
        omen_dir = tmp_path / "omen"
        omen_dir.mkdir()
        enum_bin = omen_dir / "enumNG"
        enum_bin.touch()
        enum_bin.chmod(0o755)

        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "hcatOmenEnumBin", "enumNG"
        ), patch.object(main_module, "hcatBin", "hashcat"), patch.object(
            main_module, "hcatTuning", "--force"
        ), patch.object(
            main_module, "hcatPotfilePath", ""
        ), patch.object(
            main_module, "hcatHashFile", "/tmp/hashes.txt", create=True
        ), patch(
            "hate_crack.main.subprocess.Popen"
        ) as mock_popen:
            mock_enum_proc = MagicMock()
            mock_enum_proc.stdout = MagicMock()
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
            # Second call: hashcat
            hashcat_cmd = mock_popen.call_args_list[1][0][0]
            assert hashcat_cmd[0] == "hashcat"
            assert "1000" in hashcat_cmd
            assert "/tmp/hashes.txt" in hashcat_cmd

    def test_missing_binary(self, main_module, tmp_path, capsys):
        with patch.object(main_module, "hate_path", str(tmp_path)), patch.object(
            main_module, "hcatOmenEnumBin", "enumNG"
        ):
            main_module.hcatOmen("1000", "/tmp/hashes.txt", 500000)
            captured = capsys.readouterr()
            assert "enumNG binary not found" in captured.out


class TestOmenAttackHandler:
    def test_prompts_and_calls_hcatOmen(self):
        ctx = MagicMock()
        ctx.hate_path = "/fake/path"
        ctx.omenTrainingList = "/fake/rockyou.txt"
        ctx.omenMaxCandidates = 1000000
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"

        with patch("os.path.isfile", return_value=True), patch(
            "builtins.input", return_value=""
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)

        ctx.hcatOmen.assert_called_once_with("1000", "/tmp/hashes.txt", 1000000)

    def test_trains_when_no_model(self):
        ctx = MagicMock()
        ctx.hate_path = "/fake/path"
        ctx.omenTrainingList = "/fake/rockyou.txt"
        ctx.omenMaxCandidates = 1000000
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"

        def fake_isfile(path):
            return "IP.level" not in path

        with patch("os.path.isfile", side_effect=fake_isfile), patch(
            "builtins.input", return_value=""
        ):
            from hate_crack.attacks import omen_attack

            omen_attack(ctx)

        ctx.hcatOmenTrain.assert_called_once_with("/fake/rockyou.txt")
        ctx.hcatOmen.assert_called_once()
