import os
import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


class TestHcatPassGPT:
    def test_builds_correct_pipe_commands(self, main_module):
        with patch.object(main_module, "hcatBin", "hashcat"), patch.object(
            main_module, "hcatTuning", "--force"
        ), patch.object(main_module, "hcatPotfilePath", ""), patch.object(
            main_module, "hcatHashFile", "/tmp/hashes.txt", create=True
        ), patch.object(
            main_module, "passgptModel", "javirandor/passgpt-10characters"
        ), patch.object(main_module, "passgptBatchSize", 1024), patch(
            "hate_crack.main.subprocess.Popen"
        ) as mock_popen:
            mock_gen_proc = MagicMock()
            mock_gen_proc.stdout = MagicMock()
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_gen_proc.wait.return_value = None
            mock_popen.side_effect = [mock_gen_proc, mock_hashcat_proc]

            main_module.hcatPassGPT("1000", "/tmp/hashes.txt", 500000)

            assert mock_popen.call_count == 2
            # First call: passgpt generator
            gen_cmd = mock_popen.call_args_list[0][0][0]
            assert gen_cmd[0] == sys.executable
            assert "-m" in gen_cmd
            assert "hate_crack.passgpt_generate" in gen_cmd
            assert "--num" in gen_cmd
            assert "500000" in gen_cmd
            assert "--model" in gen_cmd
            assert "javirandor/passgpt-10characters" in gen_cmd
            assert "--batch-size" in gen_cmd
            assert "1024" in gen_cmd
            # Second call: hashcat
            hashcat_cmd = mock_popen.call_args_list[1][0][0]
            assert hashcat_cmd[0] == "hashcat"
            assert "1000" in hashcat_cmd
            assert "/tmp/hashes.txt" in hashcat_cmd

    def test_custom_model_and_batch_size(self, main_module):
        with patch.object(main_module, "hcatBin", "hashcat"), patch.object(
            main_module, "hcatTuning", "--force"
        ), patch.object(main_module, "hcatPotfilePath", ""), patch.object(
            main_module, "hcatHashFile", "/tmp/hashes.txt", create=True
        ), patch.object(
            main_module, "passgptModel", "javirandor/passgpt-10characters"
        ), patch.object(main_module, "passgptBatchSize", 1024), patch(
            "hate_crack.main.subprocess.Popen"
        ) as mock_popen:
            mock_gen_proc = MagicMock()
            mock_gen_proc.stdout = MagicMock()
            mock_hashcat_proc = MagicMock()
            mock_hashcat_proc.wait.return_value = None
            mock_gen_proc.wait.return_value = None
            mock_popen.side_effect = [mock_gen_proc, mock_hashcat_proc]

            main_module.hcatPassGPT(
                "1000",
                "/tmp/hashes.txt",
                100000,
                model_name="custom/model",
                batch_size=512,
            )

            gen_cmd = mock_popen.call_args_list[0][0][0]
            assert "custom/model" in gen_cmd
            assert "512" in gen_cmd


class TestHcatPassGPTTrain:
    def test_builds_correct_subprocess_command(self, main_module, tmp_path):
        training_file = tmp_path / "wordlist.txt"
        training_file.write_text("password123\nabc456\n")

        with patch.object(
            main_module, "passgptModel", "javirandor/passgpt-10characters"
        ), patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.wait.return_value = None
            mock_popen.return_value = mock_proc

            with patch.object(
                main_module,
                "_passgpt_model_dir",
                return_value=str(tmp_path / "models"),
            ):
                result = main_module.hcatPassGPTTrain(str(training_file))

            assert result is not None
            assert mock_popen.call_count == 1
            cmd = mock_popen.call_args[0][0]
            assert cmd[0] == sys.executable
            assert "-m" in cmd
            assert "hate_crack.passgpt_train" in cmd
            assert "--training-file" in cmd
            assert str(training_file) in cmd
            assert "--base-model" in cmd
            assert "javirandor/passgpt-10characters" in cmd
            assert "--output-dir" in cmd

    def test_missing_training_file(self, main_module, capsys):
        result = main_module.hcatPassGPTTrain("/nonexistent/wordlist.txt")
        assert result is None
        captured = capsys.readouterr()
        assert "Training file not found" in captured.out

    def test_custom_base_model(self, main_module, tmp_path):
        training_file = tmp_path / "wordlist.txt"
        training_file.write_text("test\n")

        with patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.wait.return_value = None
            mock_popen.return_value = mock_proc

            with patch.object(
                main_module,
                "_passgpt_model_dir",
                return_value=str(tmp_path / "models"),
            ):
                main_module.hcatPassGPTTrain(
                    str(training_file), base_model="custom/base-model"
                )

            cmd = mock_popen.call_args[0][0]
            assert "custom/base-model" in cmd

    def test_training_failure_returns_none(self, main_module, tmp_path):
        training_file = tmp_path / "wordlist.txt"
        training_file.write_text("test\n")

        with patch.object(
            main_module, "passgptModel", "javirandor/passgpt-10characters"
        ), patch("hate_crack.main.subprocess.Popen") as mock_popen:
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.wait.return_value = None
            mock_popen.return_value = mock_proc

            with patch.object(
                main_module,
                "_passgpt_model_dir",
                return_value=str(tmp_path / "models"),
            ):
                result = main_module.hcatPassGPTTrain(str(training_file))

            assert result is None


class TestPassGPTModelDir:
    def test_creates_directory(self, main_module, tmp_path):
        target = str(tmp_path / "passgpt_models")
        with patch("hate_crack.main.os.path.expanduser", return_value=str(tmp_path)):
            result = main_module._passgpt_model_dir()
        assert os.path.isdir(result)
        assert result.endswith("passgpt")


class TestPassGPTAttackHandler:
    def _make_ctx(self, model_dir=None):
        ctx = MagicMock()
        ctx.HAS_ML_DEPS = True
        ctx.passgptMaxCandidates = 1000000
        ctx.passgptModel = "javirandor/passgpt-10characters"
        ctx.passgptBatchSize = 1024
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"
        ctx.hcatWordlists = "/tmp/wordlists"
        if model_dir is None:
            ctx._passgpt_model_dir.return_value = "/nonexistent/empty"
        else:
            ctx._passgpt_model_dir.return_value = model_dir
        return ctx

    def test_select_default_model_and_generate(self):
        ctx = self._make_ctx()

        # "1" selects default model, "" accepts default max candidates
        inputs = iter(["1", ""])
        with patch("builtins.input", side_effect=inputs), patch(
            "hate_crack.attacks.os.path.isdir", return_value=False
        ):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPT.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            1000000,
            model_name="javirandor/passgpt-10characters",
            batch_size=1024,
        )

    def test_select_local_model(self, tmp_path):
        # Create a fake local model directory
        model_dir = tmp_path / "passgpt"
        local_model = model_dir / "my_model"
        local_model.mkdir(parents=True)
        (local_model / "config.json").write_text("{}")

        ctx = self._make_ctx(model_dir=str(model_dir))

        # "2" selects the local model, "" accepts default max candidates
        inputs = iter(["2", ""])
        with patch("builtins.input", side_effect=inputs), patch(
            "hate_crack.attacks.os.path.isdir", return_value=True
        ), patch("hate_crack.attacks.os.listdir", return_value=["my_model"]), patch(
            "hate_crack.attacks.os.path.isfile", return_value=True
        ), patch(
            "hate_crack.attacks.os.path.isdir",
            side_effect=lambda p: True,
        ):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPT.assert_called_once()
        call_kwargs = ctx.hcatPassGPT.call_args
        # The model_name should be the local path
        assert call_kwargs[1]["model_name"] == str(local_model)

    def test_train_new_model(self):
        ctx = self._make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/tmp/wordlist.txt"
        ctx.hcatPassGPTTrain.return_value = "/home/user/.hate_crack/passgpt/wordlist"

        # "T" for train, "" for default base model, "" for default max candidates
        inputs = iter(["T", "", ""])
        with patch("builtins.input", side_effect=inputs), patch(
            "hate_crack.attacks.os.path.isdir", return_value=False
        ):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPTTrain.assert_called_once_with(
            "/tmp/wordlist.txt", "javirandor/passgpt-10characters"
        )
        ctx.hcatPassGPT.assert_called_once()
        call_kwargs = ctx.hcatPassGPT.call_args
        assert call_kwargs[1]["model_name"] == "/home/user/.hate_crack/passgpt/wordlist"

    def test_train_failure_aborts(self):
        ctx = self._make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/tmp/wordlist.txt"
        ctx.hcatPassGPTTrain.return_value = None

        inputs = iter(["T", ""])
        with patch("builtins.input", side_effect=inputs), patch(
            "hate_crack.attacks.os.path.isdir", return_value=False
        ):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPTTrain.assert_called_once()
        ctx.hcatPassGPT.assert_not_called()

    def test_ml_deps_missing(self, capsys):
        ctx = MagicMock()
        ctx.HAS_ML_DEPS = False

        from hate_crack.attacks import passgpt_attack

        passgpt_attack(ctx)

        captured = capsys.readouterr()
        assert "ML dependencies" in captured.out
        assert "uv pip install" in captured.out
        ctx.hcatPassGPT.assert_not_called()

    def test_custom_max_candidates(self):
        ctx = self._make_ctx()

        # "1" selects default model, "500000" for custom max candidates
        inputs = iter(["1", "500000"])
        with patch("builtins.input", side_effect=inputs), patch(
            "hate_crack.attacks.os.path.isdir", return_value=False
        ):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPT.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            500000,
            model_name="javirandor/passgpt-10characters",
            batch_size=1024,
        )
