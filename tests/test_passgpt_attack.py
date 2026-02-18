import importlib.util
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

_has_transformers = importlib.util.find_spec("transformers") is not None

from hate_crack.passgpt_train import (
    _count_lines,
    _estimate_training_memory_mb,
    _get_available_memory_mb,
)


@pytest.fixture
def main_module(hc_module):
    """Return the underlying hate_crack.main module for direct patching."""
    return hc_module._main


class TestHcatPassGPT:
    def test_builds_correct_pipe_commands(self, main_module):
        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", "--force"),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatHashFile", "/tmp/hashes.txt", create=True),
            patch.object(
                main_module, "passgptModel", "javirandor/passgpt-10characters"
            ),
            patch.object(main_module, "passgptBatchSize", 1024),
            patch("hate_crack.main.subprocess.Popen") as mock_popen,
        ):
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
        with (
            patch.object(main_module, "hcatBin", "hashcat"),
            patch.object(main_module, "hcatTuning", "--force"),
            patch.object(main_module, "hcatPotfilePath", ""),
            patch.object(main_module, "hcatHashFile", "/tmp/hashes.txt", create=True),
            patch.object(
                main_module, "passgptModel", "javirandor/passgpt-10characters"
            ),
            patch.object(main_module, "passgptBatchSize", 1024),
            patch("hate_crack.main.subprocess.Popen") as mock_popen,
        ):
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

        with (
            patch.object(
                main_module, "passgptModel", "javirandor/passgpt-10characters"
            ),
            patch("hate_crack.main.subprocess.Popen") as mock_popen,
        ):
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

        with (
            patch.object(
                main_module, "passgptModel", "javirandor/passgpt-10characters"
            ),
            patch("hate_crack.main.subprocess.Popen") as mock_popen,
        ):
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
        with (
            patch("builtins.input", side_effect=inputs),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
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
        with (
            patch("builtins.input", side_effect=inputs),
            patch("hate_crack.attacks.os.path.isdir", return_value=True),
            patch("hate_crack.attacks.os.listdir", return_value=["my_model"]),
            patch("hate_crack.attacks.os.path.isfile", return_value=True),
            patch(
                "hate_crack.attacks.os.path.isdir",
                side_effect=lambda p: True,
            ),
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

        # "T" for train, "" for default base model, "" for default device (auto-detected), "" for default max candidates
        inputs = iter(["T", "", "", ""])
        with (
            patch("builtins.input", side_effect=inputs),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
            patch(
                "hate_crack.passgpt_train._detect_device", return_value="cuda"
            ),
        ):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPTTrain.assert_called_once_with(
            "/tmp/wordlist.txt", "javirandor/passgpt-10characters", device="cuda"
        )
        ctx.hcatPassGPT.assert_called_once()
        call_kwargs = ctx.hcatPassGPT.call_args
        assert call_kwargs[1]["model_name"] == "/home/user/.hate_crack/passgpt/wordlist"

    def test_train_failure_aborts(self):
        ctx = self._make_ctx()
        ctx.select_file_with_autocomplete.return_value = "/tmp/wordlist.txt"
        ctx.hcatPassGPTTrain.return_value = None

        # "T" for train, "" for default base model, "" for default device (auto-detected)
        inputs = iter(["T", "", ""])
        with (
            patch("builtins.input", side_effect=inputs),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
            patch(
                "hate_crack.passgpt_train._detect_device", return_value="cuda"
            ),
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
        with (
            patch("builtins.input", side_effect=inputs),
            patch("hate_crack.attacks.os.path.isdir", return_value=False),
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


class TestGetAvailableMemoryMb:
    def test_returns_int_or_none(self):
        result = _get_available_memory_mb()
        assert result is None or isinstance(result, int)

    def test_never_crashes_on_any_platform(self):
        # Should not raise regardless of platform
        _get_available_memory_mb()

    def test_returns_positive_when_detected(self):
        result = _get_available_memory_mb()
        if result is not None:
            assert result > 0


class TestCountLines:
    def test_counts_non_empty_lines(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("line1\nline2\n\nline3\n")
        assert _count_lines(str(f)) == 3

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("")
        assert _count_lines(str(f)) == 0


class TestEstimateTrainingMemoryMb:
    def test_returns_reasonable_estimate(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 1000)
        estimate = _estimate_training_memory_mb(str(f))
        # Should include at least model + optimizer overhead (~1700MB)
        assert estimate >= 1700

    def test_max_lines_reduces_estimate(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 100000)
        full = _estimate_training_memory_mb(str(f))
        limited = _estimate_training_memory_mb(str(f), max_lines=100)
        assert limited <= full


class TestMemoryPrecheck:
    def test_aborts_when_insufficient(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 10)

        with (
            patch("hate_crack.passgpt_train._get_available_memory_mb", return_value=1),
            patch(
                "hate_crack.passgpt_train._estimate_training_memory_mb",
                return_value=5000,
            ),
            pytest.raises(SystemExit),
        ):
            from hate_crack.passgpt_train import train

            train(
                training_file=str(f),
                output_dir=str(tmp_path / "out"),
                base_model="test",
                epochs=1,
                batch_size=1,
                device="cpu",
            )

    @pytest.mark.skipif(not _has_transformers, reason="transformers not installed")
    def test_skips_when_detection_fails(self, tmp_path):
        """When memory detection returns None, training proceeds past the pre-check."""
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 10)

        mock_tokenizer = MagicMock()
        mock_model = MagicMock()
        mock_model.config.n_positions = 16
        mock_trainer = MagicMock()

        with (
            patch(
                "hate_crack.passgpt_train._get_available_memory_mb", return_value=None
            ),
            patch(
                "hate_crack.passgpt_train._estimate_training_memory_mb",
                return_value=5000,
            ),
            patch("hate_crack.passgpt_train._configure_mps"),
            patch(
                "transformers.RobertaTokenizerFast.from_pretrained",
                return_value=mock_tokenizer,
            ),
            patch(
                "transformers.GPT2LMHeadModel.from_pretrained",
                return_value=mock_model,
            ),
            patch("transformers.Trainer", return_value=mock_trainer),
            patch("transformers.TrainingArguments"),
        ):
            from hate_crack.passgpt_train import train

            train(
                training_file=str(f),
                output_dir=str(tmp_path / "out"),
                base_model="test",
                epochs=1,
                batch_size=1,
                device="cpu",
            )

        mock_trainer.train.assert_called_once()


class TestMaxLines:
    def test_count_lines_respects_limit(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 1000)
        # _count_lines doesn't have a limit, but _estimate uses max_lines
        total = _count_lines(str(f))
        assert total == 1000

    def test_estimate_uses_max_lines(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 10000)
        est_full = _estimate_training_memory_mb(str(f))
        est_limited = _estimate_training_memory_mb(str(f), max_lines=10)
        assert est_limited <= est_full


class TestMemoryLimitAutoTune:
    @pytest.mark.skipif(not _has_transformers, reason="transformers not installed")
    def test_auto_tunes_max_lines(self, tmp_path, capsys):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 100)

        mock_tokenizer = MagicMock()
        mock_model = MagicMock()
        mock_model.config.n_positions = 16
        mock_trainer = MagicMock()

        with (
            patch(
                "hate_crack.passgpt_train._get_available_memory_mb", return_value=None
            ),
            patch("hate_crack.passgpt_train._configure_mps"),
            patch(
                "transformers.RobertaTokenizerFast.from_pretrained",
                return_value=mock_tokenizer,
            ),
            patch(
                "transformers.GPT2LMHeadModel.from_pretrained",
                return_value=mock_model,
            ),
            patch("transformers.Trainer", return_value=mock_trainer),
            patch("transformers.TrainingArguments"),
        ):
            from hate_crack.passgpt_train import train

            train(
                training_file=str(f),
                output_dir=str(tmp_path / "out"),
                base_model="test",
                epochs=1,
                batch_size=1,
                device="cpu",
                memory_limit=2000,
            )

        captured = capsys.readouterr()
        assert "--memory-limit 2000MB: auto-set --max-lines" in captured.err

    def test_memory_limit_too_low_exits(self, tmp_path):
        f = tmp_path / "words.txt"
        f.write_text("password\n" * 10)

        with pytest.raises(SystemExit):
            from hate_crack.passgpt_train import train

            train(
                training_file=str(f),
                output_dir=str(tmp_path / "out"),
                base_model="test",
                epochs=1,
                batch_size=1,
                device="cpu",
                memory_limit=1,  # 1MB - way too low
            )
