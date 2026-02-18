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


class TestPassGPTAttackHandler:
    def test_prompts_and_calls_hcatPassGPT(self):
        ctx = MagicMock()
        ctx.HAS_ML_DEPS = True
        ctx.passgptMaxCandidates = 1000000
        ctx.passgptModel = "javirandor/passgpt-10characters"
        ctx.passgptBatchSize = 1024
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"

        with patch("builtins.input", return_value=""):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPT.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            1000000,
            model_name="javirandor/passgpt-10characters",
            batch_size=1024,
        )

    def test_custom_values(self):
        ctx = MagicMock()
        ctx.HAS_ML_DEPS = True
        ctx.passgptMaxCandidates = 1000000
        ctx.passgptModel = "javirandor/passgpt-10characters"
        ctx.passgptBatchSize = 1024
        ctx.hcatHashType = "1000"
        ctx.hcatHashFile = "/tmp/hashes.txt"

        inputs = iter(["500000", "custom/model"])
        with patch("builtins.input", side_effect=inputs):
            from hate_crack.attacks import passgpt_attack

            passgpt_attack(ctx)

        ctx.hcatPassGPT.assert_called_once_with(
            "1000",
            "/tmp/hashes.txt",
            500000,
            model_name="custom/model",
            batch_size=1024,
        )

    def test_ml_deps_missing(self, capsys):
        ctx = MagicMock()
        ctx.HAS_ML_DEPS = False

        from hate_crack.attacks import passgpt_attack

        passgpt_attack(ctx)

        captured = capsys.readouterr()
        assert "ML dependencies" in captured.out
        assert "uv pip install" in captured.out
        ctx.hcatPassGPT.assert_not_called()
