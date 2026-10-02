"""The hash-type prompt in Hashview's "Upload Hashfile and Create Job" flow.

It was a bare ``int(input(...))``. The ValueError did not reach the user as a
traceback -- the whole menu loop sits inside a broad ``except Exception`` that
reports it as "Error connecting to Hashview", which is simply untrue -- but it
did abandon the flow and drop the user back to the main menu, after the
customer had already been selected or created on the server.
"""

from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _pick_by_text(choices):
    def _pick(items, **kwargs):
        wanted = choices.pop(0)
        return next(key for key, text in items if text == wanted)

    return _pick


def _drive_upload_job(main_module, monkeypatch, tmp_path, inputs):
    """Run the upload-job branch with *inputs* answering its prompts."""
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("8846f7eaee8fb117ad06bdd830b7586c\n")

    monkeypatch.setattr(main_module, "hcatHashFile", str(hashfile))
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(hashfile))
    # Unset so the branch prompts rather than reusing the command-line type.
    monkeypatch.setattr(main_module, "hcatHashType", None)
    monkeypatch.setattr(main_module, "hashview_api_key", "k", raising=False)
    monkeypatch.setattr(main_module, "hashview_url", "http://x", raising=False)
    monkeypatch.setattr(
        main_module,
        "interactive_menu",
        _pick_by_text(["Upload Hashfile and Create Job", "Back to Main Menu"]),
        raising=False,
    )

    harness = MagicMock()
    harness.list_customers.return_value = {"customers": [{"id": 1, "name": "acme"}]}
    # No hashfile_id in the reply, so the flow stops before the job prompts.
    harness.upload_hashfile.return_value = {"msg": "uploaded"}

    with (
        patch.object(main_module, "HashviewAPI", return_value=harness),
        patch("builtins.input", side_effect=inputs),
    ):
        main_module.hashview_api()

    return harness


class TestHashTypePrompt:
    def test_typo_reprompts_and_upload_still_happens(
        self, main_module, monkeypatch, tmp_path, capsys
    ):
        harness = _drive_upload_job(
            main_module,
            monkeypatch,
            tmp_path,
            inputs=["1", "NTLM", "1000", ""],
        )
        out = capsys.readouterr().out
        assert "Error connecting to Hashview" not in out
        harness.upload_hashfile.assert_called_once()
        assert harness.upload_hashfile.call_args[0][2] == 1000

    def test_cancelling_hash_type_skips_the_upload(
        self, main_module, monkeypatch, tmp_path, capsys
    ):
        harness = _drive_upload_job(
            main_module,
            monkeypatch,
            tmp_path,
            inputs=["1", "q"],
        )
        assert "Error connecting to Hashview" not in capsys.readouterr().out
        harness.upload_hashfile.assert_not_called()
