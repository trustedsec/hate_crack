import os
from unittest.mock import MagicMock, patch

from hate_crack.api import download_all_hashmob_archives
from hate_crack.attacks import (
    hashmob_archives_handler,
    hashmob_combined_left_handler,
    hashmob_downloads_submenu,
)


def _make_ctx():
    return MagicMock()


class TestHashmobDownloadsSubmenu:
    def test_dispatches_to_archives_handler(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.hashmob_archives_handler") as mock_fn,
            patch("hate_crack.attacks.interactive_menu", side_effect=["1", "99"]),
        ):
            hashmob_downloads_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_dispatches_to_combined_left_handler(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.hashmob_combined_left_handler") as mock_fn,
            patch("hate_crack.attacks.interactive_menu", side_effect=["2", "99"]),
        ):
            hashmob_downloads_submenu(ctx)
        mock_fn.assert_called_once_with(ctx)

    def test_exits_on_99(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.interactive_menu", return_value="99"):
            hashmob_downloads_submenu(ctx)

    def test_exits_on_none(self):
        ctx = _make_ctx()
        with patch("hate_crack.attacks.interactive_menu", return_value=None):
            hashmob_downloads_submenu(ctx)


class TestHashmobArchivesHandler:
    def test_no_entries_returns_without_prompting(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=[]),
            patch("builtins.input") as mock_input,
        ):
            hashmob_archives_handler(ctx)
        mock_input.assert_not_called()

    def test_selecting_index_downloads_that_entry(self):
        ctx = _make_ctx()
        entries = [
            {"year": "2021", "name": "a.7z", "url": "https://hashmob.net/a.7z"},
            {"year": "2022", "name": "b.7z", "url": "https://hashmob.net/b.7z"},
        ]
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=entries),
            patch("hate_crack.attacks.download_hashmob_archive") as mock_dl,
            patch("builtins.input", return_value="2"),
        ):
            hashmob_archives_handler(ctx)
        mock_dl.assert_called_once_with(entries[1])

    def test_q_cancels_without_downloading(self):
        ctx = _make_ctx()
        entries = [{"year": "2021", "name": "a.7z", "url": "https://hashmob.net/a.7z"}]
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=entries),
            patch("hate_crack.attacks.download_hashmob_archive") as mock_dl,
            patch("builtins.input", return_value="q"),
        ):
            hashmob_archives_handler(ctx)
        mock_dl.assert_not_called()

    def test_invalid_index_does_not_download(self):
        ctx = _make_ctx()
        entries = [{"year": "2021", "name": "a.7z", "url": "https://hashmob.net/a.7z"}]
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=entries),
            patch("hate_crack.attacks.download_hashmob_archive") as mock_dl,
            patch("builtins.input", return_value="99"),
        ):
            hashmob_archives_handler(ctx)
        mock_dl.assert_not_called()

    def test_non_numeric_selection_does_not_download(self):
        ctx = _make_ctx()
        entries = [{"year": "2021", "name": "a.7z", "url": "https://hashmob.net/a.7z"}]
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=entries),
            patch("hate_crack.attacks.download_hashmob_archive") as mock_dl,
            patch("builtins.input", return_value="not-a-number"),
        ):
            hashmob_archives_handler(ctx)
        mock_dl.assert_not_called()

    def test_a_downloads_every_archive_in_one_call(self):
        ctx = _make_ctx()
        entries = [
            {"year": "2021", "name": "a.7z", "url": "https://hashmob.net/a.7z"},
            {"year": "2022", "name": "b.7z", "url": "https://hashmob.net/b.7z"},
        ]
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=entries),
            patch("hate_crack.attacks.download_hashmob_archive") as mock_single,
            patch("hate_crack.attacks.download_all_hashmob_archives") as mock_all,
            patch("builtins.input", return_value="a"),
        ):
            hashmob_archives_handler(ctx)
        mock_all.assert_called_once_with(entries)
        mock_single.assert_not_called()

    def test_all_spelled_out_is_accepted(self):
        ctx = _make_ctx()
        entries = [{"year": "2021", "name": "a.7z", "url": "https://hashmob.net/a.7z"}]
        with (
            patch("hate_crack.attacks.list_hashmob_archives", return_value=entries),
            patch("hate_crack.attacks.download_all_hashmob_archives") as mock_all,
            patch("builtins.input", return_value="ALL"),
        ):
            hashmob_archives_handler(ctx)
        mock_all.assert_called_once_with(entries)


class TestDownloadAllHashmobArchives:
    entries = [
        {"name": "a.7z", "url": "https://hashmob.net/a.7z", "file_size": 1000},
        {"name": "b.7z", "url": "https://hashmob.net/b.7z", "file_size": 2000},
    ]

    def test_declining_the_confirmation_downloads_nothing(self, tmp_path):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("hate_crack.api.download_hashmob_archive") as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="n") as mock_input,
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(self.entries)
        mock_dl.assert_not_called()
        assert mock_input.call_count == 1, "one aggregate prompt, not one per archive"
        assert result == {"succeeded": 0, "failed": 0, "skipped": 0}

    def test_confirming_downloads_each_without_reprompting(self, tmp_path):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch(
                "hate_crack.api.download_hashmob_archive", return_value=True
            ) as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y") as mock_input,
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(self.entries)
        assert mock_input.call_count == 1
        assert mock_dl.call_count == 2
        for call, entry in zip(mock_dl.call_args_list, self.entries):
            assert call.args[0] == entry
            assert call.kwargs["confirm"] is False
        assert result == {"succeeded": 2, "failed": 0, "skipped": 0}

    def test_prompt_names_the_count_and_total_size(self, tmp_path, capsys):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("hate_crack.api.download_hashmob_archive", return_value=True),
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="n") as mock_input,
        ):
            stdin.isatty.return_value = True
            download_all_hashmob_archives(self.entries)
        prompt = mock_input.call_args.args[0]
        assert "2 archive" in prompt
        # _format_size is base-1024, so 3000 bytes reads as 2.9 KB.
        assert "2.9 KB" in prompt, f"total of 1000+2000 bytes not in prompt: {prompt}"

    def test_a_failure_does_not_abort_the_rest(self, tmp_path):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch(
                "hate_crack.api.download_hashmob_archive", side_effect=[False, True]
            ) as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y"),
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(self.entries)
        assert mock_dl.call_count == 2
        assert result == {"succeeded": 1, "failed": 1, "skipped": 0}

    def test_an_exception_does_not_abort_the_rest(self, tmp_path):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch(
                "hate_crack.api.download_hashmob_archive",
                side_effect=[RuntimeError("boom"), True],
            ) as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y"),
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(self.entries)
        assert mock_dl.call_count == 2
        assert result == {"succeeded": 1, "failed": 1, "skipped": 0}

    def test_skips_a_complete_local_copy_but_redownloads_a_truncated_one(
        self, tmp_path
    ):
        (tmp_path / "a.7z").write_bytes(b"x" * 1000)
        (tmp_path / "b.7z").write_bytes(b"x" * 5)
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch(
                "hate_crack.api.download_hashmob_archive", return_value=True
            ) as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y"),
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(self.entries)
        assert mock_dl.call_count == 1, "the complete copy should not be re-downloaded"
        assert mock_dl.call_args.args[0] == self.entries[1]
        assert result == {"succeeded": 1, "failed": 0, "skipped": 1}

    def test_non_interactive_context_declines(self, tmp_path):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("hate_crack.api.download_hashmob_archive") as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input") as mock_input,
        ):
            stdin.isatty.return_value = False
            result = download_all_hashmob_archives(self.entries)
        mock_input.assert_not_called()
        mock_dl.assert_not_called()
        assert result == {"succeeded": 0, "failed": 0, "skipped": 0}

    def test_empty_listing_downloads_nothing(self, tmp_path):
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("hate_crack.api.download_hashmob_archive") as mock_dl,
            patch("builtins.input") as mock_input,
        ):
            result = download_all_hashmob_archives([])
        mock_input.assert_not_called()
        mock_dl.assert_not_called()
        assert result == {"succeeded": 0, "failed": 0, "skipped": 0}

    def test_missing_size_hints_still_prompt_and_download(self, tmp_path):
        entries = [{"name": "a.7z", "url": "https://hashmob.net/a.7z"}]
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch(
                "hate_crack.api.download_hashmob_archive", return_value=True
            ) as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y") as mock_input,
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(entries)
        assert "unknown total size" in mock_input.call_args.args[0]
        assert mock_dl.call_count == 1
        assert result == {"succeeded": 1, "failed": 0, "skipped": 0}

    def test_existing_copy_without_a_size_hint_is_skipped(self, tmp_path):
        entries = [{"name": "a.7z", "url": "https://hashmob.net/a.7z"}]
        (tmp_path / "a.7z").write_bytes(b"x" * 7)
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch("hate_crack.api.download_hashmob_archive") as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y"),
        ):
            stdin.isatty.return_value = True
            result = download_all_hashmob_archives(entries)
        mock_dl.assert_not_called()
        assert result == {"succeeded": 0, "failed": 0, "skipped": 1}

    def test_out_dir_overrides_the_wordlists_directory(self, tmp_path):
        out_dir = tmp_path / "elsewhere"
        with (
            patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path)),
            patch(
                "hate_crack.api.download_hashmob_archive", return_value=True
            ) as mock_dl,
            patch("hate_crack.api.sys.stdin") as stdin,
            patch("builtins.input", return_value="y"),
        ):
            stdin.isatty.return_value = True
            download_all_hashmob_archives(self.entries[:1], out_dir=str(out_dir))
        assert mock_dl.call_args.kwargs["out_path"] == os.path.join(
            str(out_dir), "a.7z"
        )


class TestHashmobCombinedLeftHandler:
    def test_no_entries_returns_without_prompting(self):
        ctx = _make_ctx()
        with (
            patch("hate_crack.attacks.list_hashmob_combined_left", return_value=[]),
            patch("builtins.input") as mock_input,
        ):
            hashmob_combined_left_handler(ctx)
        mock_input.assert_not_called()

    def test_selecting_mode_downloads_it(self):
        ctx = _make_ctx()
        files = [{"mode": 1000, "hash_count": 10, "algorithm": "NTLM"}]
        with (
            patch("hate_crack.attacks.list_hashmob_combined_left", return_value=files),
            patch("hate_crack.attacks.download_hashmob_combined_left") as mock_dl,
            patch("builtins.input", return_value="1000"),
        ):
            hashmob_combined_left_handler(ctx)
        mock_dl.assert_called_once_with(1000)

    def test_q_cancels_without_downloading(self):
        ctx = _make_ctx()
        files = [{"mode": 1000, "hash_count": 10, "algorithm": "NTLM"}]
        with (
            patch("hate_crack.attacks.list_hashmob_combined_left", return_value=files),
            patch("hate_crack.attacks.download_hashmob_combined_left") as mock_dl,
            patch("builtins.input", return_value="q"),
        ):
            hashmob_combined_left_handler(ctx)
        mock_dl.assert_not_called()

    def test_non_numeric_mode_does_not_download(self):
        ctx = _make_ctx()
        files = [{"mode": 1000, "hash_count": 10, "algorithm": "NTLM"}]
        with (
            patch("hate_crack.attacks.list_hashmob_combined_left", return_value=files),
            patch("hate_crack.attacks.download_hashmob_combined_left") as mock_dl,
            patch("builtins.input", return_value="not-a-number"),
        ):
            hashmob_combined_left_handler(ctx)
        mock_dl.assert_not_called()
