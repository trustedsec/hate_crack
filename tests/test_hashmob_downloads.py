from unittest.mock import MagicMock, patch

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
