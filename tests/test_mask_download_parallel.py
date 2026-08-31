import os
from unittest.mock import MagicMock, patch

from hate_crack.api import list_and_download_hashmob_masks


def _make_masks(names):
    return [{"file_name": n} for n in names]


def _patch_stdin_tty():
    mock_stdin = MagicMock()
    mock_stdin.isatty.return_value = True
    return patch("hate_crack.api.sys.stdin", mock_stdin)


class TestListAndDownloadHashmobMasksAllFiles:
    def test_downloads_all_masks_when_selection_is_a(self, tmp_path):
        masks = _make_masks(
            ["a.hcmask", "b.hcmask", "c.hcmask", "d.hcmask", "e.hcmask"]
        )
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        assert mock_dl.call_count == 5
        downloaded = {call.args[0] for call in mock_dl.call_args_list}
        assert downloaded == {
            "a.hcmask",
            "b.hcmask",
            "c.hcmask",
            "d.hcmask",
            "e.hcmask",
        }

    def test_output_path_is_inside_masks_dir(self, tmp_path):
        masks = _make_masks(["sample.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        captured_paths = []

        def capture(file_name, out_path):
            captured_paths.append(out_path)

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask", side_effect=capture),
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        assert len(captured_paths) == 1
        assert captured_paths[0].startswith(masks_dir)

    def test_success_count_reported(self, tmp_path, capsys):
        masks = _make_masks(["x.hcmask", "y.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask"),
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        out = capsys.readouterr().out
        assert "2 succeeded" in out
        assert "0 failed" in out

    def test_default_masks_dir_is_hate_path_masks(self, tmp_path):
        masks = _make_masks(["sample.hcmask"])
        captured_paths = []

        def capture(file_name, out_path):
            captured_paths.append(out_path)

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask", side_effect=capture),
            patch("hate_crack.api._get_hate_path", return_value=str(tmp_path)),
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks()

        assert len(captured_paths) == 1
        assert captured_paths[0] == os.path.join(
            str(tmp_path), "masks", "sample.hcmask"
        )


class TestListAndDownloadHashmobMasksSkipping:
    def test_skips_already_downloaded_files(self, tmp_path):
        masks = _make_masks(
            [
                "existing.hcmask",
                "new1.hcmask",
                "new2.hcmask",
                "also_existing.hcmask",
                "new3.hcmask",
            ]
        )
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)
        (tmp_path / "masks" / "existing.hcmask").touch()
        (tmp_path / "masks" / "also_existing.hcmask").touch()

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        assert mock_dl.call_count == 3
        downloaded = {call.args[0] for call in mock_dl.call_args_list}
        assert downloaded == {"new1.hcmask", "new2.hcmask", "new3.hcmask"}

    def test_skip_prints_message(self, tmp_path, capsys):
        masks = _make_masks(["existing.hcmask", "new.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)
        (tmp_path / "masks" / "existing.hcmask").touch()

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask"),
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        out = capsys.readouterr().out
        assert "Skipping" in out
        assert "existing.hcmask" in out

    def test_all_already_downloaded_does_nothing(self, tmp_path):
        masks = _make_masks(["m1.hcmask", "m2.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)
        (tmp_path / "masks" / "m1.hcmask").touch()
        (tmp_path / "masks" / "m2.hcmask").touch()

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        mock_dl.assert_not_called()


class TestListAndDownloadHashmobMasksSelectionParsing:
    def test_comma_and_range_selection(self, tmp_path):
        masks = _make_masks([f"m{i}.hcmask" for i in range(1, 8)])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
            _patch_stdin_tty(),
            patch("builtins.input", return_value="1,3,5-7"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        downloaded = {call.args[0] for call in mock_dl.call_args_list}
        assert downloaded == {
            "m1.hcmask",
            "m3.hcmask",
            "m5.hcmask",
            "m6.hcmask",
            "m7.hcmask",
        }


class TestListAndDownloadHashmobMasksFailures:
    def test_failed_download_reported_in_count(self, tmp_path, capsys):
        masks = _make_masks(["good.hcmask", "bad.hcmask", "also_good.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        def side_effect(file_name, out_path):
            if file_name == "bad.hcmask":
                raise RuntimeError("network error")

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask", side_effect=side_effect),
            _patch_stdin_tty(),
            patch("builtins.input", return_value="a"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        out = capsys.readouterr().out
        assert "2 succeeded" in out
        assert "1 failed" in out


class TestListAndDownloadHashmobMasksEmptyAndQuit:
    def test_returns_early_when_masks_list_empty(self, tmp_path):
        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=[]),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
        ):
            list_and_download_hashmob_masks(masks_dir=str(tmp_path))

        mock_dl.assert_not_called()

    def test_quit_selection_downloads_nothing(self, tmp_path):
        masks = _make_masks(["m.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
            _patch_stdin_tty(),
            patch("builtins.input", return_value="q"),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        mock_dl.assert_not_called()

    def test_non_tty_returns_without_prompting(self, tmp_path):
        masks = _make_masks(["m.hcmask"])
        masks_dir = str(tmp_path / "masks")
        os.makedirs(masks_dir)

        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = False

        with (
            patch("hate_crack.api.download_hashmob_mask_list", return_value=masks),
            patch("hate_crack.api.download_hashmob_mask") as mock_dl,
            patch("hate_crack.api.sys.stdin", mock_stdin),
        ):
            list_and_download_hashmob_masks(masks_dir=masks_dir)

        mock_dl.assert_not_called()
