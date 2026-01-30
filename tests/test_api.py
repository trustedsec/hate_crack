import os
import sys
import types
import pytest
from unittest import mock

import hate_crack.api as api

@pytest.fixture
def fake_file(tmp_path):
    return tmp_path / "testfile.txt"

@pytest.fixture
def patch_dependencies(tmp_path):
    # Patch sanitize_filename to just return the filename
    patch1 = mock.patch("hate_crack.api.sanitize_filename", side_effect=lambda x: x)
    # Patch get_hcat_wordlists_dir to return tmp_path
    patch2 = mock.patch("hate_crack.api.get_hcat_wordlists_dir", return_value=str(tmp_path))
    # Patch extract_with_7z to just return True
    patch3 = mock.patch("hate_crack.api.extract_with_7z", return_value=True)
    # Patch os.replace to do nothing
    patch4 = mock.patch("os.replace")
    # Patch os.makedirs to do nothing
    patch5 = mock.patch("os.makedirs")
    patches = [patch1, patch2, patch3, patch4, patch5]
    for p in patches:
        p.start()
    yield
    for p in patches:
        p.stop()

def make_mock_response(content=b"abc", total=3, status_code=200, endswith='.txt'):
    mock_resp = mock.MagicMock()
    mock_resp.__enter__.return_value = mock_resp
    mock_resp.__exit__.return_value = False
    mock_resp.iter_content = lambda chunk_size: [content]
    mock_resp.headers = {'content-length': str(total)}
    mock_resp.status_code = status_code
    mock_resp.raise_for_status = mock.Mock()
    return mock_resp

def test_download_success(tmp_path, patch_dependencies):
    file_name = "wordlist.txt"
    out_path = str(tmp_path / file_name)
    mock_resp = make_mock_response(content=b"abc", total=3)
    with mock.patch("hate_crack.api.requests.get", return_value=mock_resp):
        with mock.patch("builtins.open", mock.mock_open()) as m_open:
            result = api.download_official_wordlist(file_name, out_path)
            assert result is True
            m_open.assert_called()  # File was opened for writing

def test_download_7z_triggers_extract(tmp_path, patch_dependencies):
    file_name = "archive.7z"
    out_path = str(tmp_path / file_name)
    mock_resp = make_mock_response(content=b"abc", total=3)
    with mock.patch("hate_crack.api.requests.get", return_value=mock_resp):
        with mock.patch("builtins.open", mock.mock_open()):
            with mock.patch("hate_crack.api.extract_with_7z") as m_extract:
                m_extract.return_value = True
                result = api.download_official_wordlist(file_name, out_path)
                assert result is True
                m_extract.assert_called_once()

def test_download_keyboard_interrupt(tmp_path, patch_dependencies):
    file_name = "wordlist.txt"
    out_path = str(tmp_path / file_name)
    # Simulate KeyboardInterrupt in requests.get context manager
    def raise_keyboard_interrupt(*a, **kw):
        raise KeyboardInterrupt()
    with mock.patch("hate_crack.api.requests.get", side_effect=raise_keyboard_interrupt):
        result = api.download_official_wordlist(file_name, out_path)
        assert result is False

def test_download_exception(tmp_path, patch_dependencies):
    file_name = "wordlist.txt"
    out_path = str(tmp_path / file_name)
    # Simulate generic Exception in requests.get context manager
    def raise_exception(*a, **kw):
        raise Exception("fail")
    with mock.patch("hate_crack.api.requests.get", side_effect=raise_exception):
        result = api.download_official_wordlist(file_name, out_path)
        assert result is False

def test_progress_bar_prints(tmp_path, patch_dependencies, capsys):
    file_name = "wordlist.txt"
    out_path = str(tmp_path / file_name)
    # Simulate a file with a known size
    content = b"x" * 8192
    mock_resp = make_mock_response(content=content, total=8192)
    with mock.patch("hate_crack.api.requests.get", return_value=mock_resp):
        with mock.patch("builtins.open", mock.mock_open()):
            result = api.download_official_wordlist(file_name, out_path)
            assert result is True
            captured = capsys.readouterr()
            assert "Downloaded" in captured.out or "Downloaded" in captured.err