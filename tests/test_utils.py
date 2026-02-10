import logging
import os
import importlib


from hate_crack import api
from hate_crack import cli
from hate_crack import formatting


def test_resolve_path_none_and_expand():
    assert cli.resolve_path("") is None
    resolved = cli.resolve_path("~")
    assert resolved is not None
    assert os.path.isabs(resolved)


def test_setup_logging_adds_single_streamhandler(tmp_path):
    logger = logging.getLogger("hate_crack_test")
    logger.handlers.clear()
    cli.setup_logging(logger, str(tmp_path), debug_mode=True)
    cli.setup_logging(logger, str(tmp_path), debug_mode=True)

    stream_handlers = [
        h
        for h in logger.handlers
        if isinstance(h, logging.StreamHandler)
        and not isinstance(h, logging.FileHandler)
    ]
    assert len(stream_handlers) == 1
    file_handlers = [h for h in logger.handlers if isinstance(h, logging.FileHandler)]
    assert file_handlers == []

    logger.handlers.clear()


def test_print_multicolumn_list_truncates(capsys, monkeypatch):
    # Avoid patching os.get_terminal_size (pytest uses it internally).
    monkeypatch.setattr(formatting, "_terminal_width", lambda default=120: 10)
    formatting.print_multicolumn_list(
        "Title",
        ["abcdefghijk"],
        min_col_width=1,
        max_col_width=10,
    )
    captured = capsys.readouterr()
    assert "..." in captured.out


def test_print_multicolumn_list_empty_entries(capsys):
    formatting.print_multicolumn_list("Empty", [])
    captured = capsys.readouterr()
    assert "(none)" in captured.out


def test_get_hcat_wordlists_dir_from_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text('{"hcatWordlists": "wordlists"}')

    monkeypatch.setattr(api, "_resolve_config_path", lambda: str(config_path))
    result = api.get_hcat_wordlists_dir()

    assert result == str(tmp_path / "wordlists")
    assert os.path.isdir(result)


def test_get_hcat_wordlists_dir_fallback_cwd(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_resolve_config_path", lambda: None)
    monkeypatch.chdir(tmp_path)

    result = api.get_hcat_wordlists_dir()

    assert result == str(tmp_path / "wordlists")
    assert os.path.isdir(result)


def test_get_rules_dir_from_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.json"
    config_path.write_text('{"rules_directory": "rules"}')

    monkeypatch.setattr(api, "_resolve_config_path", lambda: str(config_path))
    result = api.get_rules_dir()

    assert result == str(tmp_path / "rules")
    assert os.path.isdir(result)


def test_get_rules_dir_fallback_cwd(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "_resolve_config_path", lambda: None)
    monkeypatch.chdir(tmp_path)

    result = api.get_rules_dir()

    assert result == str(tmp_path / "rules")
    assert os.path.isdir(result)


def test_cleanup_torrent_files_removes_only_torrents(tmp_path):
    torrent = tmp_path / "a.torrent"
    keep = tmp_path / "b.txt"
    torrent.write_text("data")
    keep.write_text("data")

    api.cleanup_torrent_files(directory=str(tmp_path))

    assert not torrent.exists()
    assert keep.exists()


def test_cleanup_torrent_files_missing_dir(capsys, tmp_path):
    missing = tmp_path / "missing"
    api.cleanup_torrent_files(directory=str(missing))
    captured = capsys.readouterr()
    assert "Failed to cleanup torrent files" in captured.out


def test_register_torrent_cleanup_idempotent(monkeypatch):
    calls = []

    def fake_register(fn):
        calls.append(fn)

    monkeypatch.setattr(api, "_TORRENT_CLEANUP_REGISTERED", False)
    monkeypatch.setattr("atexit.register", fake_register)

    api.register_torrent_cleanup()
    api.register_torrent_cleanup()

    assert len(calls) == 1


def test_line_count_and_write_helpers(tmp_path, monkeypatch):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    from hate_crack import main as main_module

    importlib.reload(main_module)

    input_path = tmp_path / "input.txt"
    input_path.write_text("a:b:c\nno-delim\n1:2:3\n")
    out_delimited = tmp_path / "out_delimited.txt"
    out_unique = tmp_path / "out_unique.txt"

    assert main_module.lineCount(str(input_path)) == 3
    assert main_module.lineCount(str(tmp_path / "missing.txt")) == 0

    assert (
        main_module._write_delimited_field(str(input_path), str(out_delimited), 2)
        is True
    )
    assert out_delimited.read_text().splitlines() == ["b", "2"]
    assert (
        main_module._write_delimited_field(
            str(tmp_path / "missing.txt"), str(out_delimited), 2
        )
        is False
    )

    class FakePopen:
        def __init__(self, args, stdin=None, stdout=None, text=None):
            self.stdin = FakeStdin(self)
            self._stdout = stdout
            self._data = None

        def wait(self):
            for line in sorted(set(self._data)):
                self._stdout.write(line + "\n")
            return 0

    class FakeStdin:
        def __init__(self, popen):
            self._popen = popen
            self._lines = []

        def write(self, data):
            self._lines.append(data.rstrip("\n"))

        def close(self):
            self._popen._data = self._lines

    monkeypatch.setattr(main_module.subprocess, "Popen", FakePopen)

    assert (
        main_module._write_field_sorted_unique(str(input_path), str(out_unique), 2)
        is True
    )
    assert out_unique.read_text().splitlines() == ["2", "b"]


def test_get_customer_hashfiles_with_hashtype_filters(monkeypatch):
    hv = api.HashviewAPI("https://example", "key")
    monkeypatch.setattr(
        hv,
        "get_customer_hashfiles",
        lambda customer_id: [
            {"customer_id": customer_id, "hashtype": "1000"},
            {"customer_id": customer_id, "hash_type": "0"},
        ],
    )

    matches = hv.get_customer_hashfiles_with_hashtype(1, target_hashtype="1000")
    assert len(matches) == 1
    assert matches[0]["hashtype"] == "1000"

    none = hv.get_customer_hashfiles_with_hashtype(1, target_hashtype="999")
    assert none == []
