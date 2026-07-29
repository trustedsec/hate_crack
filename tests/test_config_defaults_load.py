"""Tests for hate_crack.main's config.json.example defaults loader (#155)."""
import json
import os

import pytest


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def test_missing_defaults_file_exits_with_clear_message(main_module, tmp_path, capsys):
    missing_path = str(tmp_path / "config.json.example")

    with pytest.raises(SystemExit) as exc_info:
        main_module._load_config_defaults(missing_path)

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "package installation issue" in captured.out
    assert missing_path in captured.out


def test_dangling_symlink_defaults_file_names_the_cause(main_module, tmp_path, capsys):
    target = tmp_path / "does-not-exist.json"
    link_path = tmp_path / "config.json.example"
    os.symlink(target, link_path)

    with pytest.raises(SystemExit) as exc_info:
        main_module._load_config_defaults(str(link_path))

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "dangling symlink" in captured.out.lower()


def test_malformed_json_defaults_file_exits_with_clear_message(main_module, tmp_path, capsys):
    bad_path = tmp_path / "config.json.example"
    bad_path.write_text("{not valid json")

    with pytest.raises(SystemExit) as exc_info:
        main_module._load_config_defaults(str(bad_path))

    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "invalid JSON" in captured.out


def test_valid_defaults_file_loads_normally(main_module, tmp_path):
    good_path = tmp_path / "config.json.example"
    good_path.write_text(json.dumps({"hcatBin": "hashcat"}))

    result = main_module._load_config_defaults(str(good_path))

    assert result == {"hcatBin": "hashcat"}
