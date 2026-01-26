from pathlib import Path


def test_generate_session_id_sanitizes(hc_module):
    hc = hc_module
    hc.hcatHashFile = "/tmp/my hash@file(1).txt"
    assert hc.generate_session_id() == "my_hash_file_1_"


def test_line_count(hc_module, tmp_path):
    hc = hc_module
    test_file = tmp_path / "lines.txt"
    test_file.write_text("a\nb\nc\n", encoding="utf-8")
    assert hc.lineCount(str(test_file)) == 3


def test_verify_wordlist_dir_resolves(hc_module, tmp_path):
    hc = hc_module
    directory = tmp_path / "wordlists"
    directory.mkdir()
    wordlist = directory / "list.txt"
    wordlist.write_text("one\n", encoding="utf-8")
    assert hc.verify_wordlist_dir(str(directory), "list.txt") == str(wordlist)


def test_verify_wordlist_dir_prefers_absolute(hc_module, tmp_path):
    hc = hc_module
    wordlist = tmp_path / "absolute.txt"
    wordlist.write_text("one\n", encoding="utf-8")
    assert hc.verify_wordlist_dir("/does/not/matter", str(wordlist)) == str(wordlist)


def test_convert_hex(hc_module, tmp_path):
    hc = hc_module
    data = "$HEX[68656c6c6f]\nplain\n"
    infile = tmp_path / "hex.txt"
    infile.write_text(data, encoding="utf-8")
    assert hc.convert_hex(str(infile)) == ["hello", "plain"]
