from hate_crack.main import EXCLUDED_WORDLIST_EXTENSIONS, list_wordlist_files


class TestExcludedWordlistExtensions:
    def test_contains_7z(self):
        assert ".7z" in EXCLUDED_WORDLIST_EXTENSIONS

    def test_contains_torrent(self):
        assert ".torrent" in EXCLUDED_WORDLIST_EXTENSIONS

    def test_contains_out(self):
        assert ".out" in EXCLUDED_WORDLIST_EXTENSIONS

    def test_is_frozenset(self):
        assert isinstance(EXCLUDED_WORDLIST_EXTENSIONS, frozenset)


class TestListWordlistFiles:
    def _populate(self, directory, names):
        for name in names:
            (directory / name).touch()

    def test_excludes_7z_files(self, tmp_path):
        self._populate(tmp_path, ["rockyou.txt", "archive.7z"])
        result = list_wordlist_files(str(tmp_path))
        assert "archive.7z" not in result
        assert "rockyou.txt" in result

    def test_excludes_torrent_files(self, tmp_path):
        self._populate(tmp_path, ["words.txt", "data.torrent"])
        result = list_wordlist_files(str(tmp_path))
        assert "data.torrent" not in result
        assert "words.txt" in result

    def test_excludes_out_files(self, tmp_path):
        self._populate(tmp_path, ["hashesorg.lst", "results.out"])
        result = list_wordlist_files(str(tmp_path))
        assert "results.out" not in result
        assert "hashesorg.lst" in result

    def test_excludes_ds_store(self, tmp_path):
        self._populate(tmp_path, ["words.dict", ".DS_Store"])
        result = list_wordlist_files(str(tmp_path))
        assert ".DS_Store" not in result
        assert "words.dict" in result

    def test_includes_txt_lst_dict(self, tmp_path):
        names = ["rockyou.txt", "hashesorg.lst", "words.dict"]
        self._populate(tmp_path, names)
        result = list_wordlist_files(str(tmp_path))
        assert result == sorted(names)

    def test_result_is_sorted(self, tmp_path):
        names = ["zebra.txt", "apple.txt", "mango.lst"]
        self._populate(tmp_path, names)
        result = list_wordlist_files(str(tmp_path))
        assert result == sorted(names)

    def test_mixed_files_filters_correctly(self, tmp_path):
        all_files = [
            "rockyou.txt",
            "hashesorg.lst",
            "archive.7z",
            "data.torrent",
            "results.out",
            ".DS_Store",
            "words.dict",
        ]
        self._populate(tmp_path, all_files)
        result = list_wordlist_files(str(tmp_path))
        assert "archive.7z" not in result
        assert "data.torrent" not in result
        assert "results.out" not in result
        assert ".DS_Store" not in result
        assert "rockyou.txt" in result
        assert "hashesorg.lst" in result
        assert "words.dict" in result

    def test_empty_directory(self, tmp_path):
        result = list_wordlist_files(str(tmp_path))
        assert result == []

    def test_only_excluded_files_returns_empty(self, tmp_path):
        self._populate(tmp_path, ["a.7z", "b.torrent", "c.out", ".DS_Store"])
        result = list_wordlist_files(str(tmp_path))
        assert result == []
