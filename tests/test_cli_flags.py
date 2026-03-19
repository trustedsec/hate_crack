import sys

import pytest

import hate_crack.main as hc_main


def _run_main(monkeypatch, argv):
    """Set sys.argv and run hc_main.main(), returning the exit code."""
    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + argv)
    with pytest.raises(SystemExit) as exc:
        hc_main.main()
    return exc.value.code


# ---------------------------------------------------------------------------
# 1. Top-level flags that dispatch to a handler and exit 0
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "argv, handler_attr",
    [
        (["--weakpass"], "weakpass_wordlist_menu"),
        (["--hashmob"], "download_hashmob_wordlists"),
        (["--rules"], "download_hashmob_rules"),
        (["--cleanup"], "cleanup_wordlist_artifacts"),
    ],
)
def test_flag_dispatches_to_handler(monkeypatch, capsys, argv, handler_attr):
    called = []
    monkeypatch.setattr(
        hc_main,
        handler_attr,
        lambda **kw: called.append(kw) or None,
    )
    code = _run_main(monkeypatch, argv)
    assert code == 0
    assert len(called) == 1


def test_download_torrent_flag(monkeypatch, capsys):
    called = []
    monkeypatch.setattr(
        hc_main,
        "download_weakpass_torrent",
        lambda download_torrent, filename, print_fn=print: called.append(filename),
    )
    code = _run_main(monkeypatch, ["--download-torrent", "somefile.txt"])
    assert code == 0
    assert called == ["somefile.txt"]


def test_download_all_torrents_flag(monkeypatch):
    called = []
    monkeypatch.setattr(
        hc_main,
        "download_all_weakpass_torrents",
        lambda fetch_all_wordlists, download_torrent, print_fn=print: called.append(
            True
        ),
    )
    code = _run_main(monkeypatch, ["--download-all-torrents"])
    assert code == 0
    assert called == [True]


def test_hashview_flag(monkeypatch):
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    called = []
    monkeypatch.setattr(hc_main, "hashview_api", lambda: called.append(True))
    code = _run_main(monkeypatch, ["--hashview"])
    assert code == 0
    assert called == [True]


def test_download_hashview_flag(monkeypatch):
    """--download-hashview falls into the menu loop, triggers hashview_api, then exits."""
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    called = []
    monkeypatch.setattr(hc_main, "hashview_api", lambda: called.append(True))
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "1")
    code = _run_main(monkeypatch, ["--download-hashview"])
    assert code == 0
    assert called == [True]


# ---------------------------------------------------------------------------
# 2. --weakpass --rank passthrough
# ---------------------------------------------------------------------------
def test_weakpass_rank_passthrough(monkeypatch):
    called = []
    monkeypatch.setattr(
        hc_main,
        "weakpass_wordlist_menu",
        lambda **kw: called.append(kw),
    )
    code = _run_main(monkeypatch, ["--weakpass", "--rank", "5"])
    assert code == 0
    assert called == [{"rank": 5}]


def test_weakpass_default_rank(monkeypatch):
    called = []
    monkeypatch.setattr(
        hc_main,
        "weakpass_wordlist_menu",
        lambda **kw: called.append(kw),
    )
    code = _run_main(monkeypatch, ["--weakpass"])
    assert code == 0
    assert called == [{"rank": -1}]


# ---------------------------------------------------------------------------
# 3. --potfile-path and --no-potfile-path
# ---------------------------------------------------------------------------
def test_potfile_path_flag(monkeypatch):
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    _run_main(monkeypatch, ["--potfile-path", "/tmp/test.pot"])
    assert hc_main.hcatPotfilePath == "/tmp/test.pot"


def test_no_potfile_path_flag(monkeypatch):
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    _run_main(monkeypatch, ["--no-potfile-path"])
    assert hc_main.hcatPotfilePath == ""


def test_potfile_path_empty_string_reverts_to_default(monkeypatch):
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    _run_main(monkeypatch, ["--potfile-path", ""])
    assert hc_main.hcatPotfilePath == ""


# ---------------------------------------------------------------------------
# 4. --debug flag
# ---------------------------------------------------------------------------
def test_debug_flag(monkeypatch):
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    _run_main(monkeypatch, ["--debug"])
    assert hc_main.debug_mode is True


# ---------------------------------------------------------------------------
# 5. Positional arguments: hashfile and hashtype
# ---------------------------------------------------------------------------
def test_positional_hashfile_and_hashtype(monkeypatch, tmp_path):
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("aabbccdd\n")
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    # Mock the main menu loop to prevent interactive prompts after globals are set
    monkeypatch.setattr(
        hc_main, "get_main_menu_options", lambda: {"q": ("Quit", lambda: sys.exit(0))}
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": "q")
    _run_main(monkeypatch, [str(hashfile), "1000"])
    assert hc_main.hcatHashType == "1000"
    assert hc_main.hcatHashFile is not None


def test_positional_hashfile_only_enters_menu(monkeypatch, tmp_path):
    """With only hashfile (no hashtype), falls through to the interactive menu."""
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("aabbccdd\n")
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    code = _run_main(monkeypatch, [str(hashfile)])
    assert code == 0


def test_no_args_enters_menu(monkeypatch):
    """No arguments falls through to the interactive menu."""
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    code = _run_main(monkeypatch, [])
    assert code == 0


# ---------------------------------------------------------------------------
# 6. Hashview subcommand: download-hashes
# ---------------------------------------------------------------------------
class DummyHashviewAPI:
    def __init__(self, base_url, api_key, debug=False):
        self.calls = []

    def download_left_hashes(self, customer_id, hashfile_id, hash_type=None, potfile_path=None):
        self.calls.append(
            ("download_left_hashes", customer_id, hashfile_id, hash_type)
        )
        return {"output_file": "left.txt", "size": 42}


def test_hashview_download_hashes(monkeypatch, capsys):
    monkeypatch.setattr(hc_main, "HashviewAPI", DummyHashviewAPI)
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    monkeypatch.setattr(hc_main, "hashview_url", "https://hv.example.com")
    code = _run_main(
        monkeypatch,
        [
            "hashview",
            "download-hashes",
            "--customer-id",
            "1",
            "--hashfile-id",
            "2",
            "--hash-type",
            "1000",
        ],
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "42 bytes" in out


# ---------------------------------------------------------------------------
# 7. Hashview upload-hashfile-job with --limit-recovered and --no-notify-email
# ---------------------------------------------------------------------------
class DummyHashviewAPIFull:
    def __init__(self, base_url, api_key, debug=False):
        self.calls = []

    def upload_hashfile(
        self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None
    ):
        self.calls.append(("upload_hashfile", file_path))
        return {"msg": "Hashfile uploaded", "hashfile_id": 456}

    def create_job(
        self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=True
    ):
        self.calls.append(
            ("create_job", limit_recovered, notify_email)
        )
        return {"msg": "Job created", "job_id": 789}


def test_hashview_upload_hashfile_job_flags(monkeypatch, tmp_path, capsys):
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("hash1\n")
    monkeypatch.setattr(hc_main, "HashviewAPI", DummyHashviewAPIFull)
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    monkeypatch.setattr(hc_main, "hashview_url", "https://hv.example.com")
    code = _run_main(
        monkeypatch,
        [
            "hashview",
            "upload-hashfile-job",
            "--file",
            str(hashfile),
            "--customer-id",
            "1",
            "--hash-type",
            "1000",
            "--job-name",
            "TestJob",
            "--limit-recovered",
        ],
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "Hashfile uploaded" in out
    assert "Job created" in out


def test_hashview_upload_hashfile_job_no_notify_email_by_default(
    monkeypatch, tmp_path, capsys
):
    """CLI must not send notify_email - it causes the server to create the job but
    return 'Failed to add job: notify_email is invalid', hiding the created job and
    causing a second job to be created on retry."""
    captured_kwargs: dict = {}

    class TrackingAPI:
        def __init__(self, base_url, api_key, debug=False):
            pass

        def upload_hashfile(
            self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None
        ):
            return {"msg": "Hashfile uploaded", "hashfile_id": 456}

        def create_job(
            self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=None
        ):
            captured_kwargs["notify_email"] = notify_email
            return {"msg": "Job created", "job_id": 789}

    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("hash1\n")
    monkeypatch.setattr(hc_main, "HashviewAPI", TrackingAPI)
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    monkeypatch.setattr(hc_main, "hashview_url", "https://hv.example.com")
    code = _run_main(
        monkeypatch,
        [
            "hashview",
            "upload-hashfile-job",
            "--file",
            str(hashfile),
            "--customer-id",
            "1",
            "--hash-type",
            "1000",
            "--job-name",
            "TestJob",
        ],
    )
    assert code == 0
    assert captured_kwargs["notify_email"] is None


def test_hashview_upload_hashfile_job_error_response_exits_nonzero(
    monkeypatch, tmp_path, capsys
):
    """When create_job returns an error response (no job_id), exit code must be 1
    and output must show ✗ Error with a hint to check the Hashview UI."""

    class ErrorJobAPI:
        def __init__(self, base_url, api_key, debug=False):
            pass

        def upload_hashfile(
            self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None
        ):
            return {"msg": "Hashfile uploaded", "hashfile_id": 456}

        def create_job(
            self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=None
        ):
            return {
                "msg": "Failed to add job: 'notify_email' is an invalid keyword argument for JobNotifications"
            }

    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("hash1\n")
    monkeypatch.setattr(hc_main, "HashviewAPI", ErrorJobAPI)
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    monkeypatch.setattr(hc_main, "hashview_url", "https://hv.example.com")
    code = _run_main(
        monkeypatch,
        [
            "hashview",
            "upload-hashfile-job",
            "--file",
            str(hashfile),
            "--customer-id",
            "1",
            "--hash-type",
            "1000",
            "--job-name",
            "TestJob",
        ],
    )
    assert code == 1
    out = capsys.readouterr().out
    assert "✗ Error" in out
    assert "Job ID:" not in out
    assert "Check the Hashview UI before retrying" in out


# ---------------------------------------------------------------------------
# 8. Argparse error cases (exit 2)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "argv",
    [
        ["--download-torrent"],  # missing filename
        ["hashview", "upload-cracked"],  # missing --file
        ["--potfile-path"],  # missing path argument
    ],
)
def test_argparse_missing_required_args(monkeypatch, argv):
    monkeypatch.setattr(hc_main, "hashview_api_key", "dummy")
    monkeypatch.setattr(hc_main, "hashview_url", "https://hv.example.com")
    code = _run_main(monkeypatch, argv)
    assert code == 2


def test_potfile_path_and_no_potfile_path_conflict(monkeypatch):
    """Both --potfile-path and --no-potfile-path should still parse (not mutually exclusive in argparse)."""
    monkeypatch.setattr(hc_main, "ascii_art", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "5")
    # --potfile-path wins because it's checked second in the dispatch logic
    code = _run_main(monkeypatch, ["--potfile-path", "/tmp/test.pot", "--no-potfile-path"])
    assert code == 0
    assert hc_main.hcatPotfilePath == "/tmp/test.pot"
