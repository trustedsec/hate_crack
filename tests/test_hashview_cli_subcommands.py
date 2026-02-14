import sys
import pytest

import hate_crack.main as hc_main


class DummyHashviewAPI:
    def __init__(self, base_url, api_key, debug=False):
        self.base_url = base_url
        self.api_key = api_key
        self.debug = debug
        self.calls = []

    def upload_cracked_hashes(self, file_path, hash_type="1000"):
        self.calls.append(("upload_cracked_hashes", file_path, hash_type))
        return {"msg": "Cracked hashes uploaded", "count": 2}

    def upload_wordlist_file(self, wordlist_path, wordlist_name=None):
        self.calls.append(("upload_wordlist_file", wordlist_path, wordlist_name))
        return {"msg": "Wordlist uploaded", "wordlist_id": 123}

    def download_left_hashes(self, customer_id, hashfile_id, output_file=None):
        self.calls.append(
            ("download_left_hashes", customer_id, hashfile_id, output_file)
        )
        return {
            "output_file": output_file or f"left_{customer_id}_{hashfile_id}.txt",
            "size": 10,
        }

    def upload_hashfile(
        self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None
    ):
        self.calls.append(
            (
                "upload_hashfile",
                file_path,
                customer_id,
                hash_type,
                file_format,
                hashfile_name,
            )
        )
        return {"msg": "Hashfile uploaded", "hashfile_id": 456}

    def create_job(
        self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=True
    ):
        self.calls.append(
            (
                "create_job",
                name,
                hashfile_id,
                customer_id,
                limit_recovered,
                notify_email,
            )
        )
        return {"msg": "Job created", "job_id": 789}


@pytest.fixture
def _patch_hashview(monkeypatch):
    monkeypatch.setattr(hc_main, "HashviewAPI", DummyHashviewAPI)
    hc_main.hashview_api_key = "dummy"
    hc_main.hashview_url = "https://hashview.example.com"


def _run_main_with_args(monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["hate_crack.py"] + args)
    with pytest.raises(SystemExit) as excinfo:
        hc_main.main()
    return excinfo.value.code


def test_hashview_cli_upload_cracked(_patch_hashview, monkeypatch, tmp_path, capsys):
    cracked_file = tmp_path / "cracked.out"
    cracked_file.write_text("hash:pass\n")
    code = _run_main_with_args(
        monkeypatch,
        [
            "hashview",
            "upload-cracked",
            "--file",
            str(cracked_file),
            "--hash-type",
            "1000",
        ],
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Cracked hashes uploaded" in captured.out


def test_hashview_cli_upload_wordlist(_patch_hashview, monkeypatch, tmp_path, capsys):
    wordlist_file = tmp_path / "wordlist.txt"
    wordlist_file.write_text("password\n")
    code = _run_main_with_args(
        monkeypatch,
        [
            "hashview",
            "upload-wordlist",
            "--file",
            str(wordlist_file),
            "--name",
            "TestWordlist",
        ],
    )
    captured = capsys.readouterr()
    assert code == 0
    assert "Wordlist uploaded" in captured.out


def test_hashview_cli_upload_hashfile_job(
    _patch_hashview, monkeypatch, tmp_path, capsys
):
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("hash1\n")
    code = _run_main_with_args(
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
    captured = capsys.readouterr()
    assert code == 0
    assert "Hashfile uploaded" in captured.out
    assert "Job created" in captured.out
