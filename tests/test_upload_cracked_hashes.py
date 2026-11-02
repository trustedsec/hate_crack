import os
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from hate_crack.api import HashviewAPI
from types import SimpleNamespace


def get_hashview_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    hashview_url = config.get("hashview_url")
    hashview_api_key = config.get("hashview_api_key")
    return hashview_url, hashview_api_key


RUN_LIVE = os.environ.get("HATE_CRACK_RUN_LIVE_TESTS") == "1"


@pytest.mark.skipif(
    not RUN_LIVE or not get_hashview_config()[0] or not get_hashview_config()[1],
    reason="Requires HATE_CRACK_RUN_LIVE_TESTS=1 and hashview_url/hashview_api_key in config.json.",
)
def test_upload_cracked_hashes_from_file():
    hashview_url, hashview_api_key = get_hashview_config()
    api = HashviewAPI(hashview_url, hashview_api_key)

    file_path = os.path.join(os.path.dirname(__file__), "..", "1.out")
    if not os.path.isfile(file_path):
        pytest.skip("1.out not found in repo root.")

    result = api.upload_cracked_hashes(file_path, hash_type="1000")
    assert result is not None
    assert result.get("type") != "Error"


@pytest.fixture
def padded_whitespace_upload(tmp_path):
    """Sobe um hash cujo plaintext tem espaços nas pontas; devolve o resultado e o corpo enviado."""
    from hate_crack.api import _digest_for_type

    synthetic_plain = "Synthetic-Example-Xxx"
    padded_plain = " " + synthetic_plain + " "
    padded_ntlm = _digest_for_type("1000", padded_plain.encode("utf-8"))

    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text(f"{padded_ntlm}:{padded_plain}\n")

    with (
        patch("hate_crack.api.load_cache", return_value={}),
        patch("hate_crack.api.append_to_cache"),
        patch("requests.Session"),
    ):
        api = HashviewAPI(base_url="http://example.invalid", api_key="unused")
        api.session = MagicMock()
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(
            str(cracked_file), hash_type="1000", validate=True
        )
        posted_body = api.session.post.call_args.kwargs["data"]

    return SimpleNamespace(result=result, posted_body=posted_body, padded_plain=padded_plain)


def test_padded_plaintext_is_not_skipped(padded_whitespace_upload):
    """Plaintext com espaços nas pontas não é pulado na validação."""
    assert padded_whitespace_upload.result["skipped"] == 0
    assert padded_whitespace_upload.result["uploaded"] == 1


def test_padded_plaintext_reaches_hashview_intact(padded_whitespace_upload):
    """Os espaços do plaintext chegam intactos ao Hashview (não são removidos)."""
    c = padded_whitespace_upload
    assert c.padded_plain.encode() in c.posted_body

def _double_encode(text):
    """Reproduce the pre-07c2f15 corruption: valid UTF-8 read as latin-1,
    then re-encoded as UTF-8. Mirrors _wire_field_bytes' old bug so tests can
    synthesize the exact corruption shape without touching real data."""
    return text.encode("utf-8").decode("latin-1").encode("utf-8").decode("utf-8")


@pytest.fixture
def double_encoded_repair_upload(tmp_path):
    """Sobe um plaintext corrompido por double-encode; devolve resultado, corpo e os plaintexts."""
    from hate_crack.api import _digest_for_type

    real_plain = "Synthetic-Exámpleó123+"  # non-ASCII, não é senha real
    ntlm = _digest_for_type("1000", real_plain.encode("utf-8"))
    corrupted_plain = _double_encode(real_plain)
    assert corrupted_plain != real_plain  # sanidade: o double-encode mudou o texto

    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text(f"{ntlm}:{corrupted_plain}\n", encoding="utf-8")

    with (
        patch("hate_crack.api.load_cache", return_value={}),
        patch("hate_crack.api.append_to_cache"),
        patch("requests.Session"),
    ):
        api = HashviewAPI(base_url="http://example.invalid", api_key="unused")
        api.session = MagicMock()
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(
            str(cracked_file), hash_type="1000", validate=True
        )
        posted_body = api.session.post.call_args.kwargs["data"]

    return SimpleNamespace(
        result=result, posted_body=posted_body,
        real_plain=real_plain, corrupted_plain=corrupted_plain,
    )


def test_double_encoded_line_is_repaired_not_skipped(double_encoded_repair_upload):
    """A linha corrompida é reparada e contabilizada (não pulada)."""
    r = double_encoded_repair_upload.result
    assert r["skipped"] == 0
    assert r["uploaded"] == 1
    assert r.get("repaired") == 1


def test_repaired_plaintext_is_what_gets_sent(double_encoded_repair_upload):
    """O plaintext reparado (real) é enviado; o corrompido não."""
    c = double_encoded_repair_upload
    assert c.real_plain.encode("utf-8") in c.posted_body
    assert c.corrupted_plain.encode("utf-8") not in c.posted_body

def test_upload_quarantines_unrecoverable_invalid_plaintext(tmp_path):
    """A plaintext that fails validation and isn't the known double-encoding
    corruption is written to a dedicated rejected file instead of only being
    printed and dropped."""
    from hate_crack.api import _digest_for_type

    genuinely_wrong_hash = "0" * 32
    genuinely_wrong_plain = "not-the-real-password"

    # A second, genuinely valid pair so the file isn't "nothing to upload"
    # (a separate, already-covered error path) -- this test is only about
    # the quarantine behavior for the bad line.
    good_plain = "Synthetic-Example-Good"
    good_hash = _digest_for_type("1000", good_plain.encode("utf-8"))

    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text(
        f"{genuinely_wrong_hash}:{genuinely_wrong_plain}\n{good_hash}:{good_plain}\n"
    )

    with (
        patch("hate_crack.api.load_cache", return_value={}),
        patch("hate_crack.api.append_to_cache"),
        patch("requests.Session"),
    ):
        api = HashviewAPI(base_url="http://example.invalid", api_key="unused")
        api.session = MagicMock()
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        result = api.upload_cracked_hashes(
            str(cracked_file), hash_type="1000", validate=True
        )

        assert result["uploaded"] == 1
        assert result["skipped"] == 1
        assert result.get("repaired", 0) == 0

        rejected_path = cracked_file.with_name(cracked_file.name + ".rejected")
        assert rejected_path.is_file(), (
            "skipped lines must be preserved in a dedicated file"
        )
        rejected_contents = rejected_path.read_text()
        assert genuinely_wrong_hash in rejected_contents
        assert genuinely_wrong_plain in rejected_contents


def test_upload_potfile_path_repairs_and_strips_bad_potfile_entries(tmp_path):
    """When given the local hashcat potfile's path, upload_cracked_hashes
    fixes a repairable entry in place and removes an unrecoverable one --
    otherwise hashcat keeps blindly replaying the bad entry on every future
    run against that hash, since it never re-verifies a potfile plaintext.
    """
    from hate_crack.api import _digest_for_type

    real_plain = "Synthetic-Repáir99+"
    ntlm_repairable = _digest_for_type("1000", real_plain.encode("utf-8"))
    corrupted_plain = _double_encode(real_plain)

    unrecoverable_hash = "1" * 32
    unrecoverable_plain = "still-wrong"

    untouched_hash = "2" * 32
    untouched_plain = "leave-me-alone"

    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text(
        f"{ntlm_repairable}:{corrupted_plain}\n"
        f"{unrecoverable_hash}:{unrecoverable_plain}\n",
        encoding="utf-8",
    )

    potfile = tmp_path / "hashcat.potfile"
    potfile.write_text(
        f"{ntlm_repairable}:{corrupted_plain}\n"
        f"{unrecoverable_hash}:{unrecoverable_plain}\n"
        f"{untouched_hash}:{untouched_plain}\n",
        encoding="utf-8",
    )

    with (
        patch("hate_crack.api.load_cache", return_value={}),
        patch("hate_crack.api.append_to_cache"),
        patch("requests.Session"),
    ):
        api = HashviewAPI(base_url="http://example.invalid", api_key="unused")
        api.session = MagicMock()
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        api.session.post.return_value = mock_response

        api.upload_cracked_hashes(
            str(cracked_file),
            hash_type="1000",
            validate=True,
            potfile_path=str(potfile),
        )

    potfile_lines = potfile.read_text(encoding="utf-8").splitlines()
    assert f"{ntlm_repairable}:{real_plain}" in potfile_lines, (
        "the repaired plaintext must replace the corrupted one in the potfile"
    )
    assert not any(line.startswith(unrecoverable_hash) for line in potfile_lines), (
        "an unrecoverable bad entry must be stripped from the potfile"
    )
    assert f"{untouched_hash}:{untouched_plain}" in potfile_lines, (
        "an unrelated, valid potfile entry must be left alone"
    )
