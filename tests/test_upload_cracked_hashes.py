import os
import json
import pytest
import tempfile
from unittest.mock import Mock, patch
from hate_crack.api import HashviewAPI, _digest_for_type, _md4


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


def test_ntlm_plaintext_with_leading_space_is_not_skipped(tmp_path):
    """A genuine leading/trailing space in the cracked password must survive
    re-validation — see #244. NTLM of " Newpass4" (leading space) is
    ebc5560e1f9fc1de16638e92c1b52ce2.
    """
    hash_file = tmp_path / "cracked.txt"
    hash_file.write_bytes(b"ebc5560e1f9fc1de16638e92c1b52ce2: Newpass4\n")

    with patch("requests.Session") as mock_session_class:
        mock_session = Mock()
        mock_session_class.return_value = mock_session
        mock_response = Mock()
        mock_response.json.return_value = {"imported": 1}
        mock_response.raise_for_status = Mock()
        mock_session.post.return_value = mock_response

        api = HashviewAPI(base_url="http://example.invalid", api_key="unused")
        result = api.upload_cracked_hashes(str(hash_file), hash_type="1000", validate=True)

        assert result["skipped"] == 0, f"plaintext with leading space should not be skipped, got {result}"
        assert result["uploaded"] == 1, f"should have uploaded 1 hash, got {result}"

        # Verify the plaintext with its leading space was sent to Hashview
        posted_body = mock_session.post.call_args.kwargs["data"]
        assert b" Newpass4" in posted_body, (
            "The leading space in the plaintext must reach Hashview intact, not stripped"
        )
