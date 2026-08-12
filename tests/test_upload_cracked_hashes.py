import os
import json
import pytest
from unittest.mock import Mock, patch, MagicMock
from hate_crack.api import HashviewAPI


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


def test_upload_cracked_hashes_preserves_plaintext_whitespace(tmp_path):
    """A plaintext with leading/trailing spaces must not be flagged as a
    hash/plaintext mismatch — see #244.

    A bare ``.strip()`` on the plaintext field before validation eats
    whitespace that is part of the real password, desyncing it from the
    hash it was validated against and causing a false-positive skip.
    Regression test using synthetic plaintext with padded spaces.
    """
    from hate_crack.api import _digest_for_type

    # Use synthetic plaintext, not a real password
    synthetic_plain = "Synthetic-Example-Xxx"
    padded_plain = " " + synthetic_plain + " "

    # Compute the correct NTLM hash for the padded plaintext
    padded_ntlm = _digest_for_type("1000", padded_plain.encode("utf-8"))

    # Create the cracked hash:plaintext file
    cracked_file = tmp_path / "cracked.txt"
    cracked_file.write_text(f"{padded_ntlm}:{padded_plain}\n")

    # Stub the cache functions to prevent writing to the real ~/.hate_crack directory
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

        assert result["skipped"] == 0, (
            f"plaintext with padded spaces should not be skipped, got {result}"
        )
        assert result["uploaded"] == 1, f"should have uploaded 1 hash, got {result}"

        # Verify the plaintext with its leading/trailing spaces was sent to Hashview intact
        posted_body = api.session.post.call_args.kwargs["data"]
        assert padded_plain.encode() in posted_body, (
            f"The padded plaintext '{padded_plain}' must reach Hashview intact, not stripped"
        )
