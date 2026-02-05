import os
import json
import pytest
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
