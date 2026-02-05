import os
import json
import tempfile
import pytest
from hate_crack.api import HashviewAPI


def get_hashview_config():
    config_path = os.path.join(os.path.dirname(__file__), "..", "config.json")
    with open(config_path, "r") as f:
        config = json.load(f)
    hashview_url = config.get("hashview_url")
    hashview_api_key = config.get("hashview_api_key")
    return hashview_url, hashview_api_key


def test_upload_wordlist_api_mocked(monkeypatch):
    """Test direct API upload of a wordlist file using a mocked API call."""
    hashview_url, hashview_api_key = get_hashview_config()
    api = HashviewAPI(hashview_url or "http://example.com", hashview_api_key or "dummy")

    # Create a temp wordlist file
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("password1\npassword2\n")
        wordlist_path = f.name
    wordlist_name = os.path.basename(wordlist_path)

    class DummyResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "status": 200,
                "type": "message",
                "msg": "Wordlist added",
                "wordlist_id": 123,
            }

    def fake_post(url, data=None, headers=None):
        assert url.endswith(f"/v1/wordlists/add/{wordlist_name}")
        assert headers and headers.get("Content-Type") == "text/plain"
        assert data is not None
        return DummyResponse()

    monkeypatch.setattr(api.session, "post", fake_post)

    upload_result = api.upload_wordlist_file(wordlist_path, wordlist_name)
    assert upload_result is not None
    assert "wordlist_id" in upload_result
    msg = upload_result.get("msg", "").lower()
    assert "uploaded" in msg or "added" in msg

    os.remove(wordlist_path)


@pytest.mark.skipif(
    os.environ.get("HATE_CRACK_RUN_LIVE_HASHVIEW_TESTS") != "1",
    reason="Live Hashview test disabled. Set HATE_CRACK_RUN_LIVE_HASHVIEW_TESTS=1 to run.",
)
def test_upload_wordlist_api_live():
    """Live API upload test; only runs when explicitly enabled."""
    hashview_url, hashview_api_key = get_hashview_config()
    if not hashview_url or not hashview_api_key:
        pytest.skip("Requires hashview_url and hashview_api_key in config.json.")
    api = HashviewAPI(hashview_url, hashview_api_key)

    with tempfile.NamedTemporaryFile(mode="w", delete=False) as f:
        f.write("password1\npassword2\n")
        wordlist_path = f.name
    wordlist_name = os.path.basename(wordlist_path)

    try:
        upload_result = api.upload_wordlist_file(wordlist_path, wordlist_name)
        assert upload_result is not None
        assert "wordlist_id" in upload_result
        msg = upload_result.get("msg", "").lower()
        assert "uploaded" in msg or "added" in msg
    finally:
        os.remove(wordlist_path)
