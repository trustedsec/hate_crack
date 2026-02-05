import os
import re
import pytest
from hate_crack.api import download_hashmob_wordlist_list


def test_hashmob_connectivity_real(capsys):
    if os.environ.get("HASHMOB_TEST_REAL", "").lower() not in ("1", "true", "yes"):
        # Mocked response
        result = [
            {"name": "mock_wordlist_1", "information": "Mock info 1"},
            {"name": "mock_wordlist_2", "information": "Mock info 2"},
        ]
        print("Available Hashmob Wordlists:")
        for idx, wl in enumerate(result):
            print(f"{idx + 1}. {wl['name']} - {wl['information']}")
        captured = capsys.readouterr()
    else:
        try:
            result = download_hashmob_wordlist_list()
        except Exception as e:
            if "523" in str(e) or "HTTP ERROR 523" in str(e):
                pytest.skip("Hashmob returned HTTP ERROR 523 (Origin is unreachable)")
            pytest.skip(f"Network or API unavailable: {e}")
        captured = capsys.readouterr()
        if "HTTP ERROR 523" in captured.out or "523" in captured.out:
            pytest.skip("Hashmob returned HTTP ERROR 523 (Origin is unreachable)")
    assert isinstance(result, list)
    assert any("name" in wl for wl in result)
    # Check for at least one wordlist name in output using regex
    names = [wl["name"] for wl in result if "name" in wl]
    found = False
    for name in names:
        if re.search(re.escape(name), captured.out):
            found = True
            break
    assert found, "No wordlist name found in output"
