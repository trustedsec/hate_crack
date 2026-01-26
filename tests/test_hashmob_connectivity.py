import re
import pytest
from hate_crack.api import download_hashmob_wordlist_list


def test_hashmob_connectivity_real(capsys):
    try:
        result = download_hashmob_wordlist_list()
    except Exception as e:
        pytest.skip(f"Network or API unavailable: {e}")
    assert isinstance(result, list)
    assert any('name' in wl for wl in result)
    captured = capsys.readouterr()
    # Check for at least one wordlist name in output using regex
    names = [wl['name'] for wl in result if 'name' in wl]
    found = False
    for name in names:
        if re.search(re.escape(name), captured.out):
            found = True
            break
    assert found, "No wordlist name found in output"
