import subprocess
import sys
import os
import pytest

HATE_CRACK_SCRIPT = os.path.join(os.path.dirname(__file__), '..', 'hate_crack.py')

@pytest.mark.parametrize("flag,menu_text,alt_text", [
    ("--hashview", "Available Customers", None),
    ("--weakpass", "Available Wordlists", None),
    ("--hashmob", "Official Hashmob Wordlists", None),
])
def test_direct_menu_flags(monkeypatch, flag, menu_text, alt_text):
    # Only check external services if explicitly enabled
    if flag == "--hashmob" and not os.environ.get('HASHMOB_TEST_REAL', '').lower() in ('1', 'true', 'yes'):
        pytest.skip("Skipping --hashmob test unless HASHMOB_TEST_REAL is set.")
    if flag == "--hashview" and not os.environ.get('HASHVIEW_TEST_REAL', '').lower() in ('1', 'true', 'yes'):
        pytest.skip("Skipping --hashview test unless HASHVIEW_TEST_REAL is set.")
    if flag == "--weakpass" and not os.environ.get('WEAKPASS_TEST_REAL', '').lower() in ('1', 'true', 'yes'):
        pytest.skip("Skipping --weakpass test unless WEAKPASS_TEST_REAL is set.")
    cli_cmd = [sys.executable, HATE_CRACK_SCRIPT, flag]
    def fake_input(prompt):
        return 'q'
    monkeypatch.setattr('builtins.input', fake_input)
    result = subprocess.run(
        cli_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env={**os.environ, 'PYTHONUNBUFFERED': '1'}
    )
    output = result.stdout + result.stderr
    # If Hashmob is down, skip the test for --hashmob
    if flag == "--hashmob" and ("523" in output or "Server Error" in output or "Error listing official wordlists" in output):
        pytest.skip("Hashmob is down or unreachable (error 523 or server error)")
    if alt_text:
        assert menu_text in output or alt_text in output, f"Expected '{menu_text}' or '{alt_text}' in output for flag {flag}"
    else:
        assert menu_text in output, f"Menu text '{menu_text}' not found in output for flag {flag}"
    # Accept returncode 1 for --hashview, since 'q' is not a valid customer ID and triggers an error exit
    if flag == "--hashview":
        assert result.returncode in (0, 1, 130)
    else:
        assert result.returncode == 0 or result.returncode == 130
