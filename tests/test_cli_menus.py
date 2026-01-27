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
    if alt_text:
        assert menu_text in output or alt_text in output, f"Expected '{menu_text}' or '{alt_text}' in output for flag {flag}"
    else:
        assert menu_text in output, f"Menu text '{menu_text}' not found in output for flag {flag}"
    # Accept returncode 1 for --hashview, since 'q' is not a valid customer ID and triggers an error exit
    if flag == "--hashview":
        assert result.returncode in (0, 1, 130)
    else:
        assert result.returncode == 0 or result.returncode == 130
