import sys

import pytest


def test_cli_weakpass_exits(hc_module, monkeypatch, capsys):
    hc = hc_module
    monkeypatch.setattr(hc, "weakpass_wordlist_menu", lambda **kwargs: print("weakpass_wordlist_menu called"))
    monkeypatch.setattr(sys, "argv", ["hate_crack.py", "--weakpass"])
    with pytest.raises(SystemExit) as excinfo:
        hc.main()
    assert excinfo.value.code == 0
    captured = capsys.readouterr()
    assert "weakpass_wordlist_menu called" in captured.out
