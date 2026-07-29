"""Tests for regenerating <hashfile>.out from the POT file (menu option 93)."""

import sys

import pytest

import hate_crack.attacks as attacks
import hate_crack.main as main


def _stub_show(monkeypatch, lines):
    """Make _run_hashcat_show write `lines` to its output path, as hashcat would."""
    calls = []

    def fake_show(hash_type, hash_file, output_path):
        calls.append((hash_type, hash_file, output_path))
        with open(output_path, "w") as fh:
            for line in lines:
                fh.write(line + "\n")

    monkeypatch.setattr(main, "_run_hashcat_show", fake_show)
    return calls


def _load(monkeypatch, tmp_path, existing=None):
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("fb5699c234f878ce6be8182c2d2bcac8\n")
    if existing is not None:
        (tmp_path / "hashes.txt.out").write_text(existing)
    monkeypatch.setattr(main, "hcatHashFile", str(hash_file), raising=False)
    monkeypatch.setattr(main, "hcatHashType", "1000", raising=False)
    return hash_file


def test_overwrites_truncated_out_file(monkeypatch, tmp_path):
    hash_file = _load(monkeypatch, tmp_path, existing="")
    calls = _stub_show(monkeypatch, ["fb5699c234f878ce6be8182c2d2bcac8:PLAINTEXT_A"])

    assert main.restore_from_potfile() is True

    assert len(calls) == 1
    assert calls[0] == ("1000", str(hash_file), f"{hash_file}.out")
    assert (
        tmp_path / "hashes.txt.out"
    ).read_text() == "fb5699c234f878ce6be8182c2d2bcac8:PLAINTEXT_A\n"


def test_creates_out_file_when_absent(monkeypatch, tmp_path):
    _load(monkeypatch, tmp_path)
    _stub_show(monkeypatch, ["aa:PLAINTEXT_B"])
    monkeypatch.setattr("sys.stdin.isatty", lambda: True, raising=False)

    assert main.restore_from_potfile() is True
    assert (tmp_path / "hashes.txt.out").read_text() == "aa:PLAINTEXT_B\n"


def test_prompts_and_overwrites_when_confirmed(monkeypatch, tmp_path, capsys):
    _load(monkeypatch, tmp_path, existing="old:PLAINTEXT_OLD\n")
    calls = _stub_show(monkeypatch, ["new:PLAINTEXT_NEW"])
    monkeypatch.setattr(main.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "y")

    assert main.restore_from_potfile() is True

    assert len(calls) == 1
    assert (tmp_path / "hashes.txt.out").read_text() == "new:PLAINTEXT_NEW\n"
    assert "already contains 1 cracked hash(es)" in capsys.readouterr().out


def test_declining_prompt_leaves_existing_out_intact(monkeypatch, tmp_path):
    _load(monkeypatch, tmp_path, existing="old:PLAINTEXT_OLD\n")
    calls = _stub_show(monkeypatch, ["new:PLAINTEXT_NEW"])
    monkeypatch.setattr(main.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda _prompt="": "n")

    assert main.restore_from_potfile() is False

    assert calls == []
    assert (tmp_path / "hashes.txt.out").read_text() == "old:PLAINTEXT_OLD\n"


def test_non_interactive_overwrites_without_prompting(monkeypatch, tmp_path):
    _load(monkeypatch, tmp_path, existing="old:PLAINTEXT_OLD\n")
    _stub_show(monkeypatch, ["new:PLAINTEXT_NEW"])
    monkeypatch.setattr(main.sys.stdin, "isatty", lambda: False)

    def explode(_prompt=""):
        raise AssertionError("must not prompt when stdin is not a TTY")

    monkeypatch.setattr("builtins.input", explode)

    assert main.restore_from_potfile() is True
    assert (tmp_path / "hashes.txt.out").read_text() == "new:PLAINTEXT_NEW\n"


def test_no_hashfile_loaded_is_reported(monkeypatch, capsys):
    monkeypatch.setattr(main, "hcatHashFile", "", raising=False)
    calls = []
    monkeypatch.setattr(main, "check_potfile", lambda: calls.append(1))

    assert main.restore_from_potfile() is False

    assert calls == []
    assert "No hashfile loaded" in capsys.readouterr().out


def test_attacks_handler_delegates_to_main(capsys):
    class Ctx:
        def __init__(self):
            self.called = False

        def restore_from_potfile(self):
            self.called = True

    ctx = Ctx()
    attacks.restore_potfile_output(ctx)

    assert ctx.called
    assert "REGENERATE .out FROM POT FILE" in capsys.readouterr().out


def test_menu_option_93_registered(hc_module):
    assert "93" in main.get_main_menu_options()
    assert "93" in hc_module.get_main_menu_options()
    labels = dict(main.get_main_menu_items())
    assert labels["93"] == "Regenerate .out from POT file"


def test_menu_item_93_precedes_94_when_hashview_configured(monkeypatch):
    """93 must render before the conditionally-appended Hashview entry.

    get_main_menu_items() appends "94" between the base list and a trailing
    extend(), so an entry placed in that trailing block would display after 94.
    """
    monkeypatch.setattr(main, "hashview_api_key", "dummy-key", raising=False)
    keys = [key for key, _label in main.get_main_menu_items()]

    assert "94" in keys
    assert keys.index("93") < keys.index("94") < keys.index("95")


def test_restore_potfile_flag_rebuilds_existing_out(monkeypatch, tmp_path):
    """--restore-potfile regenerates .out even though the file already exists.

    Without the flag the startup block skips the POT lookup whenever .out is
    present, so this is the behaviour the flag exists to provide.
    """
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("fb5699c234f878ce6be8182c2d2bcac8\n")
    (tmp_path / "hashes.txt.out").write_text("stale:PLAINTEXT_STALE\n")

    calls = []
    monkeypatch.setattr(main, "ascii_art", lambda: None)
    monkeypatch.setattr(main, "check_potfile", lambda: calls.append(1))
    monkeypatch.setattr(
        main, "get_main_menu_options", lambda: {"q": lambda: sys.exit(0)}
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": "q")
    monkeypatch.setattr(
        sys, "argv", ["hate_crack.py", "--restore-potfile", str(hashfile), "1000"]
    )

    with pytest.raises(SystemExit):
        main.main()

    assert calls == [1], "check_potfile() should run despite .out already existing"


def test_startup_skips_restore_without_the_flag(monkeypatch, tmp_path):
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("fb5699c234f878ce6be8182c2d2bcac8\n")
    (tmp_path / "hashes.txt.out").write_text("stale:PLAINTEXT_STALE\n")

    calls = []
    monkeypatch.setattr(main, "ascii_art", lambda: None)
    monkeypatch.setattr(main, "check_potfile", lambda: calls.append(1))
    monkeypatch.setattr(
        main, "get_main_menu_options", lambda: {"q": lambda: sys.exit(0)}
    )
    monkeypatch.setattr("builtins.input", lambda _prompt="": "q")
    monkeypatch.setattr(sys, "argv", ["hate_crack.py", str(hashfile), "1000"])

    with pytest.raises(SystemExit):
        main.main()

    assert calls == []
