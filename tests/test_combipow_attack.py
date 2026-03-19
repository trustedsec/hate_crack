import importlib
import importlib.util
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

os.environ["HATE_CRACK_SKIP_INIT"] = "1"

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _load_attacks():
    """Import hate_crack.attacks with SKIP_INIT set."""
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    import hate_crack.attacks as attacks  # noqa: PLC0415

    return attacks


def _load_cli():
    spec = importlib.util.spec_from_file_location(
        "hate_crack_cli", PROJECT_ROOT / "hate_crack.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def cli():
    return _load_cli()


def _make_ctx(hash_type="1000", hash_file="/tmp/hashes.txt"):
    ctx = MagicMock()
    ctx.hcatHashType = hash_type
    ctx.hcatHashFile = hash_file
    return ctx


# --- Menu presence tests ---

def test_combipow_crack_in_main_menu(cli):
    options = cli.get_main_menu_options()
    assert "21" in options


def test_combipow_crack_menu_item_label():
    cli = _load_cli()
    items = cli.get_main_menu_items()
    keys = [k for k, _ in items]
    assert "21" in keys
    labels = {k: label for k, label in items}
    assert "passphrase" in labels["21"].lower() or "combipow" in labels["21"].lower()


# --- combipow_crack handler tests ---

class TestCombipowCrack:
    def test_calls_hcatCombipow_with_space_sep_by_default(self, tmp_path):
        attacks = _load_attacks()
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("correct\nhorse\nbattery\n")
        with patch("builtins.input", side_effect=[str(wl), ""]):
            attacks.combipow_crack(ctx)
        ctx.hcatCombipow.assert_called_once()
        call_args = ctx.hcatCombipow.call_args
        use_space = (
            call_args[0][3] if len(call_args[0]) > 3 else call_args[1].get("use_space_sep")
        )
        assert use_space is True

    def test_calls_hcatCombipow_without_space_sep(self, tmp_path):
        attacks = _load_attacks()
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("correct\nhorse\nbattery\n")
        with patch("builtins.input", side_effect=[str(wl), "n"]):
            attacks.combipow_crack(ctx)
        ctx.hcatCombipow.assert_called_once()
        call_args = ctx.hcatCombipow.call_args
        use_space = (
            call_args[0][3] if len(call_args[0]) > 3 else call_args[1].get("use_space_sep")
        )
        assert use_space is False

    def test_rejects_more_than_63_lines(self, tmp_path):
        attacks = _load_attacks()
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(64)) + "\n")
        with patch("builtins.input", return_value=str(wl)):
            attacks.combipow_crack(ctx)
        ctx.hcatCombipow.assert_not_called()

    def test_accepts_exactly_63_lines(self, tmp_path):
        attacks = _load_attacks()
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(63)) + "\n")
        with patch("builtins.input", side_effect=[str(wl), ""]):
            attacks.combipow_crack(ctx)
        ctx.hcatCombipow.assert_called_once()

    def test_rejects_nonexistent_file(self, tmp_path):
        attacks = _load_attacks()
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("test\n")
        with patch("builtins.input", side_effect=["/nonexistent.txt", str(wl), ""]):
            attacks.combipow_crack(ctx)
        ctx.hcatCombipow.assert_called_once()

    def test_passes_correct_hash_type_and_file(self, tmp_path):
        attacks = _load_attacks()
        ctx = _make_ctx(hash_type="3200", hash_file="/tmp/bcrypt.txt")
        wl = tmp_path / "words.txt"
        wl.write_text("word1\nword2\n")
        with patch("builtins.input", side_effect=[str(wl), ""]):
            attacks.combipow_crack(ctx)
        ctx.hcatCombipow.assert_called_once()
        args = ctx.hcatCombipow.call_args[0]
        assert args[0] == "3200"
        assert args[1] == "/tmp/bcrypt.txt"
        assert args[2] == str(wl)

    def test_warns_about_large_word_count(self, tmp_path, capsys):
        attacks = _load_attacks()
        ctx = _make_ctx()
        wl = tmp_path / "words.txt"
        wl.write_text("\n".join(f"word{i}" for i in range(31)) + "\n")
        with patch("builtins.input", side_effect=[str(wl), ""]):
            attacks.combipow_crack(ctx)
        captured = capsys.readouterr()
        assert "large" in captured.out.lower() or "warning" in captured.out.lower()


# --- hcatCombipow wrapper tests ---

def _get_main_module():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    import hate_crack.main as m  # noqa: PLC0415

    return m


class TestHcatCombipow:
    def _run(self, tmp_path, wl, use_space_sep):
        """Run hcatCombipow with module globals patched via context managers."""
        m = _get_main_module()
        hash_file = str(tmp_path / "hashes.txt")
        combipow_bin = tmp_path / "hashcat-utils" / "bin" / "combipow.bin"
        combipow_bin.parent.mkdir(parents=True, exist_ok=True)
        combipow_bin.touch()

        fake_combipow = MagicMock()
        fake_combipow.stdout = MagicMock()
        fake_hashcat = MagicMock()
        fake_hashcat.pid = 9999

        with (
            patch.object(m, "hate_path", str(tmp_path)),
            patch.object(m, "hcatBin", "hashcat"),
            patch.object(m, "hcatTuning", ""),
            patch("hate_crack.main.hcatHashFile", hash_file, create=True),
            patch("hate_crack.main.subprocess.Popen", side_effect=[fake_combipow, fake_hashcat]) as mock_popen,
        ):
            m.hcatCombipow("1000", hash_file, str(wl), use_space_sep=use_space_sep)

        return mock_popen

    def test_includes_s_flag_when_use_space_sep_true(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("word1\nword2\n")
        mock_popen = self._run(tmp_path, wl, use_space_sep=True)
        first_call_args = mock_popen.call_args_list[0][0][0]
        assert "-s" in first_call_args

    def test_omits_s_flag_when_use_space_sep_false(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("word1\nword2\n")
        mock_popen = self._run(tmp_path, wl, use_space_sep=False)
        first_call_args = mock_popen.call_args_list[0][0][0]
        assert "-s" not in first_call_args

    def test_wordlist_passed_as_argument(self, tmp_path):
        wl = tmp_path / "words.txt"
        wl.write_text("word1\nword2\n")
        mock_popen = self._run(tmp_path, wl, use_space_sep=True)
        first_call_args = mock_popen.call_args_list[0][0][0]
        assert str(wl) in first_call_args
