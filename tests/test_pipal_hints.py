from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from hate_crack.attacks import extensive_crack
from hate_crack.pipal_hints import hints_path, pipal_hint_words


def _ctx(tmp_path, words):
    return SimpleNamespace(
        hcatHashFile=str(tmp_path / "hashes.txt"), pipal=lambda: words
    )


def test_words_are_deduplicated_and_saved_beside_the_hash_file(tmp_path):
    ctx = _ctx(tmp_path, ["alpha", "beta", "alpha", ""])
    assert pipal_hint_words(ctx) == ["alpha", "beta"]
    assert (tmp_path / "hashes.txt.hints").read_text() == "alpha\nbeta\n"
    assert hints_path(ctx.hcatHashFile) == ctx.hcatHashFile + ".hints"


def test_no_words_writes_nothing(tmp_path):
    for empty in (None, []):
        assert pipal_hint_words(_ctx(tmp_path, empty)) == []
    assert not (tmp_path / "hashes.txt.hints").exists()


def test_unwritable_hints_file_still_returns_the_words(tmp_path):
    ctx = _ctx(tmp_path, ["alpha"])
    ctx.hcatHashFile = str(tmp_path / "missing-dir" / "hashes.txt")
    assert pipal_hint_words(ctx) == ["alpha"]


def _extensive_ctx(tmp_path, engine, pipal_path):
    ctx = MagicMock()
    ctx.hcatHashFile = str(tmp_path / "hashes.txt")
    ctx.pcfg_engine.return_value = engine
    ctx.pipalPath = pipal_path
    ctx.pipal.return_value = ["alpha"]
    return ctx


def test_extensive_runs_hints_before_good_measure(tmp_path):
    pipal_bin = tmp_path / "pipal.rb"
    pipal_bin.write_text("")
    ctx = _extensive_ctx(tmp_path, "native", str(pipal_bin))
    with patch("hate_crack.attacks._notify.prompt_notify_for_attack"):
        extensive_crack(ctx)
    ctx.hcatPCFGHints.assert_called_once_with(
        ctx.hcatHashType, ctx.hcatHashFile, hintwords=["alpha"]
    )
    names = [c[0] for c in ctx.mock_calls]
    assert names.index("hcatPCFGHints") < names.index("hcatGoodMeasure")


def test_extensive_skips_hints_without_native_engine_or_pipal(tmp_path):
    pipal_bin = tmp_path / "pipal.rb"
    pipal_bin.write_text("")
    for engine, path in (
        ("legacy", str(pipal_bin)),
        ("native", str(tmp_path / "absent.rb")),
        ("native", ""),
    ):
        ctx = _extensive_ctx(tmp_path, engine, path)
        with patch("hate_crack.attacks._notify.prompt_notify_for_attack"):
            extensive_crack(ctx)
        ctx.hcatPCFGHints.assert_not_called()
        ctx.pipal.assert_not_called()
