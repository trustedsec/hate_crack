import builtins
from pathlib import Path


SNAPSHOT_DIR = Path(__file__).resolve().parent / "fixtures" / "menu_outputs"


def _snapshot_text(out, err):
    return f"STDOUT:\n{out}STDERR:\n{err}"


def _assert_snapshot(name, capsys):
    captured = capsys.readouterr()
    snapshot_path = SNAPSHOT_DIR / f"{name}.txt"
    expected = snapshot_path.read_text(encoding="utf-8")
    actual = _snapshot_text(captured.out, captured.err)
    assert actual == expected


def _input_sequence(values):
    iterator = iter(values)

    def _fake_input(_prompt=""):
        return next(iterator)

    return _fake_input


def _setup_globals(hc, tmp_path):
    hc.hcatHashType = "1000"
    hc.hcatHashFile = "hashes"
    hc.hcatHashFileOrig = hc.hcatHashFile
    hc.hcatWordlists = str(tmp_path / "wordlists")
    hc.hcatOptimizedWordlists = str(tmp_path / "optimized")
    hc.hcatPath = str(tmp_path / "hcat")
    hc.hcatHybridlist = ["hybrid1.txt", "hybrid2.txt"]
    hc.hcatBruteCount = 0
    hc.hcatDictionaryCount = 0
    hc.hcatMaskCount = 0
    hc.hcatFingerprintCount = 0
    hc.hcatCombinationCount = 0
    hc.hcatHybridCount = 0
    hc.hcatExtraCount = 0

def test_hybrid_crack_snapshot(hc_module, monkeypatch, tmp_path, capsys):
    hc = hc_module
    _setup_globals(hc, tmp_path)
    monkeypatch.setattr(hc, "hcatHybrid", lambda *args, **kwargs: print("hcatHybrid called"))
    monkeypatch.setattr(builtins, "input", _input_sequence([""]))

    hc.hybrid_crack()
    _assert_snapshot("hybrid_crack", capsys)

