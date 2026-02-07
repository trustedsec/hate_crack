import builtins
import importlib
import io
from types import SimpleNamespace


def test_fingerprint_crack_prompts_for_expander_len_and_enables_hybrid(monkeypatch):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(hash_type, hash_file, expander_len, run_hybrid_on_expanded=False):
        seen["hash_type"] = hash_type
        seen["hash_file"] = hash_file
        seen["expander_len"] = expander_len
        seen["run_hybrid_on_expanded"] = run_hybrid_on_expanded

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
    )

    monkeypatch.setattr(builtins, "input", lambda _prompt="": "24")
    attacks.fingerprint_crack(ctx)

    assert seen["expander_len"] == 24
    assert seen["run_hybrid_on_expanded"] is True


def test_hcatFingerprint_uses_selected_expander_and_calls_hybrid(monkeypatch, tmp_path):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")

    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    out_path = tmp_path / "hashes.txt.out"
    out_path.write_text("deadbeef:Accordbookkeeping2025!:x\n")

    # Make the loop run exactly one iteration.
    counts = iter([1, 1, 1, 1])
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: next(counts))
    monkeypatch.setattr(hc_main, "hcatHashCracked", 0)

    # Avoid any filesystem/executable checks in unit test.
    monkeypatch.setattr(hc_main, "ensure_binary", lambda binary_path, **_k: binary_path)

    seen = {"popen_args": [], "hybrid_calls": []}

    def fake_hybrid(hash_type, hash_file, wordlists=None):
        seen["hybrid_calls"].append((hash_type, hash_file, wordlists))

    monkeypatch.setattr(hc_main, "hcatHybrid", fake_hybrid)

    class FakePopen:
        def __init__(self, args, stdin=None, stdout=None, text=False, **_kwargs):
            self.args = args
            self.pid = 123
            self.stdout = None
            seen["popen_args"].append(args)

            cmd0 = args[0]
            if cmd0 == "sort":
                data = stdin.read() if stdin is not None else b""
                lines = sorted(set(data.splitlines()))
                for ln in lines:
                    stdout.write(ln + b"\n")
                stdout.flush()
            elif isinstance(cmd0, str) and "expander" in cmd0:
                data = stdin.read() if stdin is not None else b""
                # Identity "expansion" is enough for this test; we just need the
                # pipeline to create the .expanded file and complete.
                self.stdout = io.BytesIO(data)
            else:
                # hashcat invocation: do nothing
                pass

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None

    monkeypatch.setattr(hc_main.subprocess, "Popen", FakePopen)

    # Run with expander24 and ensure secondary hybrid gets the expanded file.
    monkeypatch.setattr(hc_main, "hcatHashFile", str(hashfile), raising=False)
    hc_main.hcatFingerprint("1000", str(hashfile), expander_len=24, run_hybrid_on_expanded=True)

    assert any(
        isinstance(args[0], str) and args[0].endswith("expander24.bin")
        for args in seen["popen_args"]
    )

    assert seen["hybrid_calls"] == [
        ("1000", str(hashfile), [f"{hashfile}.expanded"]),
    ]
