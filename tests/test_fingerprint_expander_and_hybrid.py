import builtins
import importlib
import io
from types import SimpleNamespace


def test_fingerprint_crack_prompts_for_max_expander_len_and_enables_hybrid(
    monkeypatch,
):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(
        hash_type,
        hash_file,
        max_expander_len,
        run_hybrid_on_expanded=False,
        dictionary_wordlist=None,
        keyspace_limit=None,
    ):
        seen["hash_type"] = hash_type
        seen["hash_file"] = hash_file
        seen["max_expander_len"] = max_expander_len
        seen["run_hybrid_on_expanded"] = run_hybrid_on_expanded
        seen["dictionary_wordlist"] = dictionary_wordlist
        seen["keyspace_limit"] = keyspace_limit

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
        hcatFingerprintWordlist="",
    )

    responses = iter(["24", "", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.fingerprint_crack(ctx)

    assert seen["max_expander_len"] == 24
    assert seen["run_hybrid_on_expanded"] is True
    assert seen["dictionary_wordlist"] == ""
    assert seen["keyspace_limit"] is None


def test_fingerprint_crack_passes_wordlist_when_provided(monkeypatch):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(hash_type, hash_file, max_expander_len, **kwargs):
        seen["dictionary_wordlist"] = kwargs.get("dictionary_wordlist")

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
        hcatFingerprintWordlist="",
    )

    responses = iter(["", "rockyou.txt", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.fingerprint_crack(ctx)

    assert seen["dictionary_wordlist"] == "rockyou.txt"


def test_fingerprint_crack_passes_custom_keyspace_limit(monkeypatch):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(hash_type, hash_file, max_expander_len, **kwargs):
        seen["keyspace_limit"] = kwargs.get("keyspace_limit")

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
        hcatFingerprintWordlist="",
    )

    responses = iter(["", "", "200000000000"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.fingerprint_crack(ctx)

    assert seen["keyspace_limit"] == 200_000_000_000


def test_fingerprint_crack_zero_keyspace_limit_means_no_limit(monkeypatch, capsys):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(hash_type, hash_file, max_expander_len, **kwargs):
        seen["keyspace_limit"] = kwargs.get("keyspace_limit")

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
        hcatFingerprintWordlist="",
    )

    responses = iter(["", "", "0"])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.fingerprint_crack(ctx)

    assert seen["keyspace_limit"] == 0
    assert "No limit" in capsys.readouterr().out


def test_fingerprint_crack_accepts_configured_default_wordlist(monkeypatch):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(hash_type, hash_file, max_expander_len, **kwargs):
        seen["dictionary_wordlist"] = kwargs.get("dictionary_wordlist")

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
        hcatFingerprintWordlist="/wordlists/rockyou.txt",
    )

    # max_expander_len, "use configured default?" (accept), keyspace limit.
    responses = iter(["", "", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.fingerprint_crack(ctx)

    assert seen["dictionary_wordlist"] == "/wordlists/rockyou.txt"


def test_fingerprint_crack_declining_configured_default_falls_back_to_manual_entry(
    monkeypatch,
):
    from hate_crack import attacks

    seen = {}

    def fake_hcatFingerprint(hash_type, hash_file, max_expander_len, **kwargs):
        seen["dictionary_wordlist"] = kwargs.get("dictionary_wordlist")

    ctx = SimpleNamespace(
        hcatHashType="1000",
        hcatHashFile="dummy.hash",
        hcatFingerprint=fake_hcatFingerprint,
        hcatFingerprintWordlist="/wordlists/rockyou.txt",
    )

    # max_expander_len, "use configured default?" (decline), manual entry
    # (skip), keyspace limit.
    responses = iter(["", "n", "", ""])
    monkeypatch.setattr(builtins, "input", lambda _prompt="": next(responses))
    attacks.fingerprint_crack(ctx)

    # Declining must not silently fall back to the config default anyway.
    assert seen["dictionary_wordlist"] == ""


class _SimulatingFakePopen:
    """Popen stand-in that actually runs expander/sort logic against real
    stdin/stdout file handles, and no-ops any other command (hashcat)."""

    def __init__(self, seen):
        self.seen = seen

    def __call__(self, args, stdin=None, stdout=None, text=False, **_kwargs):
        return self._Proc(args, stdin, stdout, self.seen)

    class _Proc:
        def __init__(self, args, stdin, stdout, seen):
            self.args = args
            self.pid = 1234
            self.stdout = None
            seen["popen_args"].append(list(args))

            cmd0 = args[0]
            if cmd0 == "sort":
                data = stdin.read() if stdin is not None else b""
                lines = sorted(set(data.splitlines()))
                for ln in lines:
                    stdout.write(ln + b"\n")
                stdout.flush()
            elif isinstance(cmd0, str) and "expander" in cmd0:
                data = stdin.read() if stdin is not None else b""
                self.stdout = io.BytesIO(data)
            # else: hashcat invocation — no-op.

        def wait(self, timeout=None):
            return 0

        def kill(self):
            return None


def _combination_operands(cmd):
    """The two wordlist operands of a -a1 combine, which sit right after
    -j/-k regardless of what -O/potfile flags got appended afterward."""
    idx = cmd.index("-k")
    return (cmd[idx + 2], cmd[idx + 3])


def _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    monkeypatch.setattr(hc_main, "hcatHashCracked", 0)
    monkeypatch.setattr(hc_main, "ensure_binary", lambda binary_path, **_k: binary_path)
    monkeypatch.setattr(hc_main, "hate_path", str(tmp_path))
    monkeypatch.setattr(hc_main, "hcatHashFile", str(hashfile))
    monkeypatch.setattr(hc_main, "generate_session_id", lambda: "test_session")
    monkeypatch.setattr(hc_main, "hcatBin", "hashcat")
    monkeypatch.setattr(hc_main, "hcatTuning", "")


def test_hcatFingerprint_escalates_through_length_chain_and_calls_hybrid_per_step(
    monkeypatch, tmp_path
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    out_path = tmp_path / "hashes.txt.out"
    out_path.write_text("deadbeef:Accordbookkeeping2025!\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    # Constant lineCount makes each length's while-loop converge after one
    # iteration (crackedAfter == crackedBefore) and keeps the keyspace guard
    # well under its threshold.
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)

    seen = {"popen_args": [], "hybrid_calls": []}

    def fake_hybrid(hash_type, hash_file, wordlists=None):
        seen["hybrid_calls"].append((hash_type, hash_file, wordlists))

    monkeypatch.setattr(hc_main, "hcatHybrid", fake_hybrid)
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint(
        "1000", str(hashfile), max_expander_len=24, run_hybrid_on_expanded=True
    )

    # Chain for max_expander_len=24 is [7, 14, 21, 24]; length 7 uses the
    # configured hcatExpanderBin rather than a literal "expander7.bin".
    expected_binaries = [
        hc_main.hcatExpanderBin,
        "expander14.bin",
        "expander21.bin",
        "expander24.bin",
    ]
    for binary in expected_binaries:
        assert any(
            isinstance(args[0], str) and args[0].endswith(binary)
            for args in seen["popen_args"]
        ), f"{binary} never invoked"

    assert (
        seen["hybrid_calls"] == [("1000", str(hashfile), [f"{hashfile}.expanded"])] * 4
    )


def test_hcatFingerprint_skips_hashcat_and_hybrid_when_nothing_cracked(
    monkeypatch, tmp_path
):
    """If .out has no cracked plaintexts, hcatFingerprint must not invoke
    hashcat or the secondary hybrid attack."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    out_path = tmp_path / "hashes.txt.out"
    out_path.write_text("")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 0)

    seen = {"popen_args": [], "hybrid_calls": []}

    def fake_hybrid(hash_type, hash_file, wordlists=None):
        seen["hybrid_calls"].append((hash_type, hash_file, wordlists))

    monkeypatch.setattr(hc_main, "hcatHybrid", fake_hybrid)
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint(
        "1000", str(hashfile), max_expander_len=7, run_hybrid_on_expanded=True
    )

    hashcat_invocations = [args for args in seen["popen_args"] if "-a" in args]
    assert hashcat_invocations == []
    assert seen["hybrid_calls"] == []


def test_hcatFingerprint_self_combination_uses_capitalize_rule(monkeypatch, tmp_path):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("deadbeef:Summer2025!\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)

    seen = {"popen_args": []}
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint("1000", str(hashfile), max_expander_len=7)

    hashcat_cmds = [args for args in seen["popen_args"] if args[0] == "hashcat"]
    assert hashcat_cmds, "No hashcat invocation captured"
    for cmd in hashcat_cmds:
        assert cmd[cmd.index("-j") + 1] == "c"
        assert cmd[cmd.index("-k") + 1] == "c"


def test_hcatFingerprint_combines_against_dictionary_in_both_orders(
    monkeypatch, tmp_path
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("deadbeef:Summer2025!\n")
    dict_path = tmp_path / "words.txt"
    dict_path.write_text("winter\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)
    monkeypatch.setattr(hc_main, "hcatWordlists", str(tmp_path))

    seen = {"popen_args": []}
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint(
        "1000",
        str(hashfile),
        max_expander_len=7,
        dictionary_wordlist=str(dict_path),
    )

    hashcat_cmds = [args for args in seen["popen_args"] if args[0] == "hashcat"]
    expanded_path = f"{hashfile}.expanded"

    assert any(
        _combination_operands(c) == (expanded_path, expanded_path) for c in hashcat_cmds
    )
    assert any(
        _combination_operands(c) == (expanded_path, str(dict_path))
        for c in hashcat_cmds
    )
    assert any(
        _combination_operands(c) == (str(dict_path), expanded_path)
        for c in hashcat_cmds
    )


def test_hcatFingerprint_dictionary_guard_checked_once_not_per_direction(
    monkeypatch, tmp_path
):
    """expanded+dict and dict+expanded have the same candidate count, so an
    over-threshold keyspace must be checked (and skipped) once for the pair,
    not once per direction."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("deadbeef:Summer2025!\n")
    dict_path = tmp_path / "words.txt"
    dict_path.write_text("winter\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    # Large enough that both self- and dictionary-combination exceed the
    # keyspace guardrail threshold.
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 300_000)
    monkeypatch.setattr(hc_main, "hcatWordlists", str(tmp_path))

    guard_calls = []
    real_guard = hc_main._fingerprint_keyspace_guard

    def counting_guard(left, right, label, limit):
        guard_calls.append(label)
        return real_guard(left, right, label, limit)

    monkeypatch.setattr(hc_main, "_fingerprint_keyspace_guard", counting_guard)

    seen = {"popen_args": []}
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint(
        "1000",
        str(hashfile),
        max_expander_len=7,
        dictionary_wordlist=str(dict_path),
    )

    hashcat_cmds = [args for args in seen["popen_args"] if args[0] == "hashcat"]
    expanded_path = f"{hashfile}.expanded"

    # Over threshold: self- and dictionary-combination are both skipped.
    assert not any(
        _combination_operands(c) == (expanded_path, expanded_path) for c in hashcat_cmds
    )
    assert not any(
        _combination_operands(c) == (expanded_path, str(dict_path))
        for c in hashcat_cmds
    )
    assert not any(
        _combination_operands(c) == (str(dict_path), expanded_path)
        for c in hashcat_cmds
    )

    # One guard check for self-combination, one for the dictionary pair —
    # not three (i.e. not one per direction).
    assert len(guard_calls) == 2, guard_calls


def test_hcatFingerprint_warns_and_skips_missing_dictionary(
    monkeypatch, tmp_path, capsys
):
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("deadbeef:Summer2025!\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)
    monkeypatch.setattr(hc_main, "hcatWordlists", str(tmp_path))

    seen = {"popen_args": []}
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint(
        "1000",
        str(hashfile),
        max_expander_len=7,
        dictionary_wordlist="does-not-exist.txt",
    )

    hashcat_cmds = [args for args in seen["popen_args"] if args[0] == "hashcat"]
    expanded_path = f"{hashfile}.expanded"
    assert all(
        _combination_operands(cmd) == (expanded_path, expanded_path)
        for cmd in hashcat_cmds
    )
    assert "Wordlist not found" in capsys.readouterr().out


def test_hcatFingerprint_falls_back_to_configured_wordlist_when_none_passed(
    monkeypatch, tmp_path
):
    """dictionary_wordlist=None (the default -- e.g. extensive_crack's call,
    which can't prompt) picks up hcatFingerprintWordlist from config."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("deadbeef:Summer2025!\n")
    dict_path = tmp_path / "words.txt"
    dict_path.write_text("winter\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)
    monkeypatch.setattr(hc_main, "hcatWordlists", str(tmp_path))
    monkeypatch.setattr(hc_main, "hcatFingerprintWordlist", str(dict_path))

    seen = {"popen_args": []}
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint("1000", str(hashfile), max_expander_len=7)

    hashcat_cmds = [args for args in seen["popen_args"] if args[0] == "hashcat"]
    expanded_path = f"{hashfile}.expanded"
    assert any(
        _combination_operands(c) == (expanded_path, str(dict_path))
        for c in hashcat_cmds
    )


def test_hcatFingerprint_explicit_empty_dictionary_skips_configured_default(
    monkeypatch, tmp_path
):
    """dictionary_wordlist="" (declined at the prompt) must not fall back to
    the configured default -- only the None default does."""
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    (tmp_path / "hashes.txt.out").write_text("deadbeef:Summer2025!\n")
    dict_path = tmp_path / "words.txt"
    dict_path.write_text("winter\n")

    _install_fingerprint_test_env(monkeypatch, hc_main, tmp_path, hashfile)
    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)
    monkeypatch.setattr(hc_main, "hcatWordlists", str(tmp_path))
    monkeypatch.setattr(hc_main, "hcatFingerprintWordlist", str(dict_path))

    seen = {"popen_args": []}
    monkeypatch.setattr(hc_main.subprocess, "Popen", _SimulatingFakePopen(seen))

    hc_main.hcatFingerprint(
        "1000", str(hashfile), max_expander_len=7, dictionary_wordlist=""
    )

    hashcat_cmds = [args for args in seen["popen_args"] if args[0] == "hashcat"]
    expanded_path = f"{hashfile}.expanded"
    assert not any(
        _combination_operands(c) == (expanded_path, str(dict_path))
        for c in hashcat_cmds
    )


def test_fingerprint_expander_chain_escalates_by_seven():
    from hate_crack import main as hc_main

    assert hc_main._fingerprint_expander_chain(7) == [7]
    assert hc_main._fingerprint_expander_chain(21) == [7, 14, 21]
    assert hc_main._fingerprint_expander_chain(24) == [7, 14, 21, 24]
    assert hc_main._fingerprint_expander_chain(36) == [7, 14, 21, 28, 35, 36]


class TestFingerprintKeyspaceGuard:
    def test_under_threshold_proceeds_without_prompting(self, monkeypatch):
        from hate_crack import main as hc_main

        monkeypatch.setattr(hc_main, "lineCount", lambda _p: 100)
        monkeypatch.setattr(
            builtins,
            "input",
            lambda *_a, **_k: (_ for _ in ()).throw(
                AssertionError("should not prompt")
            ),
        )

        assert hc_main._fingerprint_keyspace_guard(
            "left", "right", "label", 50_000_000_000
        )

    def test_over_threshold_skips_without_prompting(self, monkeypatch):
        """Fingerprint is launched once and left to run; a keyspace guard
        that blocks on input() mid-run has no one there to answer it, so an
        over-threshold combination is always skipped, never asked about."""
        from hate_crack import main as hc_main

        monkeypatch.setattr(hc_main, "lineCount", lambda _p: 300_000)
        monkeypatch.setattr(
            builtins,
            "input",
            lambda *_a, **_k: (_ for _ in ()).throw(
                AssertionError("should not prompt")
            ),
        )

        assert not hc_main._fingerprint_keyspace_guard(
            "left", "right", "label", 50_000_000_000
        )

    def test_falsy_limit_means_no_limit(self, monkeypatch):
        from hate_crack import main as hc_main

        monkeypatch.setattr(hc_main, "lineCount", lambda _p: 300_000)
        monkeypatch.setattr(
            builtins,
            "input",
            lambda *_a, **_k: (_ for _ in ()).throw(
                AssertionError("should not prompt")
            ),
        )

        assert hc_main._fingerprint_keyspace_guard("left", "right", "label", 0)
        assert hc_main._fingerprint_keyspace_guard("left", "right", "label", None)
