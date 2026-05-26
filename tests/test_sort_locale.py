"""Sort subprocess calls must force LC_ALL=C.

macOS `sort` is locale-strict: when stdin contains bytes that aren't
valid in the current LC_COLLATE (commonly LC_COLLATE=en_US.UTF-8),
`sort` errors out with "sort: Illegal byte sequence". Cracked-password
streams routinely contain such bytes (hex-encoded fields, mixed
encodings, binary), so all three `sort -u` invocations in main.py must
override LC_ALL=C to fall back to byte-collation.
"""

import importlib
import io
import subprocess


def _collect_sort_calls(monkeypatch, hc_main):
    """Replace subprocess.Popen with a recorder. Returns a list that will
    receive (args, kwargs) tuples for every Popen call so tests can pick
    out the sort invocations and inspect their env."""
    calls = []

    class RecordingPopen:
        def __init__(self, args, **kwargs):
            calls.append((args, kwargs))
            self.args = args
            self.pid = 0
            self.stdout = None
            self.stdin = None
            cmd0 = args[0] if args else None
            # Pipe behavior for the sort step so callers can read/write
            # without blocking.
            if cmd0 == "sort":
                stdin = kwargs.get("stdin")
                stdout = kwargs.get("stdout")
                data = b""
                if stdin is not None and hasattr(stdin, "read"):
                    data = stdin.read()
                    if isinstance(data, str):
                        data = data.encode()
                if stdout is not None and hasattr(stdout, "write"):
                    for ln in sorted(set(data.splitlines())):
                        stdout.write(ln + b"\n" if isinstance(ln, bytes) else ln + "\n")
                    if hasattr(stdout, "flush"):
                        stdout.flush()
                # Sort also receives writes via stdin.write() in
                # _write_field_sorted_unique. For that path we need a
                # writable stdin handle.
                if stdin is subprocess.PIPE or kwargs.get("text"):
                    self.stdin = io.StringIO()
            elif isinstance(cmd0, str) and "expander" in cmd0:
                stdin = kwargs.get("stdin")
                data = stdin.read() if stdin is not None else b""
                self.stdout = io.BytesIO(data)

        def wait(self, timeout=None):
            return 0

        def kill(self):
            pass

    monkeypatch.setattr(hc_main.subprocess, "Popen", RecordingPopen)
    return calls


def _sort_calls(calls):
    return [(args, kwargs) for args, kwargs in calls if args and args[0] == "sort"]


def test_write_field_sorted_unique_uses_C_locale(monkeypatch, tmp_path):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    src = tmp_path / "input.txt"
    src.write_text("aa:bb\ncc:dd\n")
    dst = tmp_path / "out.txt"

    calls = _collect_sort_calls(monkeypatch, hc_main)
    hc_main._write_field_sorted_unique(str(src), str(dst), 2)

    sort_calls = _sort_calls(calls)
    assert sort_calls, "expected at least one sort -u invocation"
    for _args, kwargs in sort_calls:
        env = kwargs.get("env")
        assert env is not None, "sort Popen must pass env to force locale"
        assert env.get("LC_ALL") == "C", (
            f"sort env must set LC_ALL=C to handle non-UTF-8 bytes; got {env.get('LC_ALL')!r}"
        )


def test_hcatFingerprint_sort_uses_C_locale(monkeypatch, tmp_path):
    monkeypatch.setenv("HATE_CRACK_SKIP_INIT", "1")
    import hate_crack.main as hc_main

    importlib.reload(hc_main)

    hashfile = tmp_path / "hashes.txt"
    out_path = tmp_path / "hashes.txt.out"
    out_path.write_text("deadbeef:somepassword\n")

    monkeypatch.setattr(hc_main, "lineCount", lambda _p: 1)
    monkeypatch.setattr(hc_main, "hcatHashCracked", 0)
    monkeypatch.setattr(hc_main, "ensure_binary", lambda binary_path, **_k: binary_path)
    monkeypatch.setattr(hc_main, "hcatHybrid", lambda *a, **kw: None)
    monkeypatch.setattr(hc_main, "hcatHashFile", str(hashfile), raising=False)

    calls = _collect_sort_calls(monkeypatch, hc_main)
    hc_main.hcatFingerprint(
        "1000", str(hashfile), expander_len=7, run_hybrid_on_expanded=False
    )

    sort_calls = _sort_calls(calls)
    assert sort_calls, "expected at least one sort -u invocation in fingerprint pipeline"
    for _args, kwargs in sort_calls:
        env = kwargs.get("env")
        assert env is not None
        assert env.get("LC_ALL") == "C"


def test_all_sort_popen_calls_in_main_set_LC_ALL_C():
    """Source-level guard: every subprocess.Popen call in main.py whose
    first arg list begins with "sort" must also pass an env= kwarg that
    sets LC_ALL=C. This catches the third site (hcatLMtoNT) without
    needing to mock its substantial setup, and prevents future sort
    invocations from regressing the locale fix."""
    import ast
    import pathlib

    main_path = pathlib.Path(__file__).parent.parent / "hate_crack" / "main.py"
    tree = ast.parse(main_path.read_text())

    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        # Match subprocess.Popen(...)
        if not (
            isinstance(func, ast.Attribute)
            and func.attr == "Popen"
            and isinstance(func.value, ast.Name)
            and func.value.id == "subprocess"
        ):
            continue
        if not node.args:
            continue
        first = node.args[0]
        # First positional arg must be a list whose first element is "sort"
        if not isinstance(first, ast.List) or not first.elts:
            continue
        head = first.elts[0]
        if not (isinstance(head, ast.Constant) and head.value == "sort"):
            continue
        # Found a sort Popen. Require env= kwarg.
        env_kw = next((kw for kw in node.keywords if kw.arg == "env"), None)
        if env_kw is None:
            offenders.append(node.lineno)

    assert not offenders, (
        f"subprocess.Popen([\"sort\", ...]) at line(s) {offenders} must pass "
        "env={**os.environ, 'LC_ALL': 'C'} to handle non-UTF-8 bytes on macOS."
    )
