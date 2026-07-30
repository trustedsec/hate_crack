"""End-to-end tests for ``hate_crack.main.pipal``.

These are hermetic e2e tests: instead of requiring a real Ruby + pipal.rb
install, they drop a small fake ``pipal`` executable on disk that consumes the
same CLI (``<passwords> -t <N> --output <file>``) and emits a pipal-shaped
report.  ``pipal()`` is then driven through its real code path — writing the
``.passwords`` file (including ``$HEX[...]`` decoding), spawning the subprocess
via ``subprocess.Popen(..., shell=True)``, and parsing the ``Top N base words``
section back out.

A real-tool variant is gated behind ``HATE_CRACK_PIPAL_REAL=1`` +
``HATE_CRACK_PIPAL_PATH`` for anyone who wants to run against genuine pipal.rb.
"""

import os
import stat
import sys
import textwrap
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _get_main_module():
    if str(PROJECT_ROOT) not in sys.path:
        sys.path.insert(0, str(PROJECT_ROOT))
    os.environ["HATE_CRACK_SKIP_INIT"] = "1"
    import hate_crack.main as m  # noqa: PLC0415

    return m


# A fake pipal that mimics the real tool closely enough for the parser:
# base word = password lowercased with trailing non-alphabetic characters
# stripped, ranked by descending frequency, and only the top -t entries are
# emitted under the "Top N base words" header.
_FAKE_PIPAL = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import re
    import sys

    args = sys.argv[1:]
    pw_file = args[0]
    top = 10
    out = None
    i = 1
    while i < len(args):
        if args[i] in ("-t", "--top"):
            top = int(args[i + 1]); i += 2
        elif args[i] in ("-o", "--output"):
            out = args[i + 1]; i += 2
        elif args[i] == "--output":
            out = args[i + 1]; i += 2
        else:
            i += 1

    counts = {}
    with open(pw_file, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            pw = line.rstrip("\\n")
            if not pw:
                continue
            base = re.sub(r"[^a-zA-Z]+$", "", pw).lower()
            if not base:
                continue
            counts[base] = counts.get(base, 0) + 1

    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    total = sum(counts.values())

    lines = []
    lines.append("Basic Results")
    lines.append("")
    lines.append("Total entries = %d" % total)
    lines.append("")
    lines.append("Top %d base words" % top)
    for word, c in ranked[:top]:
        pct = 100.0 * c / total if total else 0.0
        lines.append("%s = %d (%.2f%%)" % (word, c, pct))
    lines.append("")

    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\\n".join(lines) + "\\n")
    """
)


def _install_fake_pipal(tmp_path: Path) -> Path:
    fake = tmp_path / "pipal"
    fake.write_text(_FAKE_PIPAL)
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return fake


def _run_pipal(monkeypatch, m, tmp_path, cracked_lines, pipal_count):
    """Wire up main-module globals and run the real ``pipal()``."""
    fake = _install_fake_pipal(tmp_path)
    hashfile = tmp_path / "hashes.txt"
    hashfile.write_text("dummy\n")
    (tmp_path / "hashes.txt.out").write_text("".join(cracked_lines))

    monkeypatch.setattr(m, "pipalPath", str(fake))
    monkeypatch.setattr(m, "pipal_count", pipal_count)
    # hcatHashFile / hcatHashType only exist after main() runs; create them.
    monkeypatch.setattr(m, "hcatHashFile", str(hashfile))
    monkeypatch.setattr(m, "hcatHashType", "0")  # not NTLM
    return m.pipal(), hashfile


class TestPipalE2E:
    def test_returns_top_basewords(self, monkeypatch, tmp_path, capsys):
        m = _get_main_module()
        cracked = [
            "hash1:password1\n",
            "hash2:password2\n",
            "hash3:Password!\n",
            "hash4:summer2021\n",
            "hash5:summer99\n",
            "hash6:winter1\n",
        ]
        result, hashfile = _run_pipal(monkeypatch, m, tmp_path, cracked, pipal_count=3)

        assert result == ["password", "summer", "winter"]
        # pipal report and intermediate passwords file were produced
        assert (Path(str(hashfile) + ".pipal")).is_file()
        assert (Path(str(hashfile) + ".passwords")).is_file()

    def test_passwords_file_decodes_hex(self, monkeypatch, tmp_path):
        m = _get_main_module()
        # 70617373776f7264 == "password"
        cracked = [
            "hash1:$HEX[70617373776f7264]\n",
            "hash2:hunter2\n",
        ]
        _run_pipal(monkeypatch, m, tmp_path, cracked, pipal_count=2)

        pw_path = tmp_path / "hashes.txt.passwords"
        contents = pw_path.read_text(encoding="utf-8").splitlines()
        assert "password" in contents  # $HEX decoded, not written literally
        assert "hunter2" in contents
        assert not any(line.startswith("$HEX[") for line in contents)

    def test_no_cracked_output_returns_empty(self, monkeypatch, tmp_path):
        m = _get_main_module()
        fake = _install_fake_pipal(tmp_path)
        hashfile = tmp_path / "hashes.txt"
        hashfile.write_text("dummy\n")  # note: no .out file created

        monkeypatch.setattr(m, "pipalPath", str(fake))
        monkeypatch.setattr(m, "pipal_count", 3)
        monkeypatch.setattr(m, "hcatHashFile", str(hashfile))
        monkeypatch.setattr(m, "hcatHashType", "0")
        assert m.pipal() == []

    def test_missing_pipal_path_returns_none(self, monkeypatch, tmp_path):
        m = _get_main_module()
        hashfile = tmp_path / "hashes.txt"
        hashfile.write_text("dummy\n")
        (tmp_path / "hashes.txt.out").write_text("hash1:password1\n")

        monkeypatch.setattr(m, "pipalPath", str(tmp_path / "does-not-exist"))
        monkeypatch.setattr(m, "pipal_count", 3)
        monkeypatch.setattr(m, "hcatHashFile", str(hashfile))
        monkeypatch.setattr(m, "hcatHashType", "0")
        assert m.pipal() is None

    def test_handles_shell_metacharacters_in_path(self, monkeypatch, tmp_path):
        """The subprocess call must not use a shell (no command injection).

        A hash-file path containing shell metacharacters would, under the old
        ``shell=True`` string command, either break or execute the injected
        fragment.  With list-form Popen it is handled as a literal path.
        """
        m = _get_main_module()
        weird_dir = tmp_path / "a b; touch INJECTED"
        weird_dir.mkdir()
        cracked = ["hash1:password1\n", "hash2:summer2021\n"]

        fake = _install_fake_pipal(tmp_path)
        hashfile = weird_dir / "hashes.txt"
        hashfile.write_text("dummy\n")
        (weird_dir / "hashes.txt.out").write_text("".join(cracked))

        monkeypatch.setattr(m, "pipalPath", str(fake))
        monkeypatch.setattr(m, "pipal_count", 3)
        monkeypatch.setattr(m, "hcatHashFile", str(hashfile))
        monkeypatch.setattr(m, "hcatHashType", "0")

        result = m.pipal()

        assert result == ["password", "summer"]
        # the injected `touch INJECTED` must NOT have run
        assert not (tmp_path / "INJECTED").exists()
        assert not Path("INJECTED").exists()

    def test_fewer_basewords_than_count(self, monkeypatch, tmp_path):
        """Real-world case: fewer unique base words than ``pipal_count``.

        A small cracked set should still surface the base words it *does*
        have, rather than silently returning nothing.
        """
        m = _get_main_module()
        cracked = [
            "hash1:password1\n",
            "hash2:summer2021\n",
            "hash3:winter1\n",
        ]
        # default pipal_count (10) is larger than the 3 available base words
        result, _ = _run_pipal(monkeypatch, m, tmp_path, cracked, pipal_count=10)
        assert result == ["password", "summer", "winter"]
