"""Regression tests for the HashcatRosetta import diagnostics (#231).

A discarded ``ImportError`` turned one missing submodule into 20 unrelated
assertion failures in ``tests/test_main_rosetta.py``. These tests pin both
halves of the fix: the captured cause on the library side, and the
report-once guard on the test-suite side.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from hate_crack import main as hate_crack_main

REPO_ROOT = Path(__file__).resolve().parents[1]
ROSETTA_TEST_FILE = "tests/test_main_rosetta.py"


class TestCapturedImportError:
    def test_error_and_symbols_agree(self):
        """A captured error and a missing DebugAnalyzer must imply each other."""
        assert (hate_crack_main.DebugAnalyzer is None) == (
            hate_crack_main.ROSETTA_IMPORT_ERROR is not None
        )

    def test_healthy_checkout_has_no_captured_error(self):
        if hate_crack_main.DebugAnalyzer is None:
            pytest.skip("HashcatRosetta is not importable in this checkout")
        assert hate_crack_main.ROSETTA_IMPORT_ERROR is None

    def test_reason_names_the_submodule_command(self, monkeypatch):
        monkeypatch.setattr(hate_crack_main, "ROSETTA_IMPORT_ERROR", None)
        reason = hate_crack_main.rosetta_unavailable_reason()
        assert "git submodule update --init HashcatRosetta" in reason
        assert "import failed" not in reason

    def test_reason_quotes_the_captured_cause(self, monkeypatch):
        monkeypatch.setattr(
            hate_crack_main,
            "ROSETTA_IMPORT_ERROR",
            ImportError("no module named hashcat_rosetta.debug_analyzer"),
        )
        reason = hate_crack_main.rosetta_unavailable_reason()
        assert "git submodule update --init HashcatRosetta" in reason
        assert "no module named hashcat_rosetta.debug_analyzer" in reason

    def test_rosetta_derive_runtime_error_includes_the_cause(
        self, monkeypatch, tmp_path
    ):
        monkeypatch.setattr(hate_crack_main, "DebugAnalyzer", None)
        monkeypatch.setattr(
            hate_crack_main,
            "ROSETTA_IMPORT_ERROR",
            ImportError("hashcat_rosetta is half-installed"),
        )
        log = tmp_path / "debug.log"
        log.write_text("alpha:$1:alpha1:wl.txt\n", encoding="utf-8")

        with pytest.raises(RuntimeError) as excinfo:
            hate_crack_main.rosetta_derive([str(log)], str(tmp_path / "out"))

        message = str(excinfo.value)
        assert "git submodule update --init HashcatRosetta" in message
        assert "hashcat_rosetta is half-installed" in message

    def test_analyze_rules_prints_the_reason(self, monkeypatch, capsys):
        monkeypatch.setattr(hate_crack_main, "display_rule_opcodes_summary", None)
        monkeypatch.setattr(
            hate_crack_main,
            "ROSETTA_IMPORT_ERROR",
            ImportError("hashcat_rosetta.formatting is missing"),
        )
        hate_crack_main.analyze_rules()
        out = capsys.readouterr().out
        assert "git submodule update --init HashcatRosetta" in out
        assert "hashcat_rosetta.formatting is missing" in out


def _run_rosetta_tests_with_forced_import_failure(tmp_path, *, submodule_present):
    """Run the rosetta test module with a simulated failed Rosetta import.

    Mirrors the real bug: the symbols are ``None`` from the moment
    ``hate_crack.main`` is imported, before any test is collected.
    """
    plugin_dir = tmp_path / "plugin"
    plugin_dir.mkdir()
    absent_snippet = (
        ""
        if submodule_present
        else '    main.ROSETTA_DIR = os.path.join(main.ROSETTA_DIR, "__absent__")\n'
    )
    (plugin_dir / "force_rosetta_failure.py").write_text(
        textwrap.dedent("""\
            import os

            from hate_crack import main


            def pytest_configure(config):
                main.DebugAnalyzer = None
                main.display_rule_opcodes_summary = None
                main.ROSETTA_IMPORT_ERROR = ImportError("forced for regression test")
            """)
        + absent_snippet,
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["HATE_CRACK_SKIP_INIT"] = "1"
    env["PYTHONPATH"] = os.pathsep.join(
        [str(plugin_dir), env.get("PYTHONPATH", "")]
    ).rstrip(os.pathsep)
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            ROSETTA_TEST_FILE,
            "-p",
            "force_rosetta_failure",
            "-p",
            "no:randomly",
            "-q",
            "-rs",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )


class TestReportedOnceNotTwenty:
    """The point of #231: many opaque failures become one clear signal."""

    def test_absent_submodule_skips_with_the_submodule_command(self, tmp_path):
        result = _run_rosetta_tests_with_forced_import_failure(
            tmp_path, submodule_present=False
        )
        output = result.stdout + result.stderr
        # Assert on the exit status and the summary line, not a substring of the
        # whole output: a developer's own config.json emits "Config key ... is
        # ignored" warnings into this stream, so a bare `"failed" not in output`
        # would break the day one of those messages happens to contain the word.
        # 5 is pytest's "no tests ran", which is what a fully-skipped module
        # gives; 0 would mean tests actually executed. Either is a pass here,
        # and neither is the non-zero a failure would produce.
        assert result.returncode in (0, 5), output
        assert "1 skipped" in output, output
        assert " failed" not in output.splitlines()[-1], output
        assert "git submodule update --init HashcatRosetta" in output, output

    def test_present_but_broken_submodule_fails_loudly(self, tmp_path):
        result = _run_rosetta_tests_with_forced_import_failure(
            tmp_path, submodule_present=True
        )
        output = result.stdout + result.stderr
        assert result.returncode != 0, output
        assert "forced for regression test" in output, output
        assert "failed to import" in output, output
