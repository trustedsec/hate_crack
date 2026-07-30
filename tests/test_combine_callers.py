"""Every caller of combine_ntlm_output must guard on pwdump_format.

The merge is pwdump-only. Calling it on a plain hash list used to truncate the
cracked output (issue #195). cleanup() guarded correctly from the start; pipal()
and export_excel() did not (issue #196). This pins the invariant so a fourth
caller cannot repeat it.
"""

import ast
import os
from unittest.mock import patch

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_PY = os.path.join(REPO_ROOT, "hate_crack", "main.py")


@pytest.fixture
def main_module(hc_module):
    return hc_module._main


def _callers_of(function_name):
    """Top-level functions whose body calls `function_name`."""
    with open(MAIN_PY) as f:
        source = f.read()
    tree = ast.parse(source)
    found = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        if node.name == function_name:
            continue
        body = ast.get_source_segment(source, node) or ""
        if f"{function_name}()" in body:
            found[node.name] = body
    return found


def test_every_combine_caller_guards_on_pwdump_format():
    callers = _callers_of("combine_ntlm_output")
    assert callers, "found no callers - has the function been renamed?"
    unguarded = [name for name, body in callers.items() if "pwdump_format" not in body]
    assert unguarded == [], (
        "these callers of combine_ntlm_output() do not mention pwdump_format, so "
        "they run a pwdump-only merge on any hash file: " + ", ".join(unguarded)
    )


def test_export_excel_skips_the_merge_for_a_non_pwdump_hash_file(
    main_module, tmp_path, monkeypatch, capsys
):
    """A plain hash list must get an explanation, not a truncated .out and an
    empty spreadsheet reported as a success."""
    pytest.importorskip("openpyxl")
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("a" * 32 + "\n")
    out_path = tmp_path / "hashes.txt.out"
    out_path.write_text("a" * 32 + ":pw-a\n")
    before = out_path.read_bytes()
    monkeypatch.setattr(main_module, "hcatHashFile", str(hash_file), raising=False)
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(hash_file), raising=False)
    monkeypatch.setattr(main_module, "hcatHashType", "1000", raising=False)
    monkeypatch.setattr(main_module, "pwdump_format", False)

    with patch.object(main_module, "combine_ntlm_output") as combine:
        main_module.export_excel()

    combine.assert_not_called()
    assert out_path.read_bytes() == before
    assert not (tmp_path / "hashes.txt.xlsx").exists()
    assert "pwdump" in capsys.readouterr().err.lower()


def test_export_excel_still_exports_for_a_pwdump_hash_file(
    main_module, tmp_path, monkeypatch
):
    """The feature must keep working on the input it is meant for."""
    openpyxl = pytest.importorskip("openpyxl")
    orig = tmp_path / "hashes.txt"
    cracked = tmp_path / "hashes.txt.nt"
    (tmp_path / "hashes.txt.out").write_text(
        f"alice:1001:{'0' * 32}:{'a' * 32}:::pw-a\n"
    )
    monkeypatch.setattr(main_module, "hcatHashFile", str(cracked), raising=False)
    monkeypatch.setattr(main_module, "hcatHashFileOrig", str(orig), raising=False)
    monkeypatch.setattr(main_module, "hcatHashType", "1000", raising=False)
    monkeypatch.setattr(main_module, "pwdump_format", True)

    with patch.object(main_module, "combine_ntlm_output"):
        main_module.export_excel()

    workbook_path = tmp_path / "hashes.txt.nt.xlsx"
    assert workbook_path.exists()
    sheet = openpyxl.load_workbook(workbook_path).active
    assert sheet["A2"].value == "alice"
    assert sheet["E2"].value == "pw-a"
