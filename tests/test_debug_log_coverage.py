"""Every rule-based attack must write hashcat's rule-debug log.

Rule-using attacks pass --debug-mode/--debug-file so the matched rule for
each crack lands under hcatDebugLogPath. Two attacks silently skipped the
helper (issue #202), which disabled a documented config key for those
attacks only. This test pins the invariant for future attacks.
"""

import ast
import os
from unittest.mock import MagicMock, patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAIN_PY = os.path.join(REPO_ROOT, "hate_crack", "main.py")


def _top_level_functions():
    with open(MAIN_PY) as f:
        source = f.read()
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            body = ast.get_source_segment(source, node)
            if body:
                yield node.name, body


def test_rule_using_attacks_write_the_debug_log():
    offenders = []
    for name, body in _top_level_functions():
        if "hcatBin" not in body:
            continue  # not a hashcat invocation
        if '"-r"' not in body:
            continue  # not a rule-based attack
        if "_add_debug_mode_for_rules" not in body:
            offenders.append(name)
    assert offenders == [], (
        f"rule-based attacks missing _add_debug_mode_for_rules: {offenders}"
    )


def test_generate_rules_passes_debug_file_to_hashcat(hc_module, tmp_path):
    """The Random Rules attack must emit --debug-file, not just --debug-mode."""
    main_module = hc_module._main
    hash_file = tmp_path / "hashes.txt"
    hash_file.write_text("")
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("aaa\nbbb\n")
    debug_dir = tmp_path / "debug"
    captured = []

    def fake_popen(cmd, **kwargs):
        captured.append(list(cmd))
        proc = MagicMock()
        proc.stdout = MagicMock()
        proc.wait.return_value = 0
        proc.returncode = 0
        return proc

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = ":\n"
        result.returncode = 0
        return result

    with (
        patch("hate_crack.main.subprocess.Popen", side_effect=fake_popen),
        patch("hate_crack.main.subprocess.run", side_effect=fake_run),
        patch.object(main_module, "hcatBin", "hashcat"),
        patch.object(main_module, "hcatTuning", ""),
        patch.object(main_module, "hcatPotfilePath", ""),
        patch.object(main_module, "hcatDebugLogPath", str(debug_dir)),
        patch.object(main_module, "hate_path", str(tmp_path)),
        patch.object(main_module, "hcatHashCracked", 0),
        patch("hate_crack.main.lineCount", return_value=0),
        patch("hate_crack.main.generate_session_id", return_value="s"),
    ):
        main_module.hcatGenerateRules("1000", str(hash_file), 10, str(wordlist))

    hashcat_cmds = [c for c in captured if c and c[0] == "hashcat"]
    assert hashcat_cmds, "no hashcat invocation captured"
    assert all("--debug-file" in c for c in hashcat_cmds), hashcat_cmds
