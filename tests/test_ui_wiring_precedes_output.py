"""Guard: the UI backend must be installed before main() produces output."""

from __future__ import annotations

import ast
import inspect
import textwrap

from hate_crack import main as main_module


def _calls_outside_nested_defs(node: ast.AST):
    """Yield Call nodes under node, not descending into nested function defs."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if isinstance(child, ast.Call):
            yield child
        yield from _calls_outside_nested_defs(child)


def _callee_name(call: ast.Call) -> str | None:
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id
    if isinstance(fn, ast.Attribute):
        return fn.attr
    return None


def test_set_ui_precedes_first_print_in_main():
    """set_ui must be called strictly before the first print() in main().

    get_ui() lazily builds a PlainUI, so a converted call site that runs
    before installation silently ignores ui_backend and nothing else would
    fail. The walk is scoped to main() itself and skips nested defs
    (_build_parser, _cleanup_preprocessing_temps), whose bodies do not run
    at main()'s top level.
    """
    source = textwrap.dedent(inspect.getsource(main_module.main))
    func = ast.parse(source).body[0]
    assert isinstance(func, ast.FunctionDef) and func.name == "main"

    calls = list(_calls_outside_nested_defs(func))
    set_ui_lines = [c.lineno for c in calls if _callee_name(c) == "set_ui"]
    print_lines = [c.lineno for c in calls if _callee_name(c) == "print"]

    assert set_ui_lines, "no set_ui call found in main()"
    assert print_lines, "no print call found in main()"
    assert min(set_ui_lines) < min(print_lines)
