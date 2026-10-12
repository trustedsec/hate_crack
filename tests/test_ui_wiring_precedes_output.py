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


_UI_METHODS = {"say", "warn", "error", "success", "ask"}


def _is_ui_output_call(call: ast.Call) -> bool:
    """True for a bare print(...) or a get_ui().<method>(...) call."""
    fn = call.func
    if isinstance(fn, ast.Name):
        return fn.id == "print"
    if (
        isinstance(fn, ast.Attribute)
        and fn.attr in _UI_METHODS
        and isinstance(fn.value, ast.Call)
        and isinstance(fn.value.func, ast.Name)
        and fn.value.func.id == "get_ui"
    ):
        return True
    return False


def test_set_ui_precedes_first_output_in_main():
    """set_ui must be called strictly before the first output call in main().

    Output means a bare print() or a get_ui().<say|warn|error|success|ask>()
    call. get_ui() lazily builds a PlainUI, so a call that runs before
    installation silently ignores ui_backend and nothing else would fail.
    The walk is scoped to main() itself and skips nested defs
    (_build_parser, _cleanup_preprocessing_temps), whose bodies do not run
    at main()'s top level.
    """
    source = textwrap.dedent(inspect.getsource(main_module.main))
    func = ast.parse(source).body[0]
    assert isinstance(func, ast.FunctionDef) and func.name == "main"

    calls = list(_calls_outside_nested_defs(func))
    set_ui_lines = [c.lineno for c in calls if _callee_name(c) == "set_ui"]
    output_lines = [c.lineno for c in calls if _is_ui_output_call(c)]

    assert set_ui_lines, "no set_ui call found in main()"
    assert output_lines, "no output call found in main()"
    assert min(set_ui_lines) < min(output_lines)
