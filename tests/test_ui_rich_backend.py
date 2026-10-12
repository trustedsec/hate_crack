import io
import sys

from rich.console import Console

import hate_crack.cli
import hate_crack.menu
from hate_crack.ui.rich_ui import RichUI


def _ui(width=40, terminal=False):
    out, err = io.StringIO(), io.StringIO()
    ui = RichUI(
        console=Console(file=out, width=width, force_terminal=terminal),
        err_console=Console(file=err, width=width, force_terminal=terminal),
    )
    return ui, out, err


def test_highlight_disabled_so_hashes_and_numbers_are_not_recoloured():
    ui, out, _ = _ui(terminal=True)
    ui.say("5f4dcc3b5aa765d61d8327deb882cf99 /tmp/x 12345")
    assert "\033[" not in out.getvalue()


def test_highlight_false_passed_to_every_print():
    calls = []
    ui, _, _ = _ui()
    for c in (ui.console, ui.err_console):
        c.print = lambda *a, _c=calls, **k: _c.append(k)  # type: ignore[method-assign]
    ui.say("a")
    ui.warn("b")
    ui.success("c")
    ui.error("d")
    assert len(calls) == 4
    assert all(k.get("highlight") is False for k in calls)


def test_error_goes_to_stderr_console_only():
    ui, out, err = _ui()
    ui.error("boom")
    ui.warn("w")
    assert "boom" in err.getvalue() and "boom" not in out.getvalue()
    assert "w" in out.getvalue()


def test_styles():
    ui, out, err = _ui(terminal=True)
    ui.warn("w")
    ui.success("s")
    ui.error("e")
    assert "\033[33m" in out.getvalue()
    assert "\033[32m" in out.getvalue()
    assert "\033[1;31m" in err.getvalue()


def test_default_consoles_when_not_injected():
    ui = RichUI()
    assert isinstance(ui.console, Console)
    assert ui.err_console.stderr is True


def test_spinner_handle_has_set_detail_non_tty(monkeypatch):
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False, raising=False)
    import threading

    before = threading.active_count()
    ui, out, _ = _ui()
    with ui.spinner("working") as h:
        h.set_detail("5 lines")
        assert threading.active_count() == before
    assert out.getvalue().count("working") == 1


def test_columns_preserve_column_major_order():
    ui, out, _ = _ui(width=20)
    entries = [f"({i})" for i in range(1, 8)]
    ui.columns(None, entries, min_col_width=5, max_col_width=5)
    lines = [ln.split() for ln in out.getvalue().splitlines() if ln.strip()]
    # width 20 / col 5 = 4 cols, 7 entries -> 2 rows; entry = row + col * 2
    assert lines == [["(1)", "(3)", "(5)", "(7)"], ["(2)", "(4)", "(6)"]]


def test_columns_title_and_empty():
    ui, out, _ = _ui(width=20)
    ui.columns("T", ["a"])
    assert "T" in out.getvalue() and "====" in out.getvalue()
    ui2, out2, _ = _ui()
    ui2.columns("T", [])
    assert "(none)" in out2.getvalue()


def test_delegates_resolve_at_call_time(monkeypatch):
    monkeypatch.setattr(hate_crack.cli, "prompt_int", lambda *a, **k: 9)
    monkeypatch.setattr(hate_crack.menu, "interactive_menu", lambda *a, **k: "3")
    ui, _, _ = _ui()
    assert ui.ask_int("n") == 9
    assert ui.select([("3", "x")]) == "3"


def test_say_does_not_interpret_markup():
    ui, out, _ = _ui(width=80)
    ui.say("rock[you].txt")
    ui.say("[/] done")
    ui.warn("a[b]c")
    ui.success("[bold]x")
    ui.error("[/] e")
    assert "rock[you].txt" in out.getvalue()
    assert "[/] done" in out.getvalue()
    assert "a[b]c" in out.getvalue() and "[bold]x" in out.getvalue()


def test_ask_prompt_verbatim_and_whitespace_preserved(monkeypatch):
    ui, out, _ = _ui(width=80)
    monkeypatch.setattr("builtins.input", lambda _p="": " ")
    assert ui.ask("Pick [default 5]: ", default="5") == " "
    assert out.getvalue() == "Pick [default 5]: "
