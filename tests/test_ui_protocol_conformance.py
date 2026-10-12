import inspect

import pytest

import hate_crack.cli
import hate_crack.formatting
import hate_crack.menu
import hate_crack.progress
import hate_crack.ui as ui_pkg
from hate_crack.ui import UI, PlainUI, get_ui, reset_ui, set_ui

BACKEND_FACTORIES = [PlainUI]

UI_MEMBERS = [n for n in vars(UI) if not n.startswith("_")]


@pytest.fixture(autouse=True)
def _clean_ui():
    reset_ui()
    yield
    reset_ui()


@pytest.fixture(params=BACKEND_FACTORIES, ids=lambda f: f.__name__)
def backend(request):
    return request.param()


def test_protocol_member_list_is_exact():
    assert sorted(UI_MEMBERS) == sorted(
        [
            "say", "warn", "error", "success", "ask", "ask_int", "confirm",
            "select", "columns", "spinner", "suspend",
        ]
    )  # fmt: skip


@pytest.mark.parametrize("name", UI_MEMBERS)
def test_backend_signature_matches_protocol(backend, name):
    assert hasattr(backend, name)
    want = inspect.signature(getattr(UI, name))
    got = inspect.signature(getattr(type(backend), name))
    assert list(want.parameters) == list(got.parameters)
    for pname, wp in want.parameters.items():
        gp = got.parameters[pname]
        assert gp.kind == wp.kind, pname
        assert gp.default == wp.default, pname


def test_spinner_and_suspend_are_context_managers(backend):
    with backend.spinner("working"):
        pass
    with backend.suspend():
        pass


def test_get_set_reset_round_trip():
    first = get_ui()
    assert isinstance(first, PlainUI)
    assert get_ui() is first
    other = PlainUI()
    set_ui(other)
    assert get_ui() is other
    reset_ui()
    assert get_ui() is not other


def test_no_non_plain_backend_by_default():
    assert type(get_ui()) is PlainUI
    assert "build_ui" not in dir(ui_pkg)


def test_select_resolves_module_attribute_at_call_time(monkeypatch):
    calls = []

    def fake(items, title=None, prompt=""):
        calls.append((items, title, prompt))
        return "7"

    monkeypatch.setattr(hate_crack.menu, "interactive_menu", fake)
    assert PlainUI().select([("7", "x")], title="t", prompt="p") == "7"
    assert calls == [([("7", "x")], "t", "p")]


def test_columns_resolves_module_attribute_at_call_time(monkeypatch):
    calls = []
    monkeypatch.setattr(
        hate_crack.formatting,
        "print_multicolumn_list",
        lambda *a, **k: calls.append((a, k)),
    )
    PlainUI().columns("T", ["a"], min_col_width=5)
    assert calls == [
        (("T", ["a"]), {"min_col_width": 5, "max_col_width": None, "styles": None})
    ]


def test_confirm(monkeypatch):
    answers = iter(["maybe", " YES "])
    monkeypatch.setattr("builtins.input", lambda _p="": next(answers))
    assert PlainUI().confirm("ok? ") is True
    monkeypatch.setattr("builtins.input", lambda _p="": "")
    assert PlainUI().confirm("ok? ", default=False) is False
    monkeypatch.setattr("builtins.input", lambda _p="": "No")
    assert PlainUI().confirm("ok? ") is False

    def eof(_p=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert PlainUI().confirm("ok? ", default=False) is False


def test_say_and_ask(monkeypatch, capsys):
    ui = PlainUI()
    ui.say()
    ui.say("hi", style="bold")
    ui.warn("w")
    ui.error("x")
    ui.success("x")
    assert capsys.readouterr().out == "\nhi\nw\nx\nx\n"
    monkeypatch.setattr("builtins.input", lambda _p="": "")
    assert ui.ask("? ", default="d") == "d"


def test_ask_int_resolves_module_attribute_at_call_time(monkeypatch):
    calls = []

    def fake(prompt, default=None, minimum=None):
        calls.append((prompt, default, minimum))
        return 42

    monkeypatch.setattr(hate_crack.cli, "prompt_int", fake)
    assert PlainUI().ask_int("n? ", default=3, minimum=1) == 42
    assert calls == [("n? ", 3, 1)]


def test_spinner_resolves_module_attribute_at_call_time(monkeypatch):
    sentinel = object()
    calls = []

    def fake(message):
        calls.append(message)
        return sentinel

    monkeypatch.setattr(hate_crack.progress, "spinner", fake)
    assert PlainUI().spinner("busy") is sentinel
    assert calls == ["busy"]
