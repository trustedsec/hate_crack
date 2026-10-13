"""``run_terminal`` contract shared by every backend.

``fn`` is called exactly once, its value is returned, and anything it raises
(including ``KeyboardInterrupt``, a ``BaseException``) propagates unchanged.
"""

import pytest

from hate_crack.ui.plain import PlainUI
from hate_crack.ui.rich_ui import RichUI


@pytest.fixture(params=[PlainUI, RichUI], ids=lambda c: c.__name__)
def backend(request):
    return request.param()


def test_calls_once_and_returns_value(backend):
    calls = []

    def fn():
        calls.append(1)
        return "result"

    assert backend.run_terminal(fn) == "result"
    assert calls == [1]


@pytest.mark.parametrize(
    "exc", [ValueError("boom"), KeyboardInterrupt(), SystemExit(3)]
)
def test_exception_propagates_unchanged(backend, exc):
    calls = []

    def fn():
        calls.append(1)
        raise exc

    with pytest.raises(type(exc)) as info:
        backend.run_terminal(fn)
    assert info.value is exc
    assert calls == [1]
