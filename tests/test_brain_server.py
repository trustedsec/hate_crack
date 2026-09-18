import socket

import pytest

from hate_crack import brain


@pytest.fixture(autouse=True)
def _reset():
    brain.shutdown()
    yield
    brain.shutdown()


class _FakeProc:
    def __init__(self):
        self.killed = False
        self.returncode = None

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def test_no_spawn_when_something_already_answers(monkeypatch):
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: pytest.fail("must not spawn")
    )
    server = brain.ensure_server(
        {"brain_host": "", "brain_port": 6863, "brain_password": "given"}
    )
    assert server is not None
    assert server.spawned is False
    assert server.password == "given"


def test_spawns_when_the_port_is_closed(monkeypatch):
    proc = _FakeProc()
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)
    monkeypatch.setattr(brain, "_spawn_server", lambda *a, **k: proc)
    server = brain.ensure_server(
        {"brain_host": "", "brain_port": 6863, "brain_password": ""}
    )
    assert server is not None and server.spawned is True
    assert server.password, "an empty configured password must be generated"
    brain.shutdown()
    assert proc.killed is True


def test_never_spawns_for_a_remote_host(monkeypatch):
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: pytest.fail("must not spawn")
    )
    assert (
        brain.ensure_server(
            {"brain_host": "10.0.0.5", "brain_port": 6863, "brain_password": "x"}
        )
        is None
    )


def test_spawn_failure_degrades_to_no_brain(monkeypatch):
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)
    monkeypatch.setattr(brain, "_spawn_server", lambda *a, **k: None)
    assert (
        brain.ensure_server(
            {"brain_host": "", "brain_port": 6863, "brain_password": ""}
        )
        is None
    )


def test_ensure_server_is_idempotent(monkeypatch):
    calls = []
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: calls.append(1) or _FakeProc()
    )
    cfg = {"brain_host": "", "brain_port": 6863, "brain_password": ""}
    first = brain.ensure_server(cfg)
    second = brain.ensure_server(cfg)
    assert first is second
    assert len(calls) == 1


def test_port_probe_detects_a_real_listener():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(1)
    port = sock.getsockname()[1]
    try:
        assert brain._port_is_open("127.0.0.1", port) is True
    finally:
        sock.close()
    assert brain._port_is_open("127.0.0.1", port) is False
