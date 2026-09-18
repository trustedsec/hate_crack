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


def test_open_loopback_port_without_configured_password_yields_no_brain(monkeypatch):
    # An orphaned auto-spawned server (atexit never ran: SIGKILL, SIGTERM,
    # os._exit, a crash) ran on an ephemeral password that died with it. An
    # empty configured password can never match that, so adopting it would
    # fail authentication on every attack with no explanation. Give up on
    # brain for the session instead of adopting a server we cannot talk to.
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: pytest.fail("must not spawn")
    )
    assert (
        brain.ensure_server(
            {"brain_host": "", "brain_port": 6863, "brain_password": ""}
        )
        is None
    )


def test_spawn_argv_restricts_the_listener_to_loopback(monkeypatch, tmp_path):
    # Without an explicit bind flag hashcat's brain server binds every
    # interface. The _LOOPBACK check in ensure_server only gates whether we
    # spawn; it says nothing about what the spawned process listens on.
    captured = {}

    class _ImmediatelyListening:
        def poll(self):
            return None

    def _fake_popen(argv, **_kwargs):
        captured["argv"] = argv
        return _ImmediatelyListening()

    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    monkeypatch.setattr(brain.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)

    proc = brain._spawn_server("hashcat", 6863, "pw", 300)

    assert proc is not None
    argv = captured["argv"]
    assert "--brain-host" in argv
    assert argv[argv.index("--brain-host") + 1] == "127.0.0.1"


def test_spawn_waits_for_the_port_before_reporting_success(monkeypatch, tmp_path):
    # A flat "sleep then poll()" only proves the process hasn't exited; it
    # never proves the port is listening. A server that is slow to bind
    # must not be reported up until the port actually opens.
    proc = _FakeProc()
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    monkeypatch.setattr(brain.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(brain.time, "sleep", lambda seconds: None)

    calls = {"n": 0}

    def _port_is_open(host, port):
        calls["n"] += 1
        return calls["n"] >= 3  # closed on the first two checks, then open

    monkeypatch.setattr(brain, "_port_is_open", _port_is_open)

    result = brain._spawn_server("hashcat", 6863, "pw", 300)

    assert result is proc
    assert calls["n"] == 3
    assert proc.killed is False


def test_spawn_gives_up_if_the_port_never_opens(monkeypatch, tmp_path):
    proc = _FakeProc()
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    monkeypatch.setattr(brain.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)
    monkeypatch.setattr(brain.time, "sleep", lambda seconds: None)

    result = brain._spawn_server("hashcat", 6863, "pw", 300)

    assert result is None
    assert proc.killed is True


def test_keyboard_interrupt_during_spawn_kills_the_child_and_yields_no_brain(
    monkeypatch, tmp_path
):
    # A KeyboardInterrupt in the spawn window is a BaseException that a plain
    # `except (OSError, ValueError)` would not catch, so it would propagate
    # before _PROC is set -- orphaning the child where shutdown() can never
    # reach it. It must be caught, the child killed, and None returned.
    proc = _FakeProc()
    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    monkeypatch.setattr(brain.subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)

    def _raise(seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(brain.time, "sleep", _raise)

    result = brain._spawn_server("hashcat", 6863, "pw", 300)

    assert result is None
    assert proc.killed is True
