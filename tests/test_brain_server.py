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


def test_no_spawn_when_something_already_answers_an_explicit_loopback_host(monkeypatch):
    # An operator who typed a loopback address explicitly is pointing at a
    # server they expect to already be running there; the configured
    # password is trusted to be the one that server was started with.
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: pytest.fail("must not spawn")
    )
    server = brain.ensure_server(
        {"brain_host": "127.0.0.1", "brain_port": 6863, "brain_password": "given"}
    )
    assert server is not None
    assert server.spawned is False
    assert server.password == "given"


def test_empty_host_never_adopts_an_already_open_port_even_with_a_password(
    monkeypatch,
):
    # brain_host == "" means "hate_crack manages this," not "connect to
    # whatever is already there." An operator can have BRAIN_PASSWORD set
    # for an unrelated remote brain and still run with an empty brain_host;
    # the already-open port could be another hate_crack's ephemeral-password
    # auto-spawn, and trying a password we cannot verify would just fail
    # authentication on every attack. Never guess: give up on brain instead.
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: pytest.fail("must not spawn")
    )
    assert (
        brain.ensure_server(
            {
                "brain_host": "",
                "brain_port": 6863,
                "brain_password": "leftover-remote-password",
            }
        )
        is None
    )


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
    # Once spawned, the port answers for every later liveness re-probe, so a
    # second call must reuse the memo rather than spawning again.
    calls = []
    spawned = {"done": False}

    def _port(host, port):
        return spawned["done"]

    def _spawn(*a, **k):
        calls.append(1)
        spawned["done"] = True
        return _FakeProc()

    monkeypatch.setattr(brain, "_port_is_open", _port)
    monkeypatch.setattr(brain, "_spawn_server", _spawn)
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


def test_memoized_server_is_reused_when_still_reachable(monkeypatch):
    monkeypatch.setattr(
        brain, "_SERVER", brain.BrainServer("127.0.0.1", 6863, "pw", True)
    )
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)
    monkeypatch.setattr(
        brain, "_spawn_server", lambda *a, **k: pytest.fail("must not spawn")
    )
    server = brain.ensure_server(
        {"brain_host": "", "brain_port": 6863, "brain_password": ""}
    )
    assert server is not None
    assert server.port == 6863


def test_stale_memoized_server_is_reprobed_and_dropped(monkeypatch):
    # A server this process already established gets a stale memo the
    # moment it dies mid-session; without a re-probe every later attack in
    # the session keeps pointing at a corpse.
    monkeypatch.setattr(
        brain, "_SERVER", brain.BrainServer("127.0.0.1", 6863, "pw", True)
    )
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: False)
    monkeypatch.setattr(brain, "_spawn_server", lambda *a, **k: None)
    server = brain.ensure_server(
        {"brain_host": "", "brain_port": 6863, "brain_password": ""}
    )
    assert server is None
    assert brain._SERVER is None


def test_spawn_race_reprobe_adopts_with_a_configured_password(monkeypatch):
    # Two hate_crack processes racing to spawn: the loser's Popen either
    # fails to bind or exits, but the winner may already be listening by
    # the time the loser checks. A shared configured password means both
    # read it from the same config, so it is safe to trust here.
    calls = {"n": 0}

    def _port(host, port):
        calls["n"] += 1
        return calls["n"] > 1  # closed for the pre-spawn check, open after

    monkeypatch.setattr(brain, "_port_is_open", _port)
    monkeypatch.setattr(brain, "_spawn_server", lambda *a, **k: None)
    server = brain.ensure_server(
        {"brain_host": "", "brain_port": 6863, "brain_password": "shared"}
    )
    assert server is not None
    assert server.spawned is False
    assert server.password == "shared"


def test_spawn_race_reprobe_gives_up_without_a_configured_password(monkeypatch):
    # No configured password means we generated our own ephemeral one for
    # the spawn we lost the race for; it cannot be assumed to match
    # whatever the race winner is using.
    calls = {"n": 0}

    def _port(host, port):
        calls["n"] += 1
        return calls["n"] > 1

    monkeypatch.setattr(brain, "_port_is_open", _port)
    monkeypatch.setattr(brain, "_spawn_server", lambda *a, **k: None)
    assert (
        brain.ensure_server(
            {"brain_host": "", "brain_port": 6863, "brain_password": ""}
        )
        is None
    )


def test_spawn_uses_a_new_session_so_ctrl_c_does_not_kill_it(monkeypatch, tmp_path):
    # A terminal Ctrl-C delivers SIGINT to the whole foreground process
    # group. hate_crack catches its own KeyboardInterrupt and carries on;
    # the server must not be in that group or it dies with the interrupt.
    captured = {}

    class _ImmediatelyListening:
        def poll(self):
            return None

    def _fake_popen(argv, **kwargs):
        captured["kwargs"] = kwargs
        return _ImmediatelyListening()

    monkeypatch.setattr(brain, "brain_dir", lambda: tmp_path)
    monkeypatch.setattr(brain.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(brain, "_port_is_open", lambda host, port: True)

    proc = brain._spawn_server("hashcat", 6863, "pw", 300)

    assert proc is not None
    assert captured["kwargs"].get("start_new_session") is True


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
