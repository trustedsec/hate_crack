"""Bring up / tear down a local Hashview docker stack for the live test suite.

Used by the session-scoped ``hashview_local_stack`` fixture in ``conftest.py``.
Activated by ``HASHVIEW_TEST_LOCAL=1``; otherwise everything here is a no-op and
the live tests skip as before.

Lifecycle (when enabled):
  1. write ``hashview/config.conf`` with ``SERVER_NAME = 127.0.0.1:5000`` so the
     app is reachable from the host (a stale ``app:5000`` SERVER_NAME makes every
     request 404 via Flask host matching)
  2. ``docker compose up -d --build``
  3. poll until the app answers on the host
  4. seed the DB (admin api_key, customer, hashfile, cracked effective-task data)
  5. export ``HASHVIEW_*`` env vars so both the test helpers and the hate_crack
     CLI (which now honours ``HASHVIEW_URL`` / ``HASHVIEW_API_KEY``) target local
  6. on teardown ``docker compose down -v`` unless ``HASHVIEW_KEEP=1``

Config via env:
  HASHVIEW_TEST_LOCAL=1     enable the stack
  HASHVIEW_REPO=<path>      hashview checkout (default ~/projects/hashview)
  HASHVIEW_KEEP=1           leave containers running after the session
  HASHVIEW_LOCAL_PORT=5000  host port the app is published on
"""
import os
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

LOCAL_API_KEY = "3eac1ab7-e525-4bb7-b565-2c9f045dfc56"
CUSTOMER_ID = "1"
HASHFILE_ID = "1"
# md5 is hashcat mode 0; the suite's pwdump test uploads NTLM (1000). Seed both.
HASH_TYPE = "0"
SEED_HASH_TYPES = "0,1000"

_CONFIG_CONF = """[SERVER]
SERVER_NAME = 127.0.0.1:{port}
SECRET_KEY = hate-crack-local-test-secret

[database]
host = db
username = hashview
password = hashview

[SMTP]
server = smtp.example.com
port = 25
use_tls = False
username =
password =
default_sender =
"""


def enabled() -> bool:
    return os.environ.get("HASHVIEW_TEST_LOCAL", "").lower() in ("1", "true", "yes")


def _keep() -> bool:
    return os.environ.get("HASHVIEW_KEEP", "").lower() in ("1", "true", "yes")


def _repo() -> Path:
    return Path(
        os.environ.get("HASHVIEW_REPO", os.path.expanduser("~/projects/hashview"))
    ).resolve()


def _port() -> str:
    return os.environ.get("HASHVIEW_LOCAL_PORT", "5000")


def _base_url() -> str:
    return f"http://127.0.0.1:{_port()}"


def _compose(repo: Path, *args: str, check: bool = True, capture: bool = False):
    env = {**os.environ, "DOCKER_PLATFORM": os.environ.get("DOCKER_PLATFORM", "linux/amd64")}
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=str(repo),
        env=env,
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def _http_status(url: str, cookie: str | None = None):
    """Return the HTTP status for ``url`` (following no redirects), or None."""

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url)
    if cookie:
        req.add_header("Cookie", f"uuid={cookie}")
    try:
        with opener.open(req, timeout=3) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return None


# Statuses that mean "Flask is up and routing" — i.e. SERVER_NAME matches and
# the app is serving. ``/login`` answers 200 or 302 (redirect) depending on
# session/setup state; either is fine. A 404 means the route didn't match
# (e.g. a stale ``app:5000`` SERVER_NAME) and a connection error (None) means
# the app isn't listening yet.
_ROUTING_STATUSES = {200, 301, 302, 303, 403}


def _wait_ready(timeout: float = 240.0) -> bool:
    """Poll until the app is routing requests on ``/login``.

    On a cold start the DB volume is fresh, so the app boots and runs
    migrations before it stops connection-refusing. Routing (not auth/seed)
    readiness is the gate here; auth/seed readiness is checked separately in
    :func:`_wait_authenticated`.
    """
    url = f"{_base_url()}/login"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _http_status(url) in _ROUTING_STATUSES:
            return True
        time.sleep(2)
    return False


def _wait_authenticated(timeout: float = 60.0) -> bool:
    """Poll an authenticated endpoint until the seeded api_key is accepted.

    Closes the race where ``/login`` is up but the seed's admin api_key isn't
    effective yet: an unauthenticated ``/v1/customers`` 302-redirects (to an
    HTML page), while a recognised cookie returns 200 JSON.
    """
    url = f"{_base_url()}/v1/customers"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _http_status(url, cookie=LOCAL_API_KEY) == 200:
            return True
        time.sleep(2)
    return False


def _seed(repo: Path, attempts: int = 6) -> None:
    seeder = Path(__file__).with_name("hashview_local_seed.py")
    _compose(repo, "cp", str(seeder), "app:/tmp/hashview_local_seed.py")
    seed_env = [
        "-e", "PYTHONPATH=/",
        "-e", f"HASHVIEW_API_KEY={LOCAL_API_KEY}",
        "-e", f"HASHVIEW_CUSTOMER_ID={CUSTOMER_ID}",
        "-e", f"HASHVIEW_HASHFILE_ID={HASHFILE_ID}",
        "-e", f"HASHVIEW_SEED_HASH_TYPES={SEED_HASH_TYPES}",
    ]
    # The admin user (id=1) and default tasks are created during the app's
    # first-request boot, which can lag a few seconds behind the app routing.
    # Retry so a cold start doesn't fail on "Admin user not found".
    last = None
    for i in range(attempts):
        result = _compose(
            repo,
            "exec",
            "-T",
            *seed_env,
            "-w",
            "/",
            "app",
            "python",
            "/tmp/hashview_local_seed.py",
            check=False,
            capture=True,
        )
        if result.returncode == 0:
            return
        last = result.stdout
        time.sleep(5)
    raise RuntimeError(f"seed did not succeed after {attempts} attempts: {last}")


def _export_env() -> None:
    os.environ["HASHVIEW_TEST_REAL"] = "1"
    os.environ["HASHVIEW_URL"] = _base_url()
    os.environ["HASHVIEW_API_KEY"] = LOCAL_API_KEY
    os.environ["HASHVIEW_CUSTOMER_ID"] = CUSTOMER_ID
    os.environ["HASHVIEW_HASHFILE_ID"] = HASHFILE_ID
    os.environ.setdefault("HASHVIEW_HASH_TYPE", HASH_TYPE)


def setup():
    """Bring the stack up + seed. Returns a skip reason string, or None on success."""
    if shutil.which("docker") is None:
        return "docker not available"
    repo = _repo()
    if not repo.is_dir():
        return f"hashview repo not found at {repo} (set HASHVIEW_REPO)"
    if not (repo / "docker-compose.yml").is_file():
        return f"no docker-compose.yml in hashview repo {repo}"

    (repo / "hashview" / "config.conf").write_text(_CONFIG_CONF.format(port=_port()))
    try:
        _compose(repo, "up", "-d", "--build")
    except subprocess.CalledProcessError as exc:
        return f"docker compose up failed: {exc}"
    if not _wait_ready():
        return f"hashview app did not become ready at {_base_url()}"
    try:
        _seed(repo)
    except (subprocess.CalledProcessError, RuntimeError) as exc:
        return f"hashview DB seed failed: {exc}"
    if not _wait_authenticated():
        return "seeded api_key not accepted by Hashview (auth/seed race)"

    _export_env()
    return None


def teardown():
    if _keep():
        return
    repo = _repo()
    if repo.is_dir() and (repo / "docker-compose.yml").is_file():
        _compose(repo, "down", "-v", check=False, capture=True)
