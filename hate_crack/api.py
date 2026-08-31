import concurrent.futures
import html
import json
import re
import sys
import os
import shutil
import tempfile
import threading
import time
from queue import Queue
from typing import Callable, Optional, Tuple

import requests  # type: ignore[import-untyped]

from hate_crack.cli import orig_cwd
from hate_crack.config_loader import (
    ConfigFileJSONError,
    ConfigFileUnreadableError,
    load_config,
    resolve_config_paths,
)
from hate_crack.config_schema import CONFIG_SCHEMA, ConfigValueError
from hate_crack.formatting import print_multicolumn_list
from hate_crack import hashcat_paths
from hate_crack.plaintext import encode_hex_wrapper
from hate_crack.hashview_cache import append_to_cache, cache_key, load_cache

_TORRENT_CLEANUP_REGISTERED = False
_WEAKPASS_INERTIA_VERSION: str | None = None
HASHVIEW_DEFAULT_TIMEOUT = 30
# requests' scalar timeout caps connect time AND inter-byte read time, so a
# bulk upload/import POST needs headroom beyond the metadata-call default --
# a large payload can legitimately take the server longer than 30s to process
# before it sends the first response byte.
HASHVIEW_UPLOAD_TIMEOUT = 300
# Same reasoning as HASHVIEW_UPLOAD_TIMEOUT but for the read direction: a
# wordlist download is a streamed GET, and requests' scalar timeout caps the
# gap between chunks, not just connect time. A large wordlist (Hashview's
# "dynamic" combined list in particular) can legitimately have gaps between
# chunks longer than 30s under server load, which previously aborted the
# download outright rather than just running slower.
HASHVIEW_DOWNLOAD_TIMEOUT = 300
# A *dynamic* Hashview wordlist (Usernames, Customers, NTLM ciphertexts, the
# per-length "Recovered Passwords" buckets) is not stored at rest: the server
# regenerates it from the database and gzip -9s it before sending a single
# response byte (on-demand dynamic wordlists). requests' scalar timeout caps
# time-to-first-byte, so this has to cover server-side build time, not
# transfer time -- it scales with the size of the recovered-password corpus,
# not with the wire. HASHVIEW_DOWNLOAD_TIMEOUT stays 300s for static lists,
# which stream straight off disk and never hit this path.
HASHVIEW_DYNAMIC_DOWNLOAD_TIMEOUT = 1800
# Hashfile enumeration gets its own knob because it fails for its own reason.
# Both listing routes compute total/cracked counts per hashfile server-side, so
# their cost scales with the number of *hashes* involved, not the number of
# files: 73 small NetNTLMv2 captures list in 0.6s while 54 NTDS dumps holding
# 7.85M hashes took 549s on a measured production instance.
#
# Deliberately NOT larger than the default. No timeout short enough to be
# usable rescues a listing that needs nine minutes, so raising this only makes
# the failure slower to arrive. The fix for a server in that state is
# server-side (one GROUP BY instead of two COUNTs per hashfile); the client's
# job is to fail fast, say so, and let the operator enter the hashfile ID from
# the web UI. Separate from HASHVIEW_DEFAULT_TIMEOUT so an operator whose
# server is merely slow rather than pathological can raise it in one place.
HASHVIEW_LISTING_TIMEOUT = 30
# A sweep abandons after this many timed-out types. A server slow enough to
# blow the listing budget twice will not answer the remaining types either, and
# the alternative is 26 x HASHVIEW_LISTING_TIMEOUT of dead waiting.
HASHVIEW_LISTING_TIMEOUT_BUDGET = 2
HASHVIEW_CRACKED_BATCH_SIZE = 10_000


def _http_status(exc):
    """Return the HTTP status carried by ``exc``, or None.

    None means "no response at all" -- a timeout, a DNS failure, a refused
    connection. Distinguishing that from a real status matters: a 404 says a
    route is absent and the caller should fall back, while a timeout says
    nothing about the route and must not be read as an answer.
    """
    return getattr(getattr(exc, "response", None), "status_code", None)


class _RateLimiter:
    """Simple rate limiter: at most ``rate`` requests per ``period`` seconds."""

    def __init__(self, rate: float = 1, period: float = 2.0):
        self._lock = threading.Lock()
        self._min_interval = period / rate
        self._last_request = 0.0

    def wait(self):
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_request
            if elapsed < self._min_interval:
                time.sleep(self._min_interval - elapsed)
            self._last_request = time.monotonic()


_hashmob_limiter = _RateLimiter(rate=1, period=2.0)


class _Hashmob429(Exception):
    """Raised inside a _with_hashmob_backoff callback to trigger a backoff retry."""

    def __init__(self, retry_after: float | None = None) -> None:
        super().__init__()
        self.retry_after = retry_after


def _parse_retry_after(resp) -> float | None:
    """Parse a Retry-After header (seconds) from a 429 response, if present."""
    raw = resp.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def _stream_response_to_file(
    r,
    dest_path: str,
    *,
    label: str | None = None,
    show_progress: bool = True,
    chunk_size: int = 8192,
) -> bool:
    """Write an already-opened streaming response to dest_path atomically via a .part file."""
    temp_path = dest_path + ".part"
    try:
        total = 0
        try:
            total = int(r.headers.get("content-length") or 0)
        except Exception:
            pass
        downloaded = 0
        os.makedirs(os.path.dirname(os.path.abspath(dest_path)), exist_ok=True)
        with open(temp_path, "wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if show_progress:
                        if total:
                            done = int(50 * downloaded / total)
                            percent = 100 * downloaded / total
                            bar = "=" * done + " " * (50 - done)
                            sys.stdout.write(
                                f"\r[{bar}] {percent:6.2f}% ({downloaded // 1024} KB/{total // 1024} KB)"
                            )
                        else:
                            sys.stdout.write(f"\rDownloaded {downloaded // 1024} KB")
                        sys.stdout.flush()
        if show_progress:
            sys.stdout.write("\n")
        os.replace(temp_path, dest_path)
        print(f"Downloaded {dest_path}")
        return True
    except KeyboardInterrupt:
        print("\nKeyboard interrupt: Cleaning up partial download...")
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                print(f"Removed partial file: {temp_path}")
            except Exception as e:
                print(f"Failed to remove partial file: {e}")
        raise
    except Exception as e:
        print(f"Error during download: {e}")
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        return False


def _streamed_download(
    url: str,
    dest_path: str,
    *,
    headers: dict | None = None,
    label: str | None = None,
    timeout: int = 120,
    chunk_size: int = 8192,
    show_progress: bool = True,
    skip_existing: bool = False,
    allow_redirects: bool = True,
) -> bool:
    """Download url to dest_path atomically, with optional progress bar.

    Returns True on success, False on handled failure.
    Re-raises KeyboardInterrupt after cleaning up the .part file.
    """
    if skip_existing and os.path.isfile(dest_path) and os.path.getsize(dest_path) > 0:
        name = label or os.path.basename(dest_path)
        print(f"[i] Skipping {name} (already present)")
        return True
    try:
        with requests.get(
            url,
            headers=headers or {},
            stream=True,
            timeout=timeout,
            allow_redirects=allow_redirects,
        ) as r:
            r.raise_for_status()
            return _stream_response_to_file(
                r,
                dest_path,
                label=label,
                show_progress=show_progress,
                chunk_size=chunk_size,
            )
    except KeyboardInterrupt:
        raise
    except Exception as e:
        print(f"Error downloading {label or url}: {e}")
        return False


def _with_hashmob_backoff(
    fn: Callable[[], bool],
    *,
    max_attempts: int = 6,
    base_delay: int = 30,
    step: int = 30,
    max_delay: int = 300,
) -> bool:
    """Call fn() with bounded 429 backoff retry logic.

    fn() should raise _Hashmob429 to signal a rate-limit response.
    Non-429 exceptions are re-raised immediately.
    Returns True on success, False after max_attempts consecutive 429s.
    """
    penalty = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except _Hashmob429 as e:
            if attempt == max_attempts - 1:
                break
            delay = penalty
            if e.retry_after is not None:
                delay = min(e.retry_after, max_delay)
            print(f"[!] Rate limit hit (429). Backing off for {delay} seconds...")
            time.sleep(delay)
            penalty = min(penalty + step, max_delay)
            step *= 2
    print(f"[!] Hashmob rate limit: gave up after {max_attempts} attempts.")
    return False


def _get_hate_path():
    _package_path = os.path.dirname(os.path.realpath(__file__))
    _repo_root = os.path.dirname(_package_path)
    if os.path.isdir(os.path.join(_package_path, "hashcat-utils")):
        return _package_path
    elif os.path.isdir(os.path.join(_repo_root, "hashcat-utils")):
        return _repo_root
    return _package_path


def _resolve_env_path():
    """Path of the `.env` the loader would read, or ``None``."""
    return resolve_config_paths()[0]


def _resolve_config_path():
    """Path of the ``config.json``, or ``None``.

    Kept as a named seam (the test suite patches it) but the directory search
    order itself now lives in :func:`hate_crack.config_loader.candidate_roots`
    -- api.py used to keep its own near-copy of main.py's order, which is
    exactly the drift that produced #153.
    """
    return resolve_config_paths()[1]


def check_7z():
    import shutil

    if shutil.which("7z") or shutil.which("7za"):
        return True
    print("\n[!] 7z (or 7za) is missing.")
    print("To install on macOS:  brew install p7zip")
    print("To install on Ubuntu/Debian:  sudo apt-get install p7zip-full")
    print("Please install 7z and try again.")
    return False


def check_transmission_daemon():
    import shutil

    daemon = shutil.which("transmission-daemon")
    remote = shutil.which("transmission-remote")
    if daemon and remote:
        return True
    print("\n[!] transmission-daemon and/or transmission-remote is missing.")
    print("To install on macOS:  brew install transmission-cli")
    print("To install on Ubuntu/Debian:  sudo apt-get install transmission-daemon")
    print("Please install transmission-daemon and transmission-remote and try again.")
    return False


def _pick_free_port() -> int:
    """Pick an unused TCP port on localhost by binding to port 0."""
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


class TransmissionSession:
    """Context manager that runs a private transmission-daemon process.

    All torrents are added/managed via transmission-remote. The daemon is
    spawned with a fresh tempdir config and an unused localhost RPC port,
    so it never collides with any pre-existing transmission-daemon. Exiting
    the context (or process exit via atexit) sends ``--exit`` and cleans
    up the temporary config directory.
    """

    def __init__(
        self,
        save_dir: str,
        *,
        poll_interval: float = 3.0,
        startup_timeout: float = 15.0,
        shutdown_timeout: float = 15.0,
    ):
        self.save_dir = save_dir
        self.poll_interval = poll_interval
        self.startup_timeout = startup_timeout
        self.shutdown_timeout = shutdown_timeout
        self._cfg_dir = ""
        self._port = 0
        self._rpc = ""
        self._proc = None
        self._stopped = False

    def __enter__(self):
        import atexit
        import subprocess

        self._cfg_dir = tempfile.mkdtemp(prefix="hate_crack_transmission_")
        self._port = _pick_free_port()
        self._rpc = f"127.0.0.1:{self._port}"
        self._proc = subprocess.Popen(
            [
                "transmission-daemon",
                "-f",
                "-g",
                self._cfg_dir,
                "--port",
                str(self._port),
                "--rpc-bind-address",
                "127.0.0.1",
                "--no-auth",
                "--download-dir",
                self.save_dir,
                "--no-portmap",
                "--no-watch-dir",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            probe = subprocess.run(
                ["transmission-remote", self._rpc, "-l"],
                capture_output=True,
            )
            if probe.returncode == 0:
                break
            time.sleep(0.5)
        else:
            self._stop()
            raise RuntimeError("Transmission daemon failed to start")
        atexit.register(self._stop)
        return self

    def _stop(self):
        import subprocess

        if self._stopped:
            return
        self._stopped = True
        if self._rpc:
            try:
                subprocess.run(
                    ["transmission-remote", self._rpc, "--exit"],
                    capture_output=True,
                )
            except Exception:
                pass
        if self._proc is not None:
            try:
                self._proc.wait(timeout=self.shutdown_timeout)
            except subprocess.TimeoutExpired:
                try:
                    self._proc.terminate()
                    try:
                        self._proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self._proc.kill()
                except Exception:
                    pass
            except Exception:
                pass
        if self._cfg_dir:
            shutil.rmtree(self._cfg_dir, ignore_errors=True)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stop()
        return None

    def add(self, torrent_path: str) -> int:
        import re
        import subprocess

        before_ids = {e["id"] for e in self.list()}
        result = subprocess.run(
            [
                "transmission-remote",
                self._rpc,
                "-a",
                torrent_path,
            ],
            capture_output=True,
            text=True,
        )
        out = result.stdout or ""
        m = re.search(r"Added torrent.*\n.*ID:\s*(\d+)", out)
        if m:
            return int(m.group(1))
        m = re.search(r"torrent added\s*\(id\s+(\d+)\)", out, re.IGNORECASE)
        if m:
            return int(m.group(1))
        after_entries = self.list()
        new_ids = [e["id"] for e in after_entries if e["id"] not in before_ids]
        if new_ids:
            return new_ids[0]
        raise RuntimeError(f"Failed to add torrent: {torrent_path}")

    def list(self) -> list:
        import subprocess

        result = subprocess.run(
            ["transmission-remote", self._rpc, "-l"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return []
        entries = []
        try:
            lines = (result.stdout or "").splitlines()
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("ID"):
                    continue
                if stripped.startswith("Sum:"):
                    continue
                tokens = stripped.split()
                if not tokens:
                    continue
                # First token must be an integer ID
                try:
                    tid = int(tokens[0])
                except ValueError:
                    continue
                # transmission-remote -l columns:
                # ID  Done  Have  ETA  Up  Down  Ratio  Status  Name
                # Done is tokens[1], like "100%" or "0%".
                percent_str = tokens[1] if len(tokens) > 1 else "0%"
                try:
                    percent_done = float(percent_str.rstrip("%"))
                except ValueError:
                    percent_done = 0.0
                # Status is tokens[7] (best-effort); name is the rest.
                status = tokens[7] if len(tokens) > 8 else ""
                name = (
                    " ".join(tokens[8:])
                    if len(tokens) > 8
                    else (tokens[-1] if len(tokens) > 1 else "")
                )
                entries.append(
                    {
                        "id": tid,
                        "percent_done": percent_done,
                        "status": status,
                        "name": name,
                    }
                )
        except Exception:
            return []
        return entries

    def info_file(self, torrent_id: int) -> str:
        import subprocess

        result = subprocess.run(
            [
                "transmission-remote",
                self._rpc,
                f"-t{torrent_id}",
                "--info-files",
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            return ""
        import re

        try:
            lines = (result.stdout or "").splitlines()
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                # Data rows look like: "0: 100% Normal Yes 1.50 GB my-list.7z"
                # i.e. they start with an integer followed by a colon.
                m = re.match(r"^\d+:\s+(.*)$", stripped)
                if not m:
                    continue
                rest = m.group(1)
                # Columns after "<id>:" are: Done Priority Get Size Unit Name
                # Split into 6 tokens; 5 splits gives us up to the Name field.
                tokens = rest.split(None, 5)
                if len(tokens) >= 6:
                    return tokens[5]
                # Less-formal output: return whatever follows the percent token.
                tokens = rest.split(None, 1)
                if len(tokens) == 2:
                    return tokens[1]
                return rest
            return ""
        except Exception:
            return ""

    def remove(self, torrent_id: int):
        import subprocess

        subprocess.run(
            [
                "transmission-remote",
                self._rpc,
                f"-t{torrent_id}",
                "--remove",
            ],
            capture_output=True,
        )

    def wait_for_all(self, on_complete: Callable[[int, str], None]) -> None:
        completed_ids: set = set()
        while True:
            time.sleep(self.poll_interval)
            entries = self.list()
            if not entries:
                break
            for entry in entries:
                if entry["percent_done"] >= 100.0 and entry["id"] not in completed_ids:
                    completed_ids.add(entry["id"])
                    file_name = self.info_file(entry["id"])
                    on_complete(entry["id"], file_name)
                    self.remove(entry["id"])


def _load_merged_config():
    """The same merged config ``main.py`` runs on, via the shared loader.

    Delegates to :func:`hate_crack.config_loader.load_config`, so api.py and
    main.py cannot disagree about defaults, precedence, or coercion. That
    duplication is what #153 was: api.py's helpers reimplemented the
    example-plus-user merge and drifted from main.py's copy.

    Unlike main.py, a bad config file must not take the process down here --
    these helpers are called from deep inside menu actions. Any load failure
    degrades to the schema defaults.
    """
    try:
        return load_config(
            env_path=_resolve_env_path(),
            legacy_json_path=_resolve_config_path(),
        ).config
    except (ConfigValueError, ConfigFileJSONError, ConfigFileUnreadableError):
        return {entry.legacy: entry.default for entry in CONFIG_SCHEMA}


def get_hcat_wordlists_dir():
    config = _load_merged_config()
    path = config.get("hcatWordlists")
    if path:
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(_get_hate_path(), path))
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except OSError:
            pass
    default = os.path.join(os.getcwd(), "wordlists")
    os.makedirs(default, exist_ok=True)
    return default


def get_rules_dir():
    config = _load_merged_config()
    path = config.get("rules_directory")
    if path:
        path = os.path.expanduser(path)
        if not os.path.isabs(path):
            path = os.path.normpath(os.path.join(_get_hate_path(), path))
        try:
            os.makedirs(path, exist_ok=True)
            return path
        except OSError:
            pass
    default = os.path.join(os.getcwd(), "rules")
    os.makedirs(default, exist_ok=True)
    return default


def get_hcat_tuning_args():
    config = _load_merged_config()
    tuning = config.get("hcatTuning")
    if tuning:
        import shlex

        return shlex.split(tuning)
    return []


def get_hcat_potfile_path():
    """Return the resolved potfile path from config, or the default."""
    config = _load_merged_config()
    raw = config.get("hcatPotfilePath", hashcat_paths.AUTO)
    return hashcat_paths.resolve_potfile_setting(
        raw,
        base_dir=_get_hate_path(),
        hcat_bin=str(config.get("hcatBin") or "hashcat"),
    )


def get_hcat_potfile_args():
    """Return potfile args list for hashcat, e.g. ['--potfile-path=/path']."""
    pot = get_hcat_potfile_path()
    if pot:
        return [f"--potfile-path={pot}"]
    return []


def cleanup_torrent_files(directory=None):
    """Remove stray .torrent files left in the hate_crack temp directory on graceful exit."""
    if directory is None:
        directory = os.path.join(tempfile.gettempdir(), "hate_crack")
    try:
        for name in os.listdir(directory):
            if name.endswith(".torrent"):
                path = os.path.join(directory, name)
                try:
                    os.remove(path)
                except Exception as e:
                    print(f"[!] Failed to remove torrent file {path}: {e}")
    except Exception as e:
        print(f"[!] Failed to cleanup torrent files in {directory}: {e}")


def register_torrent_cleanup():
    global _TORRENT_CLEANUP_REGISTERED
    if _TORRENT_CLEANUP_REGISTERED:
        return
    import atexit

    atexit.register(cleanup_torrent_files)
    _TORRENT_CLEANUP_REGISTERED = True


def run_torrent_session(torrent_files, save_dir, *, print_fn=print) -> None:
    """Run a single transmission-daemon session that downloads all
    ``torrent_files`` into ``save_dir`` in parallel.

    For each torrent that completes, the resulting file is auto-extracted
    if it ends with ``.7z``. The daemon is torn down on exit (clean or
    interrupted).
    """
    if not check_transmission_daemon():
        return
    if not check_7z():
        return
    completed = 0
    failed = 0

    def on_complete(torrent_id, file_path):
        nonlocal completed, failed
        if not file_path:
            failed += 1
            return
        abs_path = (
            file_path if os.path.isabs(file_path) else os.path.join(save_dir, file_path)
        )
        if abs_path.endswith(".7z"):
            ok = extract_with_7z(abs_path, save_dir, remove_archive=True)
            if ok:
                completed += 1
            else:
                failed += 1
        else:
            completed += 1

    try:
        with TransmissionSession(save_dir) as ts:
            for tf in torrent_files:
                try:
                    ts.add(tf)
                    print_fn(f"[i] Added torrent: {tf}")
                except Exception as e:
                    print_fn(f"[!] Failed to add torrent {tf}: {e}")
                    failed += 1
            ts.wait_for_all(on_complete=on_complete)
    except KeyboardInterrupt:
        print_fn("\n[!] Torrent download interrupted.")
        raise
    print_fn(f"[i] Torrent session complete: {completed} succeeded, {failed} failed.")


def _get_weakpass_inertia_version(headers: dict) -> str | None:
    global _WEAKPASS_INERTIA_VERSION
    if _WEAKPASS_INERTIA_VERSION:
        return _WEAKPASS_INERTIA_VERSION
    try:
        r = requests.get("https://weakpass.com/wordlists", headers=headers, timeout=30)
        m = re.search(r'data-page="([^"]*)"', r.text)
        if not m:
            return None
        raw = html.unescape(m.group(1))
        data = json.loads(raw)
        version = data.get("version")
        if version:
            _WEAKPASS_INERTIA_VERSION = version
        return version
    except Exception:
        return None


def _fetch_weakpass_listing_page(
    page: int, headers: dict
) -> tuple[list[dict], int | None]:
    url = f"https://weakpass.com/wordlists?page={page}"
    version = _get_weakpass_inertia_version(headers)
    if version:
        req_headers = {
            **headers,
            "X-Inertia": "true",
            "X-Inertia-Version": version,
            "X-Requested-With": "XMLHttpRequest",
        }
        r = requests.get(url, headers=req_headers, timeout=30)
        if r.status_code == 409:
            global _WEAKPASS_INERTIA_VERSION
            _WEAKPASS_INERTIA_VERSION = None
            r = requests.get(url, headers=headers, timeout=30)
            if r.status_code != 200:
                return [], None
            return _parse_weakpass_html_page(r.text)
        if r.status_code != 200:
            return [], None
        try:
            data = r.json()
        except Exception:
            return [], None
    else:
        r = requests.get(url, headers=headers, timeout=30)
        if r.status_code != 200:
            return [], None
        return _parse_weakpass_html_page(r.text)

    return _extract_weakpass_entries(data)


def _parse_weakpass_html_page(page_html: str) -> tuple[list[dict], int | None]:
    m = re.search(r'data-page="([^"]*)"', page_html)
    if not m:
        return [], None
    try:
        data = json.loads(html.unescape(m.group(1)))
    except Exception:
        return [], None
    return _extract_weakpass_entries(data)


def _extract_weakpass_entries(data: dict) -> tuple[list[dict], int | None]:
    wordlists_raw = data.get("props", {}).get("wordlists", {})
    last_page = None
    if isinstance(wordlists_raw, dict):
        last_page = wordlists_raw.get("last_page") or wordlists_raw.get("meta", {}).get(
            "last_page"
        )
        wordlists_raw = wordlists_raw.get("data", [])
    if not isinstance(wordlists_raw, list):
        return [], last_page
    entries = [
        {
            "id": wl.get("id", ""),
            "name": wl.get("name", ""),
            "size": wl.get("size", ""),
            "rank": wl.get("rank", ""),
            "downloads": wl.get("downloaded", ""),
            "torrent_url": wl.get("torrent_link", ""),
        }
        for wl in wordlists_raw
    ]
    return entries, last_page


def fetch_all_weakpass_wordlists_multithreaded(total_pages=None, threads=10):
    """Fetch all Weakpass wordlists. Auto-detects page count from the Inertia payload."""
    headers = {"User-Agent": "Mozilla/5.0"}

    # Determine total_pages via probe if not provided
    if total_pages is None:
        try:
            entries1, detected = _fetch_weakpass_listing_page(1, headers)
            if detected:
                total_pages = int(detected)
                print(f"[i] Weakpass: {total_pages} pages detected")
            elif entries1:
                # last_page not in payload; fall back to sequential until empty
                all_wordlists = list(entries1)
                page = 2
                while True:
                    try:
                        entries, _ = _fetch_weakpass_listing_page(page, headers)
                    except Exception as e:
                        print(f"Error fetching page {page}: {e}")
                        break
                    if not entries:
                        break
                    all_wordlists.extend(entries)
                    page += 1
                # de-duplicate and return early
                seen = set()
                result = []
                for wl in all_wordlists:
                    if wl["name"] not in seen:
                        result.append(wl)
                        seen.add(wl["name"])
                return result
            else:
                print(
                    "[!] Weakpass page 1 returned no results; falling back to 67 pages"
                )
                total_pages = 67
                entries1 = []
        except Exception as e:
            print(f"[!] Weakpass probe failed ({e}); falling back to 67 pages")
            total_pages = 67
            entries1 = []
    else:
        entries1 = []

    # Thread-pool fetch for pages 1..total_pages
    # (If we already have entries1 from the probe, we skip page 1 in the pool)
    wordlists = list(entries1)
    lock = threading.Lock()
    q = Queue()

    def worker():
        while True:
            page = q.get()
            if page is None:
                break
            try:
                entries, _ = _fetch_weakpass_listing_page(page, headers)
                with lock:
                    wordlists.extend(entries)
            except Exception as e:
                print(f"Error fetching page {page}: {e}")
            finally:
                q.task_done()

    start_page = 2 if entries1 else 1
    for page in range(start_page, total_pages + 1):
        q.put(page)

    threads_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.start()
        threads_list.append(t)

    q.join()

    for _ in range(threads):
        q.put(None)
    for t in threads_list:
        t.join()

    seen = set()
    unique_wordlists = []
    for wl in wordlists:
        if wl["name"] not in seen:
            unique_wordlists.append(wl)
            seen.add(wl["name"])

    return unique_wordlists


def _match_entry(entries: list[dict], filename: str) -> tuple[int, str] | None:
    wordlist_base = (
        filename.replace(".torrent", "").replace(".7z", "").replace(".txt", "")
    )
    for wl in entries:
        if wl.get("name") == filename or wordlist_base in wl.get("name", ""):
            wl_id = wl.get("id")
            torrent_link = wl.get("torrent_url", "")
            if wl_id and torrent_link:
                return (wl_id, torrent_link)
    return None


def fetch_torrent_metadata(torrent_url, save_dir=None, wordlist_id=None):
    """Download the .torrent metadata file from Weakpass and return its local path.

    Returns the path to the saved .torrent file, or None on failure.
    The .torrent file is stored in the system temp directory, not the wordlist dir.
    """
    register_torrent_cleanup()

    torrent_dir = os.path.join(tempfile.gettempdir(), "hate_crack")
    os.makedirs(torrent_dir, exist_ok=True)
    # Do not send Hashmob API key to weakpass.com
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    # Resolve a filename even if a URL is provided.
    if not torrent_url.startswith("http"):
        filename = torrent_url
    else:
        filename = torrent_url.split("/")[-1]

    torrent_link = None
    if torrent_url.startswith("http"):
        torrent_link = torrent_url
    elif wordlist_id:
        torrent_link = f"https://weakpass.com/download/{wordlist_id}/{torrent_url}"
    else:
        entries, last_page = _fetch_weakpass_listing_page(1, headers)
        match = _match_entry(entries, filename)
        if not match and last_page and last_page > 1:
            for page in range(2, last_page + 1):
                entries, _ = _fetch_weakpass_listing_page(page, headers)
                match = _match_entry(entries, filename)
                if match:
                    break
        if match:
            resolved_id, torrent_link_from_data = match
            torrent_link = (
                f"https://weakpass.com/download/{resolved_id}/{torrent_link_from_data}"
            )

    if not torrent_link:
        torrent_link = f"https://weakpass.com/files/{filename}"

    print(f"[+] Downloading .torrent file from: {torrent_link}")
    r2 = requests.get(torrent_link, headers=headers, stream=True)
    content_type = r2.headers.get("Content-Type", "")
    local_filename = os.path.join(
        torrent_dir,
        filename if filename.endswith(".torrent") else filename + ".torrent",
    )
    if r2.status_code == 200 and not content_type.startswith("text/html"):
        with open(local_filename, "wb") as f:
            for chunk in r2.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        print(f"Saved to {local_filename}")
    else:
        print(f"Failed to download a valid torrent file: {torrent_link}")
        try:
            response_body = r2.content.decode(errors="replace")
            print("--- Begin HTML Debug Output ---")
            print(response_body[:2000])
            print("--- End HTML Debug Output ---")
        except Exception as e:
            print(f"Could not decode response for debug: {e}")
        return None

    return local_filename


def download_torrent_file(torrent_url, save_dir=None, wordlist_id=None):
    """Download and run a single Weakpass torrent. Kept for API compatibility."""
    if save_dir is None:
        save_dir = get_hcat_wordlists_dir()
    meta = fetch_torrent_metadata(
        torrent_url, save_dir=save_dir, wordlist_id=wordlist_id
    )
    if meta:
        run_torrent_session([meta], save_dir)
    return meta


def weakpass_wordlist_menu(rank=-1):
    try:
        all_wordlists = fetch_all_weakpass_wordlists_multithreaded()
    except Exception as e:
        print(f"Failed to fetch wordlists: {e}")
        return
    if rank == 0:
        filtered_wordlists = all_wordlists
    elif rank > 0:
        filtered_wordlists = [
            wl for wl in all_wordlists if str(wl.get("rank", "")) == str(rank)
        ]
    else:
        # Default: show all with rank > 4
        filtered_wordlists = [
            wl for wl in all_wordlists if str(wl.get("rank", "")) > "4"
        ]
    print("\nEach entry shows: [number]. [wordlist name] [effectiveness score] [rank]")
    entries = []
    for idx, wl in enumerate(filtered_wordlists):
        effectiveness = wl.get("effectiveness", wl.get("downloads", ""))
        rank = wl.get("rank", "")
        name = str(wl.get("name", ""))[:30]
        entry = f"{idx + 1:3d}. {name:<30} {effectiveness:<8} {rank:<2}"
        entries.append(entry)
    max_entry_len = max((len(e) for e in entries), default=36)
    print_multicolumn_list(
        "Available Wordlists",
        entries,
        min_col_width=max_entry_len,
        max_col_width=max_entry_len,
    )

    def parse_indices(selection, max_index):
        indices = set()
        for part in selection.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-", 1))
                    if start > end:
                        start, end = end, start
                    indices.update(range(start, end + 1))
                except Exception:
                    continue
            else:
                try:
                    indices.add(int(part))
                except Exception:
                    continue
        return sorted(i for i in indices if 1 <= i <= max_index)

    def _safe_input(prompt):
        try:
            if not sys.stdin or not sys.stdin.isatty():
                return "q"
        except Exception:
            return "q"
        try:
            return input(prompt)
        except EOFError:
            return "q"

    try:
        sel = _safe_input(
            "\nEnter the number(s) to download (e.g. 1,3,5-7) or 'q' to cancel: "
        )
        if sel.lower() == "q":
            print("Returning to menu...")
            return
        indices = parse_indices(sel, len(filtered_wordlists))
        if not indices:
            print("No valid selection.")
            return
        save_dir = get_hcat_wordlists_dir()
        torrent_files = []
        for idx in indices:
            entry = filtered_wordlists[idx - 1]
            torrent_url = entry.get("torrent_url")
            if not torrent_url:
                print(f"[!] Missing torrent URL for selection {idx}")
                continue
            meta = fetch_torrent_metadata(
                torrent_url, save_dir=save_dir, wordlist_id=entry.get("id")
            )
            if meta:
                torrent_files.append(meta)
        if torrent_files:
            run_torrent_session(torrent_files, save_dir)
        else:
            print("[!] No torrent metadata files were fetched successfully.")
    except KeyboardInterrupt:
        print("\nKeyboard interrupt: Returning to main menu...")
        return
    except Exception as e:
        print(f"Error: {e}")


def _md4(data: bytes) -> str:
    """Pure-Python MD4 (OpenSSL 3 dropped md4, so hashlib can't be relied on).

    Used to compute NTLM digests for client-side plaintext validation.
    """
    import struct

    def lrot(x, n):
        x &= 0xFFFFFFFF
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    msg = bytearray(data)
    ml = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", ml)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off : off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):
            a = lrot(a + ((b & c) | (~b & d)) + X[i], 3)
            d = lrot(d + ((a & b) | (~a & c)) + X[i + 1], 7)
            c = lrot(c + ((d & a) | (~d & b)) + X[i + 2], 11)
            b = lrot(b + ((c & d) | (~c & a)) + X[i + 3], 19)
        for i in (0, 1, 2, 3):
            a = lrot(a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999, 3)
            d = lrot(d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999, 5)
            c = lrot(c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999, 9)
            b = lrot(b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999, 13)
        for i in (0, 2, 1, 3):
            a = lrot(a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1, 3)
            d = lrot(d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1, 9)
            c = lrot(c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1, 11)
            b = lrot(b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d).hex()


# Expected hex-digest length (in chars) for each supported hashcat mode.
# Option 1: cheap structural filter that catches wrong-width hashes.
_HASH_HEX_LEN = {
    "0": 32,  # MD5
    "100": 40,  # SHA1
    "900": 32,  # MD4
    "1000": 32,  # NTLM
    "1400": 64,  # SHA2-256
    "1700": 128,  # SHA2-512
    "3000": 16,  # LM (half)
}


def _decode_plaintext(plaintext: str) -> bytes:
    """Decode a hashcat plaintext, expanding $HEX[...] to raw bytes."""
    if plaintext.startswith("$HEX[") and plaintext.endswith("]"):
        inner = plaintext[5:-1]
        try:
            return bytes.fromhex(inner)
        except ValueError:
            return plaintext.encode("utf-8", "surrogateescape")
    return plaintext.encode("utf-8", "surrogateescape")


def _read_found_pairs(path) -> Tuple[list, list]:
    """Return ``(pairs, undecodable)`` for a hashcat-style ``hash:plain`` file.

    Read as bytes so a plaintext holding a non-UTF-8 byte survives as
    ``$HEX[...]`` instead of being silently rewritten into a different password
    — these values are appended to the potfile and uploaded to Hashview, where
    a lossy decode becomes durable corruption. A line whose *hash* field is not
    decodable is returned in ``undecodable`` for the caller to report rather
    than dropped without a word.
    """
    pairs: list = []
    undecodable: list = []
    with open(path, "rb") as fh:
        for raw_line in fh:
            # rstrip only the line terminator -- a plain .strip() eats a
            # leading/trailing space that belongs to the password itself.
            raw_line = raw_line.rstrip(b"\r\n")
            if not raw_line or b":" not in raw_line:
                continue
            hash_raw, plain_raw = raw_line.rsplit(b":", 1)
            try:
                hash_text = hash_raw.decode("utf-8")
            except UnicodeDecodeError:
                undecodable.append(raw_line)
                continue
            pairs.append((hash_text, encode_hex_wrapper(plain_raw)))
    return pairs, undecodable


def _digest_for_type(hash_type: str, raw: bytes) -> Optional[str]:
    """Compute the digest of ``raw`` under ``hash_type``.

    Returns None for hash types we can't verify client-side (salted,
    iterated, or otherwise not reproducible from plaintext alone).
    """
    import hashlib

    ht = str(hash_type)
    if ht == "0":
        return hashlib.md5(raw).hexdigest()
    if ht == "100":
        return hashlib.sha1(raw).hexdigest()
    if ht == "1400":
        return hashlib.sha256(raw).hexdigest()
    if ht == "1700":
        return hashlib.sha512(raw).hexdigest()
    if ht in ("900", "1000"):
        # MD4 over the raw bytes; NTLM is MD4 over UTF-16LE. A $HEX[...]
        # plaintext carries hashcat's raw candidate bytes, zero-extended one
        # byte per UTF-16 code unit -- correct for arbitrary binary. But a
        # plaintext hashcat printed as plain text is genuine Unicode (e.g. a
        # potfile line holding "£"), and re-zero-extending its *UTF-8* bytes
        # would double up every non-ASCII character. Prefer decoding as
        # UTF-8 -- always exact for the plain-text case and a no-op for
        # zero-extend when the raw bytes aren't valid UTF-8 -- falling back
        # to the zero-extend rule only when that decode fails.
        if ht == "1000":
            try:
                utf16 = raw.decode("utf-8").encode("utf-16le")
            except UnicodeDecodeError:
                utf16 = raw.decode("latin-1").encode("utf-16le")
            return _md4(utf16)
        return _md4(raw)
    return None


_REJECTED_HASH_RE = re.compile(
    r"Plaintext for hash ([0-9a-fA-F]+), was found to be invalid\."
)


def _extract_rejected_hash(msg):
    """Return the hash value named in a Hashview "plaintext invalid" error,
    or None if ``msg`` doesn't match that shape.

    Hashview's ``/v1/hashes/import`` rolls back the entire batch on the first
    line it can't verify -- notably including a hashcat plaintext with a raw
    embedded CR/LF byte, which the client can't inline without corrupting
    this line-based upload and so sends as a literal ``$HEX[...]`` token that
    an older Hashview hashes verbatim instead of decoding. Parsing the
    rejected hash out of the error lets the caller drop just that one line
    and retry, instead of losing the whole batch to it.
    """
    match = _REJECTED_HASH_RE.search(msg or "")
    return match.group(1) if match else None


def _validate_cracked_pair(hash_type, hash_value, plaintext):
    """Return (ok, reason) for a single hash:plaintext pair.

    ``ok`` False means the pair should be skipped. ``reason`` is a short
    human-readable explanation for the warning. Unverifiable types pass.
    """
    ht = str(hash_type)
    expected_len = _HASH_HEX_LEN.get(ht)
    if expected_len is not None and len(hash_value) != expected_len:
        return (
            False,
            f"wrong length ({len(hash_value)} chars, expected {expected_len} for mode {ht})",
        )
    digest = _digest_for_type(ht, _decode_plaintext(plaintext))
    if digest is not None and digest.lower() != hash_value.lower():
        return (False, f"plaintext does not match hash under mode {ht}")
    return (True, "")


def _reverse_historical_double_encoding(raw: bytes) -> Optional[bytes]:
    """Reverse the corruption the pre-07c2f15 ``_wire_field_bytes`` bug left
    behind, if *raw* fits its shape.

    That bug took an NTLM/UTF-16LE-mode plaintext that was already valid
    UTF-8, decoded it as latin-1 (misreading each UTF-8 byte as its own code
    point), then re-encoded the result as UTF-8 -- doubling every non-ASCII
    character (e.g. ``café`` became ``cafÃ©``) before it reached Hashview.
    Fixing the code stopped new corruption but left every plaintext uploaded
    before the fix corrupted in Hashview (and, via the found/potfile merge,
    in local potfiles) forever, since neither ever re-verifies a stored
    plaintext against its hash.

    The corruption is exactly one round trip in reverse: decode the
    corrupted bytes as UTF-8 to recover the mis-read code points, then encode
    those as latin-1 to get back the original UTF-8 bytes. Returns ``None``
    when *raw* doesn't fit that shape (not valid UTF-8, or the round trip is
    a no-op because there was nothing non-ASCII to double) -- the caller must
    still re-validate whatever this returns against the hash before trusting
    it, since a plaintext that happens to be built entirely from Latin-1-range
    characters can pass this reshaping without actually being corrupted.
    """
    try:
        mojibake = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        recovered = mojibake.encode("latin-1")
    except UnicodeEncodeError:
        return None
    if recovered == raw:
        return None
    try:
        recovered.decode("utf-8")
    except UnicodeDecodeError:
        return None
    return recovered


def _repair_potfile(potfile_path, repairs, removals):
    """Rewrite a hashcat potfile in place: fix a repairable hash's plaintext
    and drop an unrecoverable one entirely.

    Hashcat never re-verifies a potfile entry against its hash on a later
    run -- it just replays whatever plaintext is on file as "already
    cracked". Leaving a corrupted entry in place means every future attack
    against that hash keeps reporting the same bad password forever, so this
    patches the potfile itself rather than only what gets uploaded this run.

    *repairs* maps a lowercased hash to the corrected plaintext bytes;
    *removals* is a set of lowercased hashes to drop. Returns
    ``(repaired_count, removed_count)``. A no-op (missing/absent potfile, or
    nothing to do) returns ``(0, 0)`` without touching the file.
    """
    if not potfile_path or not os.path.isfile(potfile_path):
        return 0, 0
    if not repairs and not removals:
        return 0, 0
    repaired = 0
    removed = 0
    out_lines = []
    with open(potfile_path, "rb") as f:
        for line in f:
            core = line.rstrip(b"\r\n")
            if b":" not in core:
                out_lines.append(line)
                continue
            hash_part, _, _ = core.partition(b":")
            key = hash_part.strip().lower().decode("ascii", "ignore")
            if key in removals:
                removed += 1
                continue
            if key in repairs:
                out_lines.append(hash_part + b":" + repairs[key] + b"\n")
                repaired += 1
                continue
            out_lines.append(line)
    if repaired or removed:
        with open(potfile_path, "wb") as f:
            f.writelines(out_lines)
    return repaired, removed


# Hashcat modes whose password bytes are UTF-16LE (zero-extended) rather than
# raw bytes. These need the latin-1->UTF-8 re-encoding when decoding $HEX.
_UTF16LE_MODES = {"1000", "1731"}
# Modes whose password is hashed as raw bytes.
_RAW_BYTE_MODES = {"0", "100", "300", "900", "1400", "1700"}


def _wire_field_bytes(hash_type, plaintext: str) -> bytes:
    """Return the on-the-wire bytes for a plaintext field.

    Decodes hashcat's ``$HEX[...]`` wrapper to the exact bytes Hashview must
    re-hash, so cracked passwords with whitespace/binary bytes import even
    against a Hashview that does not itself understand ``$HEX[...]``. Falls back
    to sending the ``$HEX[...]`` token verbatim when inlining would be unsafe
    (embedded CR/LF would break the line-based upload) or the mode's byte
    handling is unknown -- those rely on a $HEX-aware server.
    """
    if not (plaintext.startswith("$HEX[") and plaintext.endswith("]")):
        return plaintext.encode("utf-8", "surrogateescape")
    try:
        raw = bytes.fromhex(plaintext[5:-1])
    except ValueError:
        return plaintext.encode("utf-8", "surrogateescape")
    if b"\n" in raw or b"\r" in raw:
        return plaintext.encode("utf-8", "surrogateescape")
    ht = str(hash_type)
    if ht in _UTF16LE_MODES:
        # hashcat $HEX-wraps for reasons unrelated to encoding (an embedded
        # colon, a control character, leading/trailing whitespace) as well as
        # for genuine zero-extended raw bytes. When the wrapped bytes are
        # already valid UTF-8 they ARE the real password text -- ship them
        # as-is. Only bytes that fail to decode as UTF-8 are the zero-extend
        # case, where each byte is a code point to reconstruct as latin-1
        # before the server's own UTF-16LE encoding. Mirrors the same
        # utf-8-first choice _digest_for_type makes when validating.
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError:
            return raw.decode("latin-1").encode("utf-8")
        return raw
    if ht in _RAW_BYTE_MODES:
        return raw
    return plaintext.encode("utf-8", "surrogateescape")


# Hashview Integration - Real API implementation matching hate_crack.py
class HashviewAPI:
    def _auth_headers(self):
        return {"Cookie": f"uuid={self.api_key}"}

    def upload_wordlist_file(self, wordlist_path, wordlist_name=None):
        """Directly upload a wordlist file to Hashview (non-interactive)."""
        if wordlist_name is None:
            wordlist_name = os.path.basename(wordlist_path)
        with open(wordlist_path, "rb") as f:
            file_content = f.read()
        url = f"{self.base_url}/v1/wordlists/add/{wordlist_name}"
        headers = {"Content-Type": "text/plain"}
        resp = self.session.post(
            url, data=file_content, headers=headers, timeout=HASHVIEW_UPLOAD_TIMEOUT
        )
        resp.raise_for_status()
        return resp.json()

    def list_wordlists(self):
        """List available wordlists from Hashview API."""
        endpoint = f"{self.base_url}/v1/wordlists"
        response = self.session.get(
            endpoint, headers=self._auth_headers(), timeout=HASHVIEW_DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        try:
            data = response.json()
        except Exception:
            raise Exception(f"Invalid API response: {response.text}")
        # The API may return a list or a dict with a key
        if isinstance(data, dict) and "wordlists" in data:
            wordlists = data["wordlists"]
            # If wordlists is a JSON string, decode it
            if isinstance(wordlists, str):
                import json

                wordlists = json.loads(wordlists)
            return wordlists
        elif isinstance(data, list):
            return data
        else:
            return []

    def __init__(self, base_url, api_key, debug=False):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.debug = debug
        self.session = requests.Session()
        self.session.cookies.set("uuid", api_key)
        self.session.verify = False
        # Hash types whose listing request timed out during the most recent
        # get_all_customer_hashfiles() call. Reset per call; callers read it to
        # tell an incomplete listing from an empty one.
        self.last_listing_timeouts = []
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def get_customer_hashfile_types(self):
        """
        Returns a dictionary mapping customer_id -> {hashfile_id: hashtype}.
        Example:
            {
                1: {123: '1000', 124: '1800'},
                2: {125: '1000'}
            }
        """
        result = {}
        customers = self.list_customers().get("customers", [])
        for customer in customers:
            cid = int(customer.get("id", 0))
            hashfiles = self.get_customer_hashfiles(cid)
            hashfile_map = {}
            for hf in hashfiles:
                hfid = hf.get("id")
                if hfid is None:
                    continue
                hfid = int(hfid)
                # Try to get hashtype from hashfile dict, else fetch details
                hashtype = hf.get("hash_type") or hf.get("hashtype")
                if not hashtype:
                    details = self.get_hashfile_details(hfid)
                    hashtype = details.get("hashtype") or details.get("hash_type")
                hashfile_map[hfid] = hashtype
            result[cid] = hashfile_map
        return result

    def get_hashfiles_by_type(self, hash_type="1000"):
        """
        Return all hashfiles of a given hash_type using the /v1/hashfiles/hash_type/<hash_type> endpoint.
        """
        url = f"{self.base_url}/v1/hashfiles/hash_type/{hash_type}"
        resp = self.session.get(
            url, headers=self._auth_headers(), timeout=HASHVIEW_LISTING_TIMEOUT
        )
        resp.raise_for_status()
        try:
            data = resp.json()
            # Expecting a list of hashfiles or a dict with a key containing them
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # Try common keys
                for key in ("hashfiles", "files", "data"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
            return []
        except Exception:
            return []

    def get_hashfile_details(self, hashfile_id):
        """Get hashfile details and hashtype for a given hashfile_id."""
        url = f"{self.base_url}/v1/getHashType/{hashfile_id}"
        resp = self.session.get(
            url, headers=self._auth_headers(), timeout=HASHVIEW_DEFAULT_TIMEOUT
        )
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Failed to parse JSON from {url}: {e}")
            data = None
        hashtype = None
        if data:
            # Prefer explicit hash-type keys by PRESENCE, not truthiness: MD5 is
            # hash_type 0, which is falsy. Never fall back to `type` — that is
            # the envelope tag ("message"), never a hash mode.
            if "hash_type" in data:
                hashtype = data["hash_type"]
            elif "hashtype" in data:
                hashtype = data["hashtype"]
            if self.debug:
                print(
                    f"[DEBUG] get_hashfile_details({hashfile_id}): raw data={data}, hashtype={hashtype}"
                )
        elif self.debug:
            print(
                f"[DEBUG] get_hashfile_details({hashfile_id}): no data returned. raw response: {resp.text}"
            )
        return {
            "hashfile_id": hashfile_id,
            "hashtype": hashtype,
            "details": data,
            "raw": resp.content,
        }

    FILE_FORMATS = {
        "pwdump": 0,
        "netntlm": 1,
        "kerberos": 2,
        "shadow": 3,
        "user:hash": 4,
        "hash_only": 5,
    }

    def list_customers(self):
        url = f"{self.base_url}/v1/customers"
        resp = self.session.get(url, timeout=HASHVIEW_DEFAULT_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        if "users" in data:
            customers = data["users"]
            # Newer servers return a native JSON array (issue #229); older ones
            # double-encode it as a JSON string. Support both.
            if isinstance(customers, str):
                customers = json.loads(customers)
            return {"customers": customers}
        return data

    def get_customer_hashfiles(self, customer_id, hash_type=None):
        """Return a customer's hashfiles of a given hash_type.

        Hashview exposes no "list all hashfiles" route; the only enumeration
        endpoint is ``/v1/hashfiles/hash_type/<hash_type>`` (see
        :meth:`get_hashfiles_by_type`), which already returns ``customer_id``
        and ``hash_type`` per file. We query that and filter by customer.

        ``hash_type`` is required to enumerate: without it there is no API
        route to list a customer's files, so an empty list is returned.
        """
        if hash_type is None:
            if self.debug:
                print(
                    "[DEBUG] get_customer_hashfiles: no hash_type given; Hashview "
                    "has no list-all route, returning []"
                )
            return []

        all_hashfiles = self.get_hashfiles_by_type(hash_type)
        customer_hfs = [
            hf
            for hf in all_hashfiles
            if int(hf.get("customer_id", 0)) == int(customer_id)
        ]

        # The type-scoped endpoint already returns the hash_type, but normalize
        # the key so downstream callers can read either spelling.
        for hf in customer_hfs:
            if not (hf.get("hashtype") or hf.get("hash_type")):
                hf["hash_type"] = str(hash_type)

        if self.debug:
            print(
                f"[DEBUG] get_customer_hashfiles({customer_id}, hash_type={hash_type}): "
                f"found {len(customer_hfs)} hashfiles"
            )

        return customer_hfs

    # Curated set of hashcat modes commonly seen in engagements. Used to
    # enumerate a customer's hashfiles by sweeping the per-type listing
    # endpoint, since Hashview exposes no list-all route. Not exhaustive:
    # uncommon types can still be queried explicitly via get_customer_hashfiles.
    COMMON_HASH_TYPES = (
        0,  # MD5
        100,  # SHA1
        1000,  # NTLM
        3000,  # LM
        1100,  # Domain Cached Credentials (DCC), MS Cache
        2100,  # Domain Cached Credentials 2 (DCC2), MS Cache 2
        5500,  # NetNTLMv1
        5600,  # NetNTLMv2
        7500,  # Kerberos 5 AS-REQ Pre-Auth (etype 23)
        13100,  # Kerberos 5 TGS-REP (Kerberoasting, etype 23)
        18200,  # Kerberos 5 AS-REP (AS-REP roasting, etype 23)
        19600,  # Kerberos 5 TGS-REP (etype 17)
        19700,  # Kerberos 5 TGS-REP (etype 18)
        1800,  # sha512crypt $6$ (Linux)
        500,  # md5crypt $1$ (Linux/Cisco)
        7400,  # sha256crypt $5$
        3200,  # bcrypt $2*$
        1700,  # SHA512
        1400,  # SHA256
        160,  # HMAC-SHA1
        13400,  # KeePass
        9600,  # MS Office 2013
        10500,  # PDF 1.4-1.6
        11600,  # 7-Zip
        16500,  # JWT
        22000,  # WPA-PBKDF2-PMKID+EAPOL
    )

    def list_customer_hashfiles(self, customer_id):
        """Return a customer's hashfiles via the customer-scoped listing route.

        ``GET /v1/customers/<id>/hashfiles`` filters server-side and covers
        every hash type in one request. Added in Hashview v0.8.3-dev; servers
        predating it have no such route, which surfaces as a 404 and is the
        caller's cue to fall back to the per-type sweep.

        Raises whatever ``requests`` raises; a 404 is meaningful, not an error
        to swallow here.
        """
        url = f"{self.base_url}/v1/customers/{customer_id}/hashfiles"
        resp = self.session.get(
            url, headers=self._auth_headers(), timeout=HASHVIEW_LISTING_TIMEOUT
        )
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            return []
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            files = data.get("hashfiles")
            if isinstance(files, list):
                return files
        return []

    def get_all_customer_hashfiles(self, customer_id, hash_types=None):
        """Return a customer's hashfiles, preferring the direct listing route.

        Tries :meth:`list_customer_hashfiles` first: one request, filtered
        server-side, complete across hash types. Servers without that route
        404, and we fall back to sweeping the per-type listing endpoint
        (:meth:`get_hashfiles_by_type`) over ``hash_types`` — 26 requests by
        default, each returning every hashfile of that type server-wide, and
        blind to any type outside :attr:`COMMON_HASH_TYPES`.

        Passing ``hash_types`` explicitly forces the sweep, since it asks for
        specific types rather than everything.
        """
        self.last_listing_timeouts = []
        if hash_types is None:
            try:
                direct = self.list_customer_hashfiles(customer_id)
            except Exception as e:
                status = _http_status(e)
                if status != 404:
                    raise
                if self.debug:
                    print(
                        "[DEBUG] get_all_customer_hashfiles: customer-scoped route "
                        "absent (404); falling back to per-type sweep"
                    )
            else:
                if self.debug:
                    print(
                        f"[DEBUG] get_all_customer_hashfiles({customer_id}): "
                        f"{len(direct)} hashfiles from customer-scoped route"
                    )
                return direct
            hash_types = self.COMMON_HASH_TYPES

        seen = {}
        for ht in hash_types:
            try:
                files = self.get_hashfiles_by_type(ht)
            except requests.exceptions.Timeout:
                # NOT an empty answer. This route's cost scales with the number
                # of hashes of the type, so the type that times out is the
                # busiest one -- usually NTLM, i.e. exactly the files the
                # operator wants. Silently continuing hands back a listing
                # missing them with nothing on screen to say so.
                self.last_listing_timeouts.append(ht)
                print(
                    f"  ! Listing hash type {ht} timed out after "
                    f"{HASHVIEW_LISTING_TIMEOUT}s; its hashfiles are missing "
                    f"from this list."
                )
                if len(self.last_listing_timeouts) >= HASHVIEW_LISTING_TIMEOUT_BUDGET:
                    print(
                        "  ! Giving up on the remaining hash types: this "
                        "Hashview server is too slow to enumerate. Look the "
                        "hashfile ID up in the web UI instead."
                    )
                    break
                continue
            except Exception as e:
                status = _http_status(e)
                if status == 404:
                    # The /v1/hashfiles/hash_type route doesn't exist on this
                    # server (e.g. Hashview main, or builds before 2026-06-08),
                    # so no per-type sweep is possible. Stop after the first 404
                    # instead of hammering the server with one request per type.
                    if self.debug:
                        print(
                            "[DEBUG] get_all_customer_hashfiles: hash_type listing "
                            "endpoint absent (404); aborting sweep"
                        )
                    break
                if self.debug:
                    print(f"[DEBUG] get_all_customer_hashfiles: type {ht} failed: {e}")
                continue
            for hf in files:
                if int(hf.get("customer_id", 0)) != int(customer_id):
                    continue
                hf_id = hf.get("id")
                if hf_id is None:
                    continue
                if not (hf.get("hashtype") or hf.get("hash_type")):
                    hf["hash_type"] = str(ht)
                seen.setdefault(int(hf_id), hf)
        if self.debug:
            print(
                f"[DEBUG] get_all_customer_hashfiles({customer_id}): "
                f"found {len(seen)} hashfiles across {len(hash_types)} types"
            )
        return list(seen.values())

    def get_customer_hashfiles_with_hashtype(self, customer_id, target_hashtype="1000"):
        """Return hashfiles for a customer that match the requested hashtype."""
        customer_hashfiles = self.get_customer_hashfiles(
            customer_id, hash_type=target_hashtype
        )
        if not customer_hashfiles:
            return []
        target_str = str(target_hashtype)
        filtered = []
        for hf in customer_hashfiles:
            hashtype = hf.get("hashtype") or hf.get("hash_type")
            if hashtype is None:
                hf_id = hf.get("id")
                if hf_id is not None:
                    try:
                        details = self.get_hashfile_details(hf_id)
                        hashtype = details.get("hashtype")
                    except Exception:
                        hashtype = None
            if hashtype is not None and str(hashtype) == target_str:
                filtered.append(hf)
        return filtered

    def display_customers_multicolumn(self, customers):
        if not customers:
            print("\nNo customers found.")
            return
        try:
            terminal_width = os.get_terminal_size().columns
        except OSError:
            terminal_width = 120
        max_id_len = max(len(str(c.get("id", ""))) for c in customers)
        col_width = max_id_len + 2 + 30 + 2
        num_cols = max(1, terminal_width // col_width)
        print("\n" + "=" * terminal_width)
        print("Available Customers:")
        print("=" * terminal_width)
        num_customers = len(customers)
        rows = (num_customers + num_cols - 1) // num_cols
        for row in range(rows):
            line_parts = []
            for col in range(num_cols):
                idx = row + col * rows
                if idx < num_customers:
                    customer = customers[idx]
                    cust_id = customer.get("id", "N/A")
                    cust_name = customer.get("name", "N/A")
                    name_width = col_width - max_id_len - 2 - 2
                    if len(str(cust_name)) > name_width:
                        cust_name = str(cust_name)[: name_width - 3] + "..."
                    entry = f"{cust_id}: {cust_name}"
                    line_parts.append(entry.ljust(col_width))
            print("".join(line_parts).rstrip())
        print("=" * terminal_width)
        print(f"Total: {len(customers)} customer(s)")

    def upload_hashfile(
        self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None
    ):
        if hashfile_name is None:
            hashfile_name = os.path.basename(file_path)

        cache = load_cache()
        kept_lines = []
        new_keys = []
        skipped_cached = 0
        with open(file_path, "rb") as f:
            for raw_line in f:
                line = raw_line.rstrip(b"\r\n")
                if not line:
                    continue
                hash_value = line.decode("utf-8", errors="ignore")
                key = cache_key(hash_value, hash_type, scope=f"hashfile:{customer_id}")
                if key in cache:
                    skipped_cached += 1
                    continue
                kept_lines.append(line)
                new_keys.append(key)

        if skipped_cached:
            print(f"↷ Skipped {skipped_cached} hash(es) already uploaded previously")

        if not kept_lines:
            return {
                "uploaded": 0,
                "skipped_cached": skipped_cached,
                "hashfile_id": None,
            }

        file_content = b"\n".join(kept_lines)
        url = (
            f"{self.base_url}/v1/hashfiles/upload/"
            f"{customer_id}/{file_format}/{hash_type}/{hashfile_name}"
        )
        headers = {"Content-Type": "text/plain"}
        resp = self.session.post(
            url, data=file_content, headers=headers, timeout=HASHVIEW_UPLOAD_TIMEOUT
        )
        resp.raise_for_status()
        append_to_cache(new_keys)
        result = resp.json()
        if isinstance(result, dict):
            result.setdefault("skipped_cached", skipped_cached)
        return result

    def create_job(
        self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=None
    ):
        url = f"{self.base_url}/v1/jobs/add"
        headers = {"Content-Type": "application/json"}
        data = {
            "name": name,
            "hashfile_id": hashfile_id,
            "customer_id": customer_id,
            "limit_recovered": bool(limit_recovered),
        }
        if notify_email is not None:
            data["notify_email"] = bool(notify_email)
        resp = self.session.post(
            url, json=data, headers=headers, timeout=HASHVIEW_DEFAULT_TIMEOUT
        )
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return {}

    def stop_job(self, job_id):
        # Hashview exposes no "stop job" route (only add/get/start/delete).
        # Deleting a job removes it regardless of Queued/Running state, which
        # is the closest supported operation; use delete_job() instead.
        raise NotImplementedError(
            "Hashview has no stop-job endpoint; use delete_job() to remove a job."
        )

    def delete_job(self, job_id):
        # Hashview deletes via DELETE /v1/jobs/<id> (there is no /jobs/delete/).
        url = f"{self.base_url}/v1/jobs/{job_id}"
        resp = self.session.delete(url, timeout=HASHVIEW_DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def start_job(self, job_id, priority=3, limit_recovered=False):
        # /v1/jobs/start/<id> is POST-only; priority/limit_recovered come from
        # the stored job record server-side, so they are validated here but not
        # required by the endpoint.
        url = f"{self.base_url}/v1/jobs/start/{job_id}"
        priority = int(priority)
        if priority < 1 or priority > 5:
            raise ValueError("priority must be an int between 1 and 5")
        resp = self.session.post(url, timeout=HASHVIEW_DEFAULT_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def download_left_hashes(
        self,
        customer_id,
        hashfile_id,
        output_file=None,
        potfile_path=None,
    ):
        import sys

        # Hashview's GET /v1/hashfiles/<id> returns exactly the uncracked
        # ("left") ciphertexts for the hashfile (see v1_api_get_hashfile). The
        # older /v1/hashfiles/<id>/left route no longer exists and 404s.
        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}"
        resp = self.session.get(
            url,
            headers=self._auth_headers(),
            stream=True,
            timeout=HASHVIEW_DEFAULT_TIMEOUT,
        )
        resp.raise_for_status()
        if output_file is None:
            output_file = f"left_{customer_id}_{hashfile_id}.txt"
        # Resolve relative paths against the user's original CWD, not the
        # install directory that ``uv run --directory`` may have switched to.
        if not os.path.isabs(output_file):
            output_file = os.path.join(orig_cwd(), output_file)
        output_abs = output_file
        total = int(resp.headers.get("content-length", 0))
        downloaded = 0
        chunk_size = 8192
        with open(output_file, "wb") as f:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total > 0:
                        done = int(50 * downloaded / total)
                        bar = "[" + "=" * done + " " * (50 - done) + "]"
                        percent = 100 * downloaded / total
                        sys.stdout.write(
                            f"\rDownloading: {bar} {percent:5.1f}% ({downloaded}/{total} bytes)"
                        )
                        sys.stdout.flush()
            if total > 0:
                sys.stdout.write("\n")
        # If content-length is not provided, just print size at end
        if total == 0:
            print(f"Downloaded {downloaded} bytes.")

        # Try to download found file and process with hashcat
        combined_count = 0
        combined_file = None
        out_dir = os.path.dirname(output_abs) or orig_cwd()
        found_file = os.path.join(out_dir, f"found_{customer_id}_{hashfile_id}.txt")

        try:
            # Best-effort: Hashview v0.8.3-dev exposes no bulk "found"/cracked
            # export endpoint (only the single-hash POST /v1/search), so this
            # request 404s against stock servers and the merge is skipped. It
            # remains for forks/versions that expose a per-hashfile found dump.
            found_url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/found"
            found_resp = self.session.get(
                found_url,
                headers=self._auth_headers(),
                stream=True,
                timeout=HASHVIEW_DEFAULT_TIMEOUT,
            )

            # Only proceed if we successfully downloaded the found file (ignore 404s)
            if found_resp.status_code == 404:
                # No found file available, that's okay
                pass
            else:
                found_resp.raise_for_status()

                # Write the found file temporarily
                with open(found_file, "wb") as f:
                    for chunk in found_resp.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)

                # Split found file into hashes and clears
                found_hashes_file = os.path.join(
                    out_dir, f"found_hashes_{customer_id}_{hashfile_id}.txt"
                )
                found_clears_file = os.path.join(
                    out_dir, f"found_clears_{customer_id}_{hashfile_id}.txt"
                )

                found_pairs, undecodable_lines = _read_found_pairs(found_file)
                hashes_count = len(found_pairs)
                clears_count = len(found_pairs)

                with (
                    open(found_hashes_file, "w", encoding="utf-8") as hf,
                    open(found_clears_file, "w", encoding="utf-8") as cf,
                ):
                    for hash_part, clear_part in found_pairs:
                        hf.write(hash_part + "\n")
                        cf.write(clear_part + "\n")

                if undecodable_lines:
                    print(
                        f"⚠ Skipped {len(undecodable_lines)} found line(s) with an "
                        "undecodable hash field"
                    )

                # Append found hashes to the left file to reconstruct the full hashlist
                with open(output_abs, "a", encoding="utf-8") as lf:
                    with open(found_hashes_file, "r", encoding="utf-8") as hf:
                        for line in hf:
                            lf.write(line)

                print(
                    f"Split found file into {hashes_count} hashes and {clears_count} clears"
                )

                # Append found hash:clear pairs to the potfile
                resolved_potfile = (
                    potfile_path
                    if potfile_path is not None
                    else get_hcat_potfile_path()
                )
                if resolved_potfile:
                    appended = 0
                    with open(resolved_potfile, "a", encoding="utf-8") as pf:
                        for hash_part, clear_part in found_pairs:
                            pf.write(f"{hash_part}:{clear_part}\n")
                            appended += 1
                    combined_count = appended
                    print(
                        f"✓ Appended {appended} found hashes to potfile: {resolved_potfile}"
                    )
                else:
                    print(
                        "Warning: No potfile path configured, skipping potfile update"
                    )

                # Clean up the two found_ files
                for f_path in (found_file, found_hashes_file, found_clears_file):
                    try:
                        os.remove(f_path)
                    except OSError:
                        pass

        except Exception as e:
            # If there's any error downloading found file, just skip it
            print(f"Note: Could not download found hashes: {e}")

        return {
            "output_file": output_file,
            "size": downloaded,
            "combined_count": combined_count,
            "combined_file": combined_file,
        }

    def upload_cracked_hashes(
        self, file_path, hash_type="1000", *, validate=True, potfile_path=None
    ):
        valid_lines = []
        skipped = []
        skipped_cached = 0
        new_keys = []
        repaired_count = 0
        potfile_repairs = {}
        potfile_removals = set()
        cache = load_cache()
        can_repair = validate and str(hash_type) in _UTF16LE_MODES
        # Bytes, not a lossy text read: a plaintext with a non-UTF-8 byte must
        # reach Hashview intact (as $HEX[...]) rather than as a different
        # password -- see _read_found_pairs.
        with open(file_path, "rb") as f:
            for lineno, raw_line in enumerate(f, 1):
                # rstrip only the line terminator -- a plain .strip() eats a
                # leading/trailing space that belongs to the password itself.
                raw_line = raw_line.rstrip(b"\r\n")
                if b"31d6cfe0d16ae931b73c59d7e0c089c0" in raw_line:
                    continue
                if not raw_line or b":" not in raw_line:
                    continue
                hash_raw, plain_raw = raw_line.split(b":", 1)
                try:
                    hash_value = hash_raw.strip().decode("utf-8")
                except UnicodeDecodeError:
                    skipped.append(
                        (lineno, "<undecodable>", "hash field is not UTF-8", raw_line)
                    )
                    continue

                key = cache_key(hash_value, hash_type, scope="cracked")
                if key in cache:
                    skipped_cached += 1
                    continue

                plaintext = encode_hex_wrapper(plain_raw)
                if validate:
                    ok, reason = _validate_cracked_pair(
                        hash_type, hash_value, plaintext
                    )
                    if not ok:
                        recovered_bytes = (
                            _reverse_historical_double_encoding(
                                _decode_plaintext(plaintext)
                            )
                            if can_repair
                            else None
                        )
                        recovered_plaintext = (
                            encode_hex_wrapper(recovered_bytes)
                            if recovered_bytes is not None
                            else None
                        )
                        rec_ok = (
                            _validate_cracked_pair(
                                hash_type, hash_value, recovered_plaintext
                            )[0]
                            if recovered_plaintext is not None
                            else False
                        )
                        if rec_ok:
                            repaired_count += 1
                            potfile_repairs[hash_value.lower()] = recovered_bytes
                            plaintext = recovered_plaintext
                        else:
                            skipped.append((lineno, hash_value, reason, raw_line))
                            potfile_removals.add(hash_value.lower())
                            continue
                valid_lines.append(
                    hash_value.encode("ascii", "ignore")
                    + b":"
                    + _wire_field_bytes(hash_type, plaintext)
                )
                new_keys.append(key)

        if skipped_cached:
            print(f"↷ Skipped {skipped_cached} hash(es) already uploaded previously")

        if repaired_count:
            print(
                f"✓ Repaired {repaired_count} plaintext(s) corrupted by the historical "
                "double-encoding bug (fixed in 07c2f15) before upload"
            )

        if potfile_repairs or potfile_removals:
            n_repaired, n_removed = _repair_potfile(
                potfile_path, potfile_repairs, potfile_removals
            )
            if n_repaired:
                print(f"✓ Fixed {n_repaired} corrupted plaintext(s) in the potfile")
            if n_removed:
                print(
                    f"✓ Removed {n_removed} unrecoverable entr{'y' if n_removed == 1 else 'ies'} "
                    "from the potfile (hashcat would otherwise keep replaying them)"
                )

        rejected_path = None
        if skipped:
            rejected_path = f"{file_path}.rejected"
            with open(rejected_path, "wb") as rf:
                for _, _, _, raw_line in skipped:
                    rf.write(raw_line + b"\n")
            print(
                f"⚠ Skipped {len(skipped)} line(s) that do not match hash mode "
                f"{hash_type} (would be rejected by Hashview) -- "
                f"preserved in {rejected_path}:"
            )
            for lineno, hash_value, reason, _ in skipped[:10]:
                print(f"    line {lineno}: {hash_value} — {reason}")
            if len(skipped) > 10:
                print(f"    ... and {len(skipped) - 10} more")

        if not valid_lines:
            if skipped_cached:
                # At least one line was already-uploaded-and-cached, so this
                # is not "nothing valid" -- it's "nothing left to upload
                # after skipping what's cached," even if other lines were
                # also genuinely invalid. Return gracefully instead of
                # raising and blaming the invalid lines for the whole file.
                return {
                    "uploaded": 0,
                    "skipped": len(skipped),
                    "skipped_cached": skipped_cached,
                    "repaired": repaired_count,
                    "rejected_file": rejected_path,
                }
            raise Exception(
                f"No valid hashes to upload for hash mode {hash_type} "
                f"({len(skipped)} line(s) skipped by validation)."
            )

        url = f"{self.base_url}/v1/hashes/import/{hash_type}"
        headers = {"Content-Type": "text/plain; charset=utf-8"}

        batches = [
            valid_lines[i : i + HASHVIEW_CRACKED_BATCH_SIZE]
            for i in range(0, len(valid_lines), HASHVIEW_CRACKED_BATCH_SIZE)
        ]
        key_batches = [
            new_keys[i : i + HASHVIEW_CRACKED_BATCH_SIZE]
            for i in range(0, len(new_keys), HASHVIEW_CRACKED_BATCH_SIZE)
        ]

        aggregated = {}
        summable_fields = ("verified", "updated", "count")
        list_fields = ("unmatched",)
        rejected_by_server = []
        for batch_num, (line_batch, key_batch) in enumerate(
            zip(batches, key_batches), start=1
        ):
            line_batch = list(line_batch)
            key_batch = list(key_batch)
            if len(batches) > 1:
                print(
                    f"Uploading batch {batch_num}/{len(batches)} "
                    f"({len(line_batch)} hashes)..."
                )
            # A single line Hashview rejects rolls back its whole batch. Retry
            # with that one line dropped rather than losing every hash in the
            # batch to it -- bounded by the batch size so a server that keeps
            # rejecting can't loop forever.
            for _attempt in range(len(line_batch) + 1):
                if not line_batch:
                    break
                converted_content = b"\n".join(line_batch)
                resp = self.session.post(
                    url,
                    data=converted_content,
                    headers=headers,
                    timeout=HASHVIEW_UPLOAD_TIMEOUT,
                )
                resp.raise_for_status()
                try:
                    json_response = resp.json()
                except (json.JSONDecodeError, ValueError):
                    raise Exception(f"Invalid API response: {resp.text[:200]}")
                if not isinstance(json_response, dict):
                    if len(batches) == 1:
                        # Matches today's single-request behavior: a non-dict
                        # response (rare, but Hashview's contract doesn't
                        # forbid it) is returned as-is rather than merged.
                        append_to_cache(key_batch)
                        return json_response
                    raise Exception(
                        f"Hashview API returned a non-object response for "
                        f"batch {batch_num}/{len(batches)}: {json_response!r}"
                    )
                if json_response.get("type") == "Error":
                    rejected_hash = _extract_rejected_hash(json_response.get("msg", ""))
                    if rejected_hash is not None:
                        kept_lines, kept_keys = [], []
                        for line, key in zip(line_batch, key_batch):
                            line_hash = line.split(b":", 1)[0].decode("ascii", "ignore")
                            if line_hash.lower() == rejected_hash.lower():
                                rejected_by_server.append(line_hash)
                                continue
                            kept_lines.append(line)
                            kept_keys.append(key)
                        line_batch, key_batch = kept_lines, kept_keys
                        continue
                    raise Exception(
                        f"Hashview API Error: "
                        f"{json_response.get('msg', 'Unknown error')}"
                    )
                append_to_cache(key_batch)
                for field in summable_fields:
                    if isinstance(json_response.get(field), (int, float)):
                        aggregated[field] = (
                            aggregated.get(field, 0) + json_response[field]
                        )
                for field in list_fields:
                    if isinstance(json_response.get(field), list):
                        aggregated.setdefault(field, [])
                        aggregated[field].extend(json_response[field])
                for key, value in json_response.items():
                    if key not in summable_fields and key not in list_fields:
                        aggregated.setdefault(key, value)
                break

        if rejected_by_server:
            print(
                f"⚠ Hashview rejected {len(rejected_by_server)} plaintext(s) as "
                "invalid (server does not decode $HEX[...] on import) -- "
                "skipped, rest of the batch uploaded:"
            )
            for hash_value in rejected_by_server[:10]:
                print(f"    {hash_value}")
            if len(rejected_by_server) > 10:
                print(f"    ... and {len(rejected_by_server) - 10} more")

        aggregated.setdefault("uploaded", len(valid_lines) - len(rejected_by_server))
        aggregated["skipped"] = len(skipped) + len(rejected_by_server)
        aggregated["skipped_cached"] = skipped_cached
        aggregated["repaired"] = repaired_count
        aggregated["rejected_file"] = rejected_path
        return aggregated

    def download_wordlist(
        self, wordlist_id, output_file=None, *, update_dynamic: bool = False
    ):
        import re

        if int(wordlist_id) == 1 and update_dynamic:
            update_url = f"{self.base_url}/v1/updateWordlist/{wordlist_id}"
            try:
                update_resp = self.session.get(
                    update_url,
                    headers=self._auth_headers(),
                    timeout=HASHVIEW_DEFAULT_TIMEOUT,
                )
                update_resp.raise_for_status()
            except Exception as exc:
                if self.debug:
                    print(
                        f"Warning: failed to update dynamic wordlist {wordlist_id}: {exc}"
                    )

        # A dynamic wordlist is regenerated from the DB on every download
        # request, so it needs far more time-to-first-byte headroom than a
        # static list streamed straight off disk. Resolve the real type via
        # the metadata listing rather than assuming only id 1 is dynamic --
        # Hashview also has dynamic Usernames/Customers/NTLM-ciphertext rows
        # and per-length Recovered Passwords buckets. A failed lookup must
        # never block the download itself, so fall back to the legacy id==1
        # heuristic on any error.
        is_dynamic = int(wordlist_id) == 1
        wordlist_name = None
        try:
            for wl in self.list_wordlists():
                if int(wl.get("id", -1)) == int(wordlist_id):
                    is_dynamic = str(wl.get("type", "")).lower() == "dynamic"
                    wordlist_name = wl.get("name")
                    break
        except Exception:
            pass

        if is_dynamic:
            print(
                "Hashview regenerates dynamic wordlists on demand -- it builds "
                "and compresses the list before sending any data, so this can "
                "sit silent for several minutes on a large corpus. Waiting up "
                "to 30 minutes..."
            )
            download_timeout = HASHVIEW_DYNAMIC_DOWNLOAD_TIMEOUT
        else:
            download_timeout = HASHVIEW_DOWNLOAD_TIMEOUT

        url = f"{self.base_url}/v1/wordlists/{wordlist_id}"
        resp = self.session.get(
            url,
            headers=self._auth_headers(),
            stream=True,
            timeout=download_timeout,
        )
        resp.raise_for_status()

        if output_file is None:
            if is_dynamic:
                # The dynamic route serves a random secrets.token_hex(8) scratch
                # filename (a fresh one per request, since the file is
                # regenerated each time), so content-disposition is useless for
                # naming a dynamic download -- build one from the wordlist's own
                # name plus today's date instead, so repeated downloads of the
                # same dynamic list are distinguishable and sort chronologically.
                import datetime

                slug = sanitize_filename(wordlist_name or "dynamic-all") or "dynamic"
                today = datetime.date.today().isoformat()
                output_file = f"{slug}-{today}.txt.gz"
            else:
                content_disp = resp.headers.get("content-disposition", "")
                match = re.search(
                    r"filename=\"?([^\";]+)\"?", content_disp, re.IGNORECASE
                )
                output_file = (
                    os.path.basename(match.group(1))
                    if match
                    else f"wordlist_{wordlist_id}.gz"
                )

        if not os.path.isabs(output_file):
            dest_dir = get_hcat_wordlists_dir()
            output_file = os.path.join(dest_dir, output_file)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        try:
            ok = _stream_response_to_file(resp, output_file, label=output_file)
        finally:
            resp.close()
        if ok:
            return {"output_file": output_file, "size": os.path.getsize(output_file)}
        return {"output_file": output_file, "size": 0}

    def list_rules(self):
        """List available rule files from the Hashview API (/v1/rules)."""
        endpoint = f"{self.base_url}/v1/rules"
        response = self.session.get(
            endpoint, headers=self._auth_headers(), timeout=HASHVIEW_DEFAULT_TIMEOUT
        )
        response.raise_for_status()
        try:
            data = response.json()
        except Exception:
            raise Exception(f"Invalid API response: {response.text}")
        if isinstance(data, dict) and "rules" in data:
            rules = data["rules"]
            # Newer servers return a native JSON array (issue #229); tolerate a
            # legacy double-encoded string as well.
            if isinstance(rules, str):
                rules = json.loads(rules)
            return rules
        elif isinstance(data, list):
            return data
        return []

    def download_rules(self, rules_id, output_file=None):
        """Download a rule file from the Hashview API (/v1/rules/<id>).

        Rules are stored plaintext at rest and the server gzip-compresses them
        on the fly, so the response body is gzip. We decompress before saving
        so the file is directly usable with ``hashcat -r``. An unknown rule id
        is a real HTTP 404, surfaced via ``raise_for_status``.
        """
        import gzip

        url = f"{self.base_url}/v1/rules/{rules_id}"
        resp = self.session.get(
            url, headers=self._auth_headers(), timeout=HASHVIEW_DEFAULT_TIMEOUT
        )
        resp.raise_for_status()

        content = resp.content
        try:
            content = gzip.decompress(content)
        except (OSError, EOFError):
            # Already plaintext (or a fork that serves uncompressed) — save as-is.
            pass

        if output_file is None:
            output_file = f"rule_{rules_id}.rule"
        if not os.path.isabs(output_file):
            output_file = os.path.join(get_rules_dir(), output_file)
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

        with open(output_file, "wb") as f:
            f.write(content)
        return {"output_file": output_file, "size": os.path.getsize(output_file)}

    def download_all_rules(self):
        """Download every rule file the Hashview API lists (/v1/rules).

        One rule failing to download (e.g. a 404 on a stale listing) must not
        abort the rest, so each rule's outcome is collected individually
        rather than raised.
        """
        rules = self.list_rules()
        results = []
        for rule in rules:
            rule_id = rule.get("id")
            rule_name = rule.get("name")
            if rule_id is None:
                results.append(
                    {"id": rule_id, "name": rule_name, "error": "missing id"}
                )
                continue
            try:
                download_result = self.download_rules(rule_id, rule_name)
                results.append(
                    {
                        "id": rule_id,
                        "name": rule_name,
                        "output_file": download_result["output_file"],
                        "size": download_result["size"],
                    }
                )
            except Exception as e:
                results.append({"id": rule_id, "name": rule_name, "error": str(e)})
        return results

    def create_customer(self, name):
        url = f"{self.base_url}/v1/customers/add"
        headers = {"Content-Type": "application/json"}
        data = {"name": name}
        resp = self.session.post(
            url, json=data, headers=headers, timeout=HASHVIEW_DEFAULT_TIMEOUT
        )
        resp.raise_for_status()
        try:
            payload = resp.json()
        except Exception:
            return resp.json()

        msg = str(payload.get("msg", ""))
        if "invalid keyword argument for Customers" in msg:
            # Fallback for older Hashview servers that choke on JSON body parsing.
            resp = self.session.post(
                url, data={"name": name}, timeout=HASHVIEW_DEFAULT_TIMEOUT
            )
            resp.raise_for_status()
            return resp.json()
        return payload

    def get_hashfile_hash_type(self, hashtype_id):
        """
        Query /v1/hashfiles/hash_type/<int:hashtype_id> and return a list of file IDs.

        The endpoint answers with an envelope ``{..., "hashfiles": [ {...} ]}``
        (native JSON objects); we extract the ``id`` of each hashfile.
        """
        url = f"{self.base_url}/v1/hashfiles/hash_type/{hashtype_id}"
        resp = self.session.get(url, timeout=HASHVIEW_DEFAULT_TIMEOUT)
        resp.raise_for_status()
        try:
            data = resp.json()
            # A bare list is tolerated for forward/backward compatibility.
            if isinstance(data, list):
                hashfiles = data
            elif isinstance(data, dict):
                hashfiles = data.get("hashfiles") or []
            else:
                return []
            ids = []
            for hf in hashfiles:
                hf_id = hf.get("id") if isinstance(hf, dict) else hf
                if hf_id is not None:
                    ids.append(hf_id)
            return ids
        except Exception:
            return []


def download_hashes_from_hashview(
    hashview_url: str,
    hashview_api_key: str,
    debug_mode: bool,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
    potfile_path: Optional[str] = None,
    hash_type: Optional[str] = None,
) -> Tuple[str, str]:
    """Interactive Hashview download flow used by CLI.

    ``hash_type`` is required to enumerate a customer's hashfiles, since
    Hashview only exposes a per-hash-type listing endpoint.
    """
    try:
        if not sys.stdin or not sys.stdin.isatty():
            print_fn("\nAvailable Customers:")
            raise ValueError("non-interactive")
    except ValueError:
        raise
    except Exception:
        # If stdin status can't be determined, continue normally.
        pass
    api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)
    customers_result = api_harness.list_customers()
    customers = (
        customers_result.get("customers", [])
        if isinstance(customers_result, dict)
        else customers_result
    )
    if customers:
        api_harness.display_customers_multicolumn(customers)
    else:
        print_fn("\nNo customers found.")

    def _safe_input(prompt):
        try:
            if not sys.stdin or not sys.stdin.isatty():
                return "q"
        except Exception:
            return "q"
        try:
            return input_fn(prompt)
        except EOFError:
            return "q"

    # Select or create customer
    customer_raw = _safe_input("\nEnter customer ID or N to create new: ").strip()
    if customer_raw.lower() == "q":
        raise ValueError("cancelled")

    if customer_raw.lower() == "n":
        customer_name = _safe_input("Enter customer name: ").strip()
        if customer_name.lower() == "q":
            raise ValueError("cancelled")
        if customer_name:
            try:
                result = api_harness.create_customer(customer_name)
                print_fn(f"\n✓ Success: {result.get('msg', 'Customer created')}")
                customer_id = result.get("customer_id") or result.get("id")
                if not customer_id:
                    raise ValueError("Customer ID not returned")
                print_fn(f"  Customer ID: {customer_id}")
            except Exception as e:
                print_fn(f"\n✗ Error creating customer: {str(e)}")
                raise
        else:
            raise ValueError("Customer name cannot be empty")
    else:
        customer_id = int(customer_raw)
    try:
        customer_hashfiles = api_harness.get_customer_hashfiles(
            customer_id, hash_type=hash_type
        )
        if customer_hashfiles:
            print_fn("\n" + "=" * 120)
            print_fn(f"Hashfiles for Customer ID {customer_id}:")
            print_fn("=" * 120)
            print_fn(f"{'ID':<10} {'Hash Type':<10} {'Name':<96}")
            print_fn("-" * 120)
            hashfile_map = {}
            for hf in customer_hashfiles:
                hf_id = hf.get("id")
                hf_name = hf.get("name", "N/A")
                hf_type = hf.get("hash_type") or hf.get("hashtype") or "N/A"
                if hf_id is None:
                    continue
                if len(str(hf_name)) > 96:
                    hf_name = str(hf_name)[:93] + "..."
                if debug_mode:
                    print_fn(
                        f"[DEBUG] Hashfile {hf_id}: hash_type={hf.get('hash_type')}, hashtype={hf.get('hashtype')}, combined={hf_type}"
                    )
                print_fn(f"{hf_id:<10} {hf_type:<10} {hf_name:<96}")
                hashfile_map[int(hf_id)] = hf_type
            print_fn("=" * 120)
            print_fn(f"Total: {len(hashfile_map)} hashfile(s)")
        else:
            print_fn(f"\nNo hashfiles found for customer ID {customer_id}")
            print_fn(
                "This customer needs to have hashfiles uploaded before downloading left hashes."
            )
            print_fn("Please use the Hashview menu to upload a hashfile first.")
            raise ValueError("No hashfiles available for download")
    except ValueError:
        raise
    except Exception as exc:
        print_fn(f"\nWarning: Could not list hashfiles: {exc}")
        print_fn("You may need to manually find the hashfile ID in the web interface.")
        hashfile_map = {}

    while True:
        hashfile_raw = _safe_input("\nEnter hashfile ID: ").strip()
        if hashfile_raw.lower() == "q":
            raise ValueError("cancelled")
        try:
            hashfile_id = int(hashfile_raw)
        except ValueError:
            print_fn("\n✗ Error: Invalid ID entered. Please enter a numeric ID.")
            continue
        if hashfile_map and hashfile_id not in hashfile_map:
            print_fn("\n✗ Error: Hashfile ID not in the list. Please try again.")
            continue
        break

    selected_hash_type = hashfile_map.get(hashfile_id) if hashfile_map else None
    if debug_mode:
        print_fn(f"[DEBUG] selected_hash_type from map: {selected_hash_type}")
    if not selected_hash_type or selected_hash_type == "N/A":
        try:
            details = api_harness.get_hashfile_details(hashfile_id)
            selected_hash_type = details.get("hashtype")
            if debug_mode:
                print_fn(
                    f"[DEBUG] selected_hash_type from get_hashfile_details: {selected_hash_type}"
                )
        except Exception as exc:
            if debug_mode:
                print_fn(f"[DEBUG] Error fetching hashfile details: {exc}")
            selected_hash_type = None

    hcat_hash_type = str(selected_hash_type) if selected_hash_type else "1000"
    output_file = f"left_{customer_id}_{hashfile_id}.txt"
    download_result = api_harness.download_left_hashes(
        customer_id,
        hashfile_id,
        output_file,
        potfile_path=potfile_path,
    )
    print_fn(f"\n✓ Success: Downloaded {download_result['size']} bytes")
    print_fn(f"  File: {download_result['output_file']}")
    hcat_hash_file = download_result["output_file"]
    print_fn("\nNow starting hate_crack with:")
    print_fn(f"  Hash file: {hcat_hash_file}")
    print_fn(f"  Hash type: {hcat_hash_type}")
    return hcat_hash_file, hcat_hash_type


def sanitize_filename(filename):
    """Sanitize a filename by replacing spaces and removing problematic characters."""
    import re

    filename = filename.replace(" ", "_")
    filename = re.sub(r"[^A-Za-z0-9._-]", "", filename)
    return filename


def get_hashmob_api_key():
    """Return ``hashmob_api_key`` from the merged config, or ``None``.

    Goes through :func:`_load_merged_config` -- and therefore through
    ``config_loader`` -- like every other config read in this module. It used
    to walk its own two-directory list of ``config.json`` candidates, which
    was #153's duplication in a third place and, once ``hashmob_api_key``
    became a `.env`-homed key, plainly wrong: a user who set
    ``HASHMOB_API_KEY`` in `.env` kept getting the stale value out of a
    leftover ``config.json`` entry.

    ``None`` rather than ``""`` for "not configured", because callers test it
    with ``if key:`` and one passes it straight into a request header.
    """
    return _load_merged_config().get("hashmob_api_key") or None


def _format_size(num_bytes) -> str:
    """Format a byte count as a human-readable string (powers of 1024, one
    decimal place), e.g. 12.3 MB, 1.4 GB. Returns "" for a missing/invalid
    value."""
    try:
        size = float(num_bytes)
    except (TypeError, ValueError):
        return ""
    if size < 0:
        return ""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} EB"


def _listing_detail_suffix(file_size, line_count) -> str:
    """Build the "(12.3 MB, 1,234,567 lines)" suffix for a listing entry.

    Either piece is omitted when missing/zero/unformattable.
    """
    bits = []
    size_str = _format_size(file_size) if file_size else ""
    if size_str:
        bits.append(size_str)
    if line_count:
        try:
            bits.append(f"{int(line_count):,} lines")
        except (TypeError, ValueError):
            pass
    return f" ({', '.join(bits)})" if bits else ""


def download_hashmob_wordlist_list():
    """Fetch available wordlists from Hashmob API v2 and print them."""
    url = "https://hashmob.net/api/v2/resource"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        wordlists = [r for r in data if r.get("type") == "wordlist"]
        entries = []
        for idx, wl in enumerate(wordlists):
            name = wl.get("name", wl.get("file_name", ""))
            info = wl.get("information", "")
            detail = _listing_detail_suffix(wl.get("file_size"), wl.get("line_count"))
            if info:
                entry = f"{idx + 1}. {name}{detail} - {info}"
            else:
                entry = f"{idx + 1}. {name}{detail}"
            entries.append(entry)
        max_entry_len = max((len(e) for e in entries), default=30)
        print_multicolumn_list(
            "Available Hashmob Wordlists",
            entries,
            min_col_width=max_entry_len,
            max_col_width=max_entry_len,
        )
        return wordlists
    except Exception as e:
        print(f"Error fetching Hashmob wordlists: {e}")
        return []


def download_hashmob_wordlist(file_name, out_path):
    """Download a wordlist file from Hashmob by file name."""
    import re

    url = f"https://hashmob.net/api/v2/downloads/research/wordlists/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}

    def _attempt():
        _hashmob_limiter.wait()
        with requests.get(
            url, headers=headers, stream=True, timeout=60, allow_redirects=True
        ) as r:
            if r.status_code == 429:
                raise _Hashmob429(_parse_retry_after(r))
            r.raise_for_status()
            content_type = r.headers.get("Content-Type", "")
            if "text/plain" in content_type:
                html = r.content.decode(errors="replace")
                match = re.search(
                    r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"]0;url=([^'\"]+)['\"]",
                    html,
                    re.IGNORECASE,
                )
                if match:
                    real_url = match.group(1)
                    print(f"Found meta refresh redirect to: {real_url}")
                    return _streamed_download(real_url, out_path, label=file_name)
                print(
                    "Error: Received HTML instead of file. Possible permission or quota issue."
                )
                return False
            return _stream_response_to_file(r, out_path, label=file_name)

    try:
        return _with_hashmob_backoff(_attempt)
    except Exception as e:
        print(f"Error downloading wordlist: {e}")
        return False


def download_hashmob_rule_list():
    """Fetch available rules from Hashmob API v2 and print them."""
    url = "https://hashmob.net/api/v2/resource"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        rules = [r for r in data if r.get("type") in ("rule", "official_rule")]
        entries = []
        for idx, rule in enumerate(rules):
            name = rule.get("name", rule.get("file_name", ""))
            detail = _listing_detail_suffix(
                rule.get("file_size"), rule.get("line_count")
            )
            entries.append(f"{idx + 1}. {name}{detail}")
        max_entry_len = max((len(e) for e in entries), default=30)
        print_multicolumn_list(
            "Available Hashmob Rules",
            entries,
            min_col_width=max_entry_len,
            max_col_width=max_entry_len,
        )
        return rules
    except Exception as e:
        print(f"Error fetching Hashmob rules: {e}")
        return []


def download_hashmob_rule(file_name, out_path, resource_type=None):
    """Download a rule file from Hashmob by file name.

    ``resource_type`` should be the ``type`` field of the matching entry
    from ``download_hashmob_rule_list()`` (``"rule"`` or
    ``"official_rule"``), which determines the primary download host. If
    it's not supplied or doesn't match a known type, fall back to the
    public rules prefix and rely on the 404-triggered alternate-URL retry
    below.
    """
    if resource_type == "official_rule":
        primary_url = f"https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/{file_name}"
    elif resource_type == "rule":
        primary_url = (
            f"https://www.hashmob.net/api/v2/downloads/research/rules/{file_name}"
        )
    else:
        print(
            f"[i] Unknown Hashmob rule resource type, using public prefix: {file_name}"
        )
        primary_url = (
            f"https://www.hashmob.net/api/v2/downloads/research/rules/{file_name}"
        )
    alt_url = f"https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}

    def _attempt():
        _hashmob_limiter.wait()
        with requests.get(
            primary_url, headers=headers, stream=True, timeout=60, allow_redirects=True
        ) as r:
            if r.status_code == 429:
                raise _Hashmob429(_parse_retry_after(r))
            if r.status_code == 404 and alt_url:
                print(
                    f"[i] Hashmob rule not found at primary URL, trying fallback: {alt_url}"
                )
                with requests.get(
                    alt_url,
                    headers=headers,
                    stream=True,
                    timeout=60,
                    allow_redirects=True,
                ) as r2:
                    if r2.status_code == 429:
                        raise _Hashmob429(_parse_retry_after(r2))
                    r2.raise_for_status()
                    return _stream_response_to_file(r2, out_path, label=file_name)
            r.raise_for_status()
            return _stream_response_to_file(r, out_path, label=file_name)

    try:
        return _with_hashmob_backoff(_attempt)
    except Exception as e:
        print(f"Error downloading rule: {e}")
        return False


def download_hashmob_mask_list():
    """Fetch available masks from Hashmob API v2 and print them.

    The live response contains duplicate ``file_name`` entries; dedupe by
    ``file_name``, keeping the first occurrence.
    """
    url = "https://hashmob.net/api/v2/resource"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        masks = []
        seen_names = set()
        for r in data:
            if r.get("type") != "masks":
                continue
            file_name = r.get("file_name")
            if file_name in seen_names:
                continue
            seen_names.add(file_name)
            masks.append(r)
        entries = []
        for idx, mask in enumerate(masks):
            name = mask.get("name", mask.get("file_name", ""))
            detail = _listing_detail_suffix(
                mask.get("file_size"), mask.get("line_count")
            )
            entries.append(f"{idx + 1}. {name}{detail}")
        max_entry_len = max((len(e) for e in entries), default=30)
        print_multicolumn_list(
            "Available Hashmob Masks",
            entries,
            min_col_width=max_entry_len,
            max_col_width=max_entry_len,
        )
        return masks
    except Exception as e:
        print(f"Error fetching Hashmob masks: {e}")
        return []


def download_hashmob_mask(file_name, out_path):
    """Download a mask file from Hashmob by file name."""
    url = f"https://hashmob.net/api/v2/downloads/research/masks/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}

    def _attempt():
        _hashmob_limiter.wait()
        with requests.get(
            url, headers=headers, stream=True, timeout=60, allow_redirects=True
        ) as r:
            if r.status_code == 429:
                raise _Hashmob429(_parse_retry_after(r))
            r.raise_for_status()
            return _stream_response_to_file(r, out_path, label=file_name)

    try:
        return _with_hashmob_backoff(_attempt)
    except Exception as e:
        print(f"Error downloading mask: {e}")
        return False


def list_official_wordlists():
    """List files in the official wordlists directory via the Hashmob API."""
    url = "https://hashmob.net/api/v2/downloads/research/official/"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        try:
            data = resp.json()
            entries = [f"{idx + 1}. {entry}" for idx, entry in enumerate(data)]
            max_entry_len = max((len(e) for e in entries), default=30)
            print_multicolumn_list(
                "Official Hashmob Wordlists (JSON)",
                entries,
                min_col_width=max_entry_len,
                max_col_width=max_entry_len,
            )
            return data
        except Exception:
            print("Official Hashmob Wordlists (raw text):")
            print(resp.text)
            return resp.text
    except Exception as e:
        print(f"Error listing official wordlists: {e}")
        return []


def list_and_download_official_wordlists():
    """List files in the official wordlists directory via the Hashmob API, prompt for selection, and download."""
    url = "https://hashmob.net/api/v2/downloads/research/official/"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not isinstance(data, list):
            print("Unexpected response format. Raw output:")
            print(data)
            return
        entries = []
        for idx, entry in enumerate(data):
            name = entry.get("name", entry.get("file_name", str(entry)))
            file_name = entry.get("file_name", name)
            entries.append(f"{idx + 1}. {name} ({file_name})")
        max_entry_len = max((len(e) for e in entries), default=30)
        print_multicolumn_list(
            "Official Hashmob Wordlists",
            entries,
            min_col_width=max_entry_len,
            max_col_width=max_entry_len,
        )
        print("a. Download ALL files")

        def _safe_input(prompt):
            try:
                if not sys.stdin or not sys.stdin.isatty():
                    return "q"
            except Exception:
                return "q"
            try:
                return input(prompt)
            except EOFError:
                return "q"

        sel = _safe_input(
            "Enter the number(s) to download (e.g. 1,3,5-7), or 'a' for all, or 'q' to quit: "
        )
        if sel.lower() == "q":
            return
        dest_dir = get_hcat_wordlists_dir()

        def _already_downloaded_wordlist(file_name):
            sanitized = sanitize_filename(file_name)
            if sanitized.endswith(".7z"):
                extracted_name = sanitized[:-3]
                check_path = os.path.join(dest_dir, extracted_name)
            else:
                check_path = os.path.join(dest_dir, sanitized)
            return os.path.isfile(check_path) and os.path.getsize(check_path) > 0

        if sel.lower() == "a":
            try:
                for entry in data:
                    file_name = entry.get("file_name")
                    if not file_name:
                        print("No file_name found for an entry, skipping.")
                        continue
                    if _already_downloaded_wordlist(file_name):
                        print(f"[i] Skipping {file_name} (already present)")
                        continue
                    download_official_wordlist(file_name)
            except KeyboardInterrupt:
                print("\nKeyboard interrupt: Returning to download menu...")
                return
            return

        def parse_indices(selection, max_index):
            indices = set()
            for part in selection.split(","):
                part = part.strip()
                if not part:
                    continue
                if "-" in part:
                    try:
                        start, end = map(int, part.split("-", 1))
                        if start > end:
                            start, end = end, start
                        indices.update(range(start, end + 1))
                    except Exception:
                        continue
                else:
                    try:
                        indices.add(int(part))
                    except Exception:
                        continue
            return sorted(i for i in indices if 1 <= i <= max_index)

        try:
            indices = parse_indices(sel, len(data))
            if not indices:
                print("No valid selection.")
                return
            for idx in indices:
                entry = data[idx - 1]
                file_name = entry.get("file_name")
                if not file_name:
                    print("No file_name found for selection, skipping.")
                    continue
                if _already_downloaded_wordlist(file_name):
                    print(f"[i] Skipping {file_name} (already present)")
                    continue
                download_official_wordlist(file_name)
        except Exception as e:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error listing official wordlists: {e}")


def _downloaded_rule_names(rules_dir):
    """Names of rule files already present, for the download dedup check.

    Files only: a directory whose name matches a wanted rule would otherwise
    mark it as already downloaded and skip it.
    """
    try:
        return {
            name
            for name in os.listdir(rules_dir)
            if os.path.isfile(os.path.join(rules_dir, name))
        }
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return set()


def _downloaded_mask_names(masks_dir):
    """Names of mask files already present, for the download dedup check.

    Files only: a directory whose name matches a wanted mask would otherwise
    mark it as already downloaded and skip it.
    """
    try:
        return {
            name
            for name in os.listdir(masks_dir)
            if os.path.isfile(os.path.join(masks_dir, name))
        }
    except (FileNotFoundError, NotADirectoryError, PermissionError):
        return set()


def list_and_download_hashmob_masks(masks_dir=None):
    """List masks via the Hashmob API, prompt for selection, and download."""
    masks = download_hashmob_mask_list()
    if not masks:
        return
    print("a. Download ALL files")

    def _safe_input(prompt):
        try:
            if not sys.stdin or not sys.stdin.isatty():
                return "q"
        except Exception:
            return "q"
        try:
            return input(prompt)
        except EOFError:
            return "q"

    sel = _safe_input(
        "Enter the number(s) to download (e.g. 1,3,5-7), or 'a' for all, or 'q' to quit: "
    )
    if sel.lower() == "q":
        return
    if not masks_dir:
        masks_dir = os.path.join(_get_hate_path(), "masks")

    def parse_indices(selection, max_index):
        indices = set()
        for part in selection.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-", 1))
                    if start > end:
                        start, end = end, start
                    indices.update(range(start, end + 1))
                except Exception:
                    continue
            else:
                try:
                    indices.add(int(part))
                except Exception:
                    continue
        return sorted(i for i in indices if 1 <= i <= max_index)

    # Track already-downloaded masks to avoid duplicates
    downloaded_masks = _downloaded_mask_names(masks_dir)

    def already_downloaded(file_name):
        sanitized = sanitize_filename(file_name)
        return sanitized in downloaded_masks

    if sel.lower() == "a":
        entries = masks
    else:
        indices = parse_indices(sel, len(masks))
        if not indices:
            print("No valid selection.")
            return
        entries = [masks[idx - 1] for idx in indices]

    jobs = []
    for entry in entries:
        file_name = entry.get("file_name")
        if not file_name:
            print("No file_name found for an entry, skipping.")
            continue
        if already_downloaded(file_name):
            print(f"[i] Skipping already downloaded mask: {file_name}")
            continue
        os.makedirs(masks_dir, exist_ok=True)
        out_path = os.path.join(masks_dir, sanitize_filename(file_name))
        jobs.append((file_name, out_path))

    if not jobs:
        return

    succeeded = 0
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(download_hashmob_mask, fn, op): fn for fn, op in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            file_name = futures[future]
            try:
                future.result()
                succeeded += 1
            except Exception as exc:
                print(f"[!] Failed to download {file_name}: {exc}")
                failed += 1

    print(f"[i] Mask downloads complete: {succeeded} succeeded, {failed} failed.")


def list_and_download_hashmob_rules(rules_dir=None):
    """List rules via the Hashmob API, prompt for selection, and download."""
    rules = download_hashmob_rule_list()
    if not rules:
        return
    print("a. Download ALL files")

    def _safe_input(prompt):
        try:
            if not sys.stdin or not sys.stdin.isatty():
                return "q"
        except Exception:
            return "q"
        try:
            return input(prompt)
        except EOFError:
            return "q"

    sel = _safe_input(
        "Enter the number(s) to download (e.g. 1,3,5-7), or 'a' for all, or 'q' to quit: "
    )
    if sel.lower() == "q":
        return
    if not rules_dir:
        rules_dir = get_rules_dir()

    def parse_indices(selection, max_index):
        indices = set()
        for part in selection.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    start, end = map(int, part.split("-", 1))
                    if start > end:
                        start, end = end, start
                    indices.update(range(start, end + 1))
                except Exception:
                    continue
            else:
                try:
                    indices.add(int(part))
                except Exception:
                    continue
        return sorted(i for i in indices if 1 <= i <= max_index)

    # Track already-downloaded rules to avoid duplicates
    downloaded_rules = _downloaded_rule_names(rules_dir)

    def already_downloaded(file_name):
        sanitized = sanitize_filename(file_name)
        return sanitized in downloaded_rules

    if sel.lower() == "a":
        entries = rules
    else:
        indices = parse_indices(sel, len(rules))
        if not indices:
            print("No valid selection.")
            return
        entries = [rules[idx - 1] for idx in indices]

    jobs = []
    for entry in entries:
        file_name = entry.get("file_name")
        if not file_name:
            print("No file_name found for an entry, skipping.")
            continue
        if already_downloaded(file_name):
            print(f"[i] Skipping already downloaded rule: {file_name}")
            continue
        out_path = os.path.join(rules_dir, sanitize_filename(file_name))
        resource_type = entry.get("type")
        jobs.append((file_name, out_path, resource_type))

    if not jobs:
        return

    succeeded = 0
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(download_hashmob_rule, fn, op, rt): fn
            for fn, op, rt in jobs
        }
        for future in concurrent.futures.as_completed(futures):
            file_name = futures[future]
            try:
                future.result()
                succeeded += 1
            except Exception as exc:
                print(f"[!] Failed to download {file_name}: {exc}")
                failed += 1

    print(f"[i] Rule downloads complete: {succeeded} succeeded, {failed} failed.")


def download_official_wordlist(file_name, out_path=None):
    """Download a file from the official wordlists directory with a progress bar."""
    import re

    url = f"https://hashmob.net/api/v2/downloads/research/official/{file_name}"
    if not out_path:
        out_path = sanitize_filename(file_name)
    dest_dir = get_hcat_wordlists_dir()
    archive_path = (
        os.path.join(dest_dir, out_path) if not os.path.isabs(out_path) else out_path
    )
    os.makedirs(os.path.dirname(archive_path), exist_ok=True)

    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}

    def _attempt():
        _hashmob_limiter.wait()
        with requests.get(
            url, headers=headers, stream=True, timeout=60, allow_redirects=True
        ) as r:
            if r.status_code == 429:
                raise _Hashmob429(_parse_retry_after(r))
            r.raise_for_status()
            content_type = r.headers.get("Content-Type", "")
            if "text/plain" in content_type:
                html = r.content.decode(errors="replace")
                match = re.search(
                    r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"]0;url=([^'\"]+)['\"]",
                    html,
                    re.IGNORECASE,
                )
                if match:
                    real_url = match.group(1)
                    print(f"Found meta refresh redirect to: {real_url}")
                    return _streamed_download(real_url, archive_path, label=file_name)
                print(
                    "Error: Received HTML instead of file. Possible permission or quota issue."
                )
                return False
            return _stream_response_to_file(r, archive_path, label=file_name)

    try:
        ok = _with_hashmob_backoff(_attempt)
    except Exception as e:
        print(f"Error downloading official wordlist: {e}")
        return False

    if ok and archive_path.endswith(".7z"):
        extract_with_7z(archive_path)
    return ok


def extract_with_7z(archive_path, output_dir=None, remove_archive=True):
    """Extract a .7z archive using the 7z or 7za command."""
    import subprocess

    if output_dir is None:
        output_dir = os.path.dirname(archive_path) or "."
    sevenz_bin = shutil.which("7z") or shutil.which("7za")
    if not sevenz_bin:
        print(
            "[!] 7z or 7za not found in PATH. Please install p7zip-full or 7-zip to extract archives."
        )
        return False
    try:
        print(f"Extracting {archive_path} to {output_dir} ...")
        result = subprocess.run(
            [sevenz_bin, "e", "-y", archive_path],
            capture_output=True,
            text=True,
            cwd=output_dir,
        )
        print(result.stdout)
        if result.returncode == 0:
            print(f"[+] Extraction complete: {archive_path}")
            if remove_archive:
                try:
                    os.remove(archive_path)
                    print(f"[i] Removed archive: {archive_path}")
                except Exception as e:
                    print(f"[!] Could not remove archive {archive_path}: {e}")
            return True
        print(f"[!] Extraction failed for {archive_path}: {result.stderr}")
        return False
    except Exception as e:
        print(f"[!] Error extracting {archive_path}: {e}")
        return False


def download_hashmob_wordlists(print_fn=print) -> None:
    """Download official Hashmob wordlists."""
    list_and_download_official_wordlists()
    print_fn("Hashmob wordlist download complete.")


def download_hashmob_rules(print_fn=print, rules_dir=None) -> None:
    """Download Hashmob rules."""
    list_and_download_hashmob_rules(rules_dir=rules_dir)
    print_fn("Hashmob rules download complete.")


def download_hashmob_masks(print_fn=print, masks_dir=None) -> None:
    """Download Hashmob masks."""
    list_and_download_hashmob_masks(masks_dir=masks_dir)
    print_fn("Hashmob masks download complete.")


def download_weakpass_torrent(download_torrent, filename: str, print_fn=print) -> None:
    """Download a single Weakpass torrent file by name or URL."""
    print_fn(f"[i] Downloading: {filename}")
    download_torrent(filename)


def download_all_weakpass_torrents(
    fetch_all_wordlists,
    download_torrent,
    print_fn=print,
    cache_path: str = "weakpass_wordlists.json",
) -> None:
    """Download all Weakpass torrents from a cached wordlist JSON."""
    if not os.path.exists(cache_path):
        print_fn("[i] weakpass_wordlists.json not found, fetching wordlist cache...")
        fetch_all_wordlists()
    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            all_wordlists = json.load(f)
    except Exception as exc:
        print_fn(f"Failed to load local wordlist cache: {exc}")
        raise
    if any("id" not in wl or wl.get("id") in ("", None) for wl in all_wordlists):
        print_fn(
            "[i] weakpass_wordlists.json missing wordlist IDs, refreshing cache..."
        )
        fetch_all_wordlists()
        with open(cache_path, "r", encoding="utf-8") as f:
            all_wordlists = json.load(f)
    torrents = [
        (wl.get("torrent_url"), wl.get("id"))
        for wl in all_wordlists
        if wl.get("torrent_url")
    ]
    print_fn(f"[i] Downloading {len(torrents)} torrents...")
    torrent_files = []
    for tfile, wordlist_id in torrents:
        print_fn(f"[i] Fetching torrent metadata: {tfile}")
        meta = download_torrent(tfile, wordlist_id=wordlist_id)
        if meta:
            torrent_files.append(meta)
    if torrent_files:
        run_torrent_session(
            torrent_files, save_dir=get_hcat_wordlists_dir(), print_fn=print_fn
        )
    print_fn("[i] All torrents processed.")
