import concurrent.futures
import json
import sys
import os
import shutil
import tempfile
import threading
import time
from queue import Queue
from typing import Callable, Optional, Tuple

import requests  # type: ignore[import-untyped]
from bs4 import BeautifulSoup

from hate_crack.cli import orig_cwd
from hate_crack.formatting import print_multicolumn_list

_TORRENT_CLEANUP_REGISTERED = False


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


def _stream_response_to_file(
    r,
    dest_path: str,
    *,
    label: str | None = None,
    show_progress: bool = True,
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
            for chunk in r.iter_content(chunk_size=8192):
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
            return _stream_response_to_file(r, dest_path, label=label, show_progress=show_progress)
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
        except _Hashmob429:
            if attempt == max_attempts - 1:
                break
            print(f"[!] Rate limit hit (429). Backing off for {penalty} seconds...")
            time.sleep(penalty)
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


def _candidate_roots():
    cwd = os.getcwd()
    home = os.path.expanduser("~")
    candidates = [
        cwd,
        os.path.abspath(os.path.join(cwd, os.pardir)),
        "/opt/hate_crack",
        "/usr/local/share/hate_crack",
    ]
    for candidate_name in ["hate_crack", "hate-crack", ".hate_crack"]:
        candidates.append(os.path.join(home, candidate_name))
    return candidates


def _resolve_config_path():
    for candidate in _candidate_roots():
        config_path = os.path.join(candidate, "config.json")
        if os.path.isfile(config_path):
            return config_path
    return None


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
        self._watch_dir = ""
        self._port = 0
        self._rpc = ""
        self._proc = None
        self._stopped = False

    def __enter__(self):
        import atexit
        import subprocess

        self._cfg_dir = tempfile.mkdtemp(prefix="hate_crack_transmission_")
        self._watch_dir = os.path.join(self._cfg_dir, "watch")
        os.makedirs(self._watch_dir, exist_ok=True)
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
                "--watch-dir",
                self._watch_dir,
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
        before_ids = {e["id"] for e in self.list()}
        shutil.copy2(torrent_path, self._watch_dir)
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline:
            after_entries = self.list()
            new_ids = [e["id"] for e in after_entries if e["id"] not in before_ids]
            if new_ids:
                return new_ids[0]
            time.sleep(0.5)
        raise RuntimeError(f"Failed to add torrent: {torrent_path}")

    def list(self) -> list:
        import subprocess

        result = subprocess.run(
            ["transmission-remote", self._rpc, "--no-auth", "-l"],
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
                name = " ".join(tokens[8:]) if len(tokens) > 8 else (
                    tokens[-1] if len(tokens) > 1 else ""
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
                "--no-auth",
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
                "--no-auth",
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
                if (
                    entry["percent_done"] >= 100.0
                    and entry["id"] not in completed_ids
                ):
                    completed_ids.add(entry["id"])
                    file_name = self.info_file(entry["id"])
                    on_complete(entry["id"], file_name)
                    self.remove(entry["id"])


def get_hcat_wordlists_dir():
    config_path = _resolve_config_path()
    if config_path:
        try:
            with open(config_path) as f:
                config = json.load(f)
            path = config.get("hcatWordlists")
            if path:
                path = os.path.expanduser(path)
                if not os.path.isabs(path):
                    path = os.path.normpath(os.path.join(_get_hate_path(), path))
                os.makedirs(path, exist_ok=True)
                return path
        except Exception:
            pass
    default = os.path.join(os.getcwd(), "wordlists")
    os.makedirs(default, exist_ok=True)
    return default


def get_rules_dir():
    config_path = _resolve_config_path()
    if config_path:
        try:
            with open(config_path) as f:
                config = json.load(f)
            path = config.get("rules_directory")
            if path:
                path = os.path.expanduser(path)
                if not os.path.isabs(path):
                    path = os.path.normpath(os.path.join(_get_hate_path(), path))
                os.makedirs(path, exist_ok=True)
                return path
        except Exception:
            pass
    default = os.path.join(os.getcwd(), "rules")
    os.makedirs(default, exist_ok=True)
    return default


def get_hcat_tuning_args():
    config_path = _resolve_config_path()
    if config_path:
        try:
            with open(config_path) as f:
                config = json.load(f)
            tuning = config.get("hcatTuning")
            if tuning:
                import shlex

                return shlex.split(tuning)
        except Exception:
            pass
    return []


def get_hcat_potfile_path():
    """Return the resolved potfile path from config, or the default."""
    config_path = _resolve_config_path()
    if config_path:
        try:
            with open(config_path) as f:
                config = json.load(f)
            if "hcatPotfilePath" in config:
                raw = (config["hcatPotfilePath"] or "").strip()
                if raw == "":
                    return ""
                expanded = os.path.expanduser(raw)
                if not os.path.isabs(expanded):
                    expanded = os.path.join(os.path.dirname(config_path), expanded)
                return expanded
        except Exception:
            pass
    return os.path.expanduser("~/.hashcat/hashcat.potfile")


def get_hcat_potfile_args():
    """Return potfile args list for hashcat, e.g. ['--potfile-path=/path']."""
    pot = get_hcat_potfile_path()
    if pot:
        return [f"--potfile-path={pot}"]
    return []


def cleanup_torrent_files(directory=None):
    """Remove stray .torrent files left in the system temp directory on graceful exit."""
    if directory is None:
        directory = tempfile.gettempdir()
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
            file_path
            if os.path.isabs(file_path)
            else os.path.join(save_dir, file_path)
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
    print_fn(
        f"[i] Torrent session complete: {completed} succeeded, {failed} failed."
    )


def fetch_all_weakpass_wordlists_multithreaded(total_pages=None, threads=10):
    """Fetch all Weakpass wordlists. Auto-detects page count from the Inertia payload."""
    headers = {"User-Agent": "Mozilla/5.0"}

    def _fetch_page(page):
        """Fetch a single page; return (entries, last_page_or_None)."""
        url = f"https://weakpass.com/wordlists?page={page}"
        r = requests.get(url, headers=headers, timeout=30)
        soup = BeautifulSoup(r.text, "html.parser")
        app_div = soup.find("div", id="app")
        if not app_div or not app_div.has_attr("data-page"):
            return [], None
        data_page_val = app_div["data-page"]
        if not isinstance(data_page_val, str):
            data_page_val = str(data_page_val)
        data = json.loads(data_page_val)
        wordlists_raw = data.get("props", {}).get("wordlists", {})
        last_page = None
        if isinstance(wordlists_raw, dict):
            # Check multiple possible locations for last_page
            last_page = (
                wordlists_raw.get("last_page")
                or wordlists_raw.get("meta", {}).get("last_page")
            )
            if "data" in wordlists_raw:
                wordlists_raw = wordlists_raw["data"]
            else:
                wordlists_raw = []
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

    # Determine total_pages via probe if not provided
    if total_pages is None:
        try:
            entries1, detected = _fetch_page(1)
            if detected:
                total_pages = int(detected)
                print(f"[i] Weakpass: {total_pages} pages detected")
            elif entries1:
                # last_page not in payload; fall back to sequential until empty
                all_wordlists = list(entries1)
                page = 2
                while True:
                    try:
                        entries, _ = _fetch_page(page)
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
                print("[!] Weakpass page 1 returned no results; falling back to 67 pages")
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
                entries, _ = _fetch_page(page)
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


def fetch_torrent_metadata(torrent_url, save_dir=None, wordlist_id=None):
    """Download the .torrent metadata file from Weakpass and return its local path.

    Returns the path to the saved .torrent file, or None on failure.
    The .torrent file is stored in the system temp directory, not the wordlist dir.
    """
    register_torrent_cleanup()

    torrent_dir = tempfile.gettempdir()
    os.makedirs(torrent_dir, exist_ok=True)
    # Optionally include hashmob_api_key in headers if present
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    hashmob_api_key = None
    # Try to get hashmob_api_key from config
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
    for cfg in (
        os.path.join(pkg_dir, "config.json"),
        os.path.join(project_root, "config.json"),
    ):
        if os.path.isfile(cfg):
            try:
                with open(cfg) as f:
                    config = json.load(f)
                    key = config.get("hashmob_api_key")
                    if key:
                        hashmob_api_key = key
                        break
            except Exception:
                continue
    if hashmob_api_key:
        headers["api-key"] = hashmob_api_key

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
        wordlist_base = (
            filename.replace(".torrent", "").replace(".7z", "").replace(".txt", "")
        )
        wordlist_uri = f"https://weakpass.com/wordlists/{wordlist_base}"
        print(f"[+] Fetching wordlist page: {wordlist_uri}")
        r = requests.get(wordlist_uri, headers=headers)
        if r.status_code != 200:
            print(f"[!] Failed to fetch wordlist page: {wordlist_uri}")
            wordlist_uri = None
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            app_div = soup.find("div", id="app")
            if not app_div or not app_div.has_attr("data-page"):
                print(f"[!] Could not find app data on {wordlist_uri}")
            else:
                data_page_val = app_div["data-page"]
                if not isinstance(data_page_val, str):
                    data_page_val = str(data_page_val)
                data_page_val = data_page_val.replace("&quot;", '"')
                try:
                    data = json.loads(data_page_val)
                    wordlist = data.get("props", {}).get("wordlist")
                    resolved_id = None
                    torrent_link_from_data = None
                    if wordlist:
                        resolved_id = wordlist.get("id")
                        torrent_link_from_data = wordlist.get("torrent_link")
                    else:
                        wordlists = data.get("props", {}).get("wordlists")
                        if isinstance(wordlists, dict) and "data" in wordlists:
                            wordlists = wordlists["data"]
                        if isinstance(wordlists, list):
                            for wl in wordlists:
                                if (
                                    wl.get("torrent_link") == filename
                                    or wl.get("name") == filename
                                ):
                                    resolved_id = wl.get("id")
                                    torrent_link_from_data = wl.get("torrent_link")
                                    break
                                if wordlist_base in wl.get("name", ""):
                                    resolved_id = wl.get("id")
                                    torrent_link_from_data = wl.get("torrent_link")
                                    break
                    if torrent_link_from_data and resolved_id:
                        if not torrent_link_from_data.startswith("http"):
                            torrent_link = f"https://weakpass.com/download/{resolved_id}/{torrent_link_from_data}"
                        else:
                            torrent_link = torrent_link_from_data
                except Exception as e:
                    print(f"[!] Failed to parse data-page JSON: {e}")

    if not torrent_link:
        torrent_link = f"https://weakpass.com/files/{filename}"

    print(f"[+] Downloading .torrent file from: {torrent_link}")
    r2 = requests.get(torrent_link, headers=headers, stream=True)
    content_type = r2.headers.get("Content-Type", "")
    local_filename = os.path.join(
        torrent_dir, filename if filename.endswith(".torrent") else filename + ".torrent"
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
            html = r2.content.decode(errors="replace")
            print("--- Begin HTML Debug Output ---")
            print(html[:2000])
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
            meta = fetch_torrent_metadata(torrent_url, save_dir=save_dir, wordlist_id=entry.get("id"))
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
        resp = self.session.post(url, data=file_content, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def list_wordlists(self):
        """List available wordlists from Hashview API."""
        endpoint = f"{self.base_url}/v1/wordlists"
        response = self.session.get(endpoint, headers=self._auth_headers())
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
        resp = self.session.get(url, headers=self._auth_headers())
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
        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/hash_type"
        resp = self.session.get(url, headers=self._auth_headers())
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Failed to parse JSON from {url}: {e}")
            data = None
        hashtype = None
        if data:
            hashtype = data.get("hashtype") or data.get("hash_type") or data.get("type")
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
        resp = self.session.get(url)
        resp.raise_for_status()
        data = resp.json()
        if "users" in data:
            customers = json.loads(data["users"])
            return {"customers": customers}
        return data

    def list_hashfiles(self):
        url = f"{self.base_url}/v1/hashfiles"
        resp = self.session.get(url, headers=self._auth_headers())
        resp.raise_for_status()
        data = resp.json()
        if "hashfiles" in data:
            if isinstance(data["hashfiles"], str):
                hashfiles = json.loads(data["hashfiles"])
            else:
                hashfiles = data["hashfiles"]
            return hashfiles
        return []

    def get_customer_hashfiles(self, customer_id):
        all_hashfiles = self.list_hashfiles()
        customer_hfs = [
            hf for hf in all_hashfiles if int(hf.get("customer_id", 0)) == customer_id
        ]

        if self.debug:
            print(
                f"[DEBUG] get_customer_hashfiles({customer_id}): found {len(customer_hfs)} hashfiles"
            )

        # Fetch hash types for any hashfiles missing them
        for hf in customer_hfs:
            if not (hf.get("hashtype") or hf.get("hash_type")):
                hf_id = hf.get("id")
                if hf_id is not None:
                    if self.debug:
                        print(f"[DEBUG] Fetching hash_type for hashfile {hf_id}")
                    try:
                        details = self.get_hashfile_details(hf_id)
                        hashtype = details.get("hashtype")
                        if hashtype:
                            hf["hash_type"] = hashtype
                            if self.debug:
                                print(
                                    f"[DEBUG] Updated hashfile {hf_id} with hash_type={hashtype}"
                                )
                        elif self.debug:
                            print(
                                f"[DEBUG] No hashtype found in details for {hf_id}: {details}"
                            )
                    except Exception as e:
                        if self.debug:
                            print(
                                f"[DEBUG] Exception fetching hash_type for {hf_id}: {e}"
                            )

        return customer_hfs

    def get_customer_hashfiles_with_hashtype(self, customer_id, target_hashtype="1000"):
        """Return hashfiles for a customer that match the requested hashtype."""
        customer_hashfiles = self.get_customer_hashfiles(customer_id)
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
        with open(file_path, "rb") as f:
            file_content = f.read()
        url = (
            f"{self.base_url}/v1/hashfiles/upload/"
            f"{customer_id}/{file_format}/{hash_type}/{hashfile_name}"
        )
        headers = {"Content-Type": "text/plain"}
        resp = self.session.post(url, data=file_content, headers=headers)
        resp.raise_for_status()
        return resp.json()

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
        resp = self.session.post(url, json=data, headers=headers)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return {}

    def stop_job(self, job_id):
        url = f"{self.base_url}/v1/jobs/stop/{job_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def delete_job(self, job_id):
        url = f"{self.base_url}/v1/jobs/delete/{job_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        return resp.json()

    def start_job(self, job_id, priority=3, limit_recovered=False):
        url = f"{self.base_url}/v1/jobs/start/{job_id}"
        params = {}
        priority = int(priority)
        if priority < 1 or priority > 5:
            raise ValueError("priority must be an int between 1 and 5")
        params["priority"] = priority
        params["limit_recovered"] = bool(limit_recovered)
        resp = self.session.get(url, params=params)
        resp.raise_for_status()
        return resp.json()

    def download_left_hashes(
        self, customer_id, hashfile_id, output_file=None, hash_type=None, potfile_path=None
    ):
        import sys

        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/left"
        resp = self.session.get(url, headers=self._auth_headers(), stream=True)
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
            # Try to download the found file
            found_url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/found"
            found_resp = self.session.get(
                found_url, headers=self._auth_headers(), stream=True, timeout=30
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

                hashes_count = 0
                clears_count = 0

                with (
                    open(found_hashes_file, "w", encoding="utf-8") as hf,
                    open(found_clears_file, "w", encoding="utf-8") as cf,
                ):
                    with open(found_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                parts = line.split(":", 1)  # Split on first colon
                                if len(parts) == 2:
                                    hash_part, clear_part = parts
                                    hf.write(hash_part + "\n")
                                    cf.write(clear_part + "\n")
                                    hashes_count += 1
                                    clears_count += 1

                print(
                    f"Split found file into {hashes_count} hashes and {clears_count} clears"
                )

                # Append found hash:clear pairs to the potfile
                resolved_potfile = potfile_path if potfile_path is not None else get_hcat_potfile_path()
                if resolved_potfile:
                    appended = 0
                    with open(resolved_potfile, "a", encoding="utf-8") as pf:
                        with open(
                            found_file, "r", encoding="utf-8", errors="ignore"
                        ) as ff:
                            for line in ff:
                                line = line.strip()
                                if line and ":" in line:
                                    pf.write(line + "\n")
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

    def upload_cracked_hashes(self, file_path, hash_type="1000"):
        valid_lines = []
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if "31d6cfe0d16ae931b73c59d7e0c089c0" in line:
                    continue
                if not line or ":" not in line:
                    continue
                parts = line.split(":", 1)
                if len(parts) != 2:
                    break
                hash_value = parts[0].strip()
                plaintext = parts[1].strip()
                valid_lines.append(f"{hash_value}:{plaintext}")
        converted_content = "\n".join(valid_lines)
        url = f"{self.base_url}/v1/hashes/import/{hash_type}"
        headers = {"Content-Type": "text/plain"}
        resp = self.session.post(url, data=converted_content, headers=headers)
        resp.raise_for_status()
        try:
            json_response = resp.json()
            if "type" in json_response and json_response["type"] == "Error":
                raise Exception(
                    f"Hashview API Error: {json_response.get('msg', 'Unknown error')}"
                )
            return json_response
        except (json.JSONDecodeError, ValueError):
            raise Exception(f"Invalid API response: {resp.text[:200]}")

    def download_wordlist(
        self, wordlist_id, output_file=None, *, update_dynamic: bool = False
    ):
        import re

        if int(wordlist_id) == 1 and update_dynamic:
            update_url = f"{self.base_url}/v1/updateWordlist/{wordlist_id}"
            try:
                update_resp = self.session.get(
                    update_url, headers=self._auth_headers(), timeout=30
                )
                update_resp.raise_for_status()
            except Exception as exc:
                if self.debug:
                    print(
                        f"Warning: failed to update dynamic wordlist {wordlist_id}: {exc}"
                    )

        url = f"{self.base_url}/v1/wordlists/{wordlist_id}"
        resp = self.session.get(url, headers=self._auth_headers(), stream=True)
        resp.raise_for_status()

        if output_file is None:
            if int(wordlist_id) == 1:
                output_file = "dynamic-all.txt.gz"
            else:
                content_disp = resp.headers.get("content-disposition", "")
                match = re.search(
                    r"filename=\"?([^\";]+)\"?", content_disp, re.IGNORECASE
                )
                output_file = (
                    os.path.basename(match.group(1)) if match else f"wordlist_{wordlist_id}.gz"
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

    def create_customer(self, name):
        url = f"{self.base_url}/v1/customers/add"
        headers = {"Content-Type": "application/json"}
        data = {"name": name}
        resp = self.session.post(url, json=data, headers=headers)
        resp.raise_for_status()
        try:
            payload = resp.json()
        except Exception:
            return resp.json()

        msg = str(payload.get("msg", ""))
        if "invalid keyword argument for Customers" in msg:
            # Fallback for older Hashview servers that choke on JSON body parsing.
            resp = self.session.post(url, data={"name": name})
            resp.raise_for_status()
            return resp.json()
        return payload

    def get_hashfile_hash_type(self, hashtype_id):
        """
        Query /v1/hashfiles/hash_type/<int:hashtype_id> and return a list of file IDs.
        """
        url = f"{self.base_url}/v1/hashfiles/hash_type/{hashtype_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        try:
            data = resp.json()
            # Expecting a list of file IDs or a dict with a key containing them
            if isinstance(data, list):
                return data
            elif isinstance(data, dict):
                # Try common keys
                for key in ("file_ids", "ids", "hashfile_ids"):
                    if key in data and isinstance(data[key], list):
                        return data[key]
            return []
        except Exception:
            return []


def download_hashes_from_hashview(
    hashview_url: str,
    hashview_api_key: str,
    debug_mode: bool,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
    potfile_path: Optional[str] = None,
) -> Tuple[str, str]:
    """Interactive Hashview download flow used by CLI."""
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
        customer_hashfiles = api_harness.get_customer_hashfiles(customer_id)
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
        hash_type=selected_hash_type,
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
    """Return hashmob_api_key from config.json in package or project root."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
    for cfg in (
        os.path.join(pkg_dir, "config.json"),
        os.path.join(project_root, "config.json"),
    ):
        if os.path.isfile(cfg):
            try:
                with open(cfg) as f:
                    config = json.load(f)
                    key = config.get("hashmob_api_key")
                    if key:
                        return key
            except Exception:
                continue
    return None


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
            if info:
                entry = f"{idx + 1}. {name} - {info}"
            else:
                entry = f"{idx + 1}. {name}"
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
        with requests.get(url, headers=headers, stream=True, timeout=60, allow_redirects=True) as r:
            if r.status_code == 429:
                raise _Hashmob429()
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
                print("Error: Received HTML instead of file. Possible permission or quota issue.")
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
            entries.append(f"{idx + 1}. {rule.get('name', rule.get('file_name', ''))}")
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


def download_hashmob_rule(file_name, out_path):
    """Download a rule file from Hashmob by file name."""
    hashmob_rule_urls = {
        "nsa64.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/nsa64.rule",
        "OneRuleToRuleThemAll.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/OneRuleToRuleThemAll.rule",
        "pantagrule.hashorg.v6.one.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/pantagrule.hashorg.v6.one.rule",
        "_NSAKEY.v2.dive.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/_NSAKEY.v2.dive.rule",
        "append_digits_and_special.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/append_digits_and_special.rule",
        "best64.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/best64.rule",
        "blandyuk.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/blandyuk.rule",
        "blandyuk_basic.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/blandyuk_basic.rule",
        "combinator.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/combinator.rule",
        "dive.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/dive.rule",
        "fordy10k.txt": "https://www.hashmob.net/api/v2/downloads/research/rules/fordy10k.txt",
        "fordy50k.txt": "https://www.hashmob.net/api/v2/downloads/research/rules/fordy50k.txt",
        "FordyBigBoy.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/FordyBigBoy.rule",
        "fordyv1.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/fordyv1.rule",
        "Incisive-leetspeak.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Incisive-leetspeak.rule",
        "InsidePro-HashManager.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/InsidePro-HashManager.rule",
        "InsidePro-PasswordsPro.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/InsidePro-PasswordsPro.rule",
        "Robot-Best10.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Robot-Best10.rule",
        "Robot_CurrentBestRules.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Robot_CurrentBestRules.rule",
        "Robot_MyFavorite.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Robot_MyFavorite.rule",
        "Robot_ReverseRules.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Robot_ReverseRules.rule",
        "Robot_Top1268Rules.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Robot_Top1268Rules.rule",
        "Robot_toporder.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Robot_toporder.rule",
        "Top1268.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Top1268.rule",
        "top_1500.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/top_1500.rule",
        "top_250.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/top_250.rule",
        "top_3000.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/top_3000.rule",
        "top_500.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/top_500.rule",
        "top_5000.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/top_5000.rule",
        "top_750.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/top_750.rule",
        "Fordyv2.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Fordyv2.rule",
        "combinator_ngram.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/combinator_ngram.rule",
        "d3ad0ne.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/d3ad0ne.rule",
        "generated.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/generated.rule",
        "generated2.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/generated2.rule",
        "leetspeak.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/leetspeak.rule",
        "oscommerce.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/oscommerce.rule",
        "specific.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/specific.rule",
        "T0XlC-insert_00-99_1950-2050_toprules_0_F.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/T0XlC-insert_00-99_1950-2050_toprules_0_F.rule",
        "T0XlC-insert_space_and_special_0_F.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/T0XlC-insert_space_and_special_0_F.rule",
        "T0XlC-insert_top_100_passwords_1_G.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/T0XlC-insert_top_100_passwords_1_G.rule",
        "T0XlC.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/T0XlC.rule",
        "T0XlCv1.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/T0XlCv1.rule",
        "toggles1.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/toggles1.rule",
        "toggles2.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/toggles2.rule",
        "toggles3.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/toggles3.rule",
        "toggles4.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/toggles4.rule",
        "toggles5.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/toggles5.rule",
        "unix-ninja-leetspeak.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/unix-ninja-leetspeak.rule",
        "OneRuleToRuleThemStill.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/OneRuleToRuleThemStill.rule",
        "Pantacorn.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/Pantacorn.rule",
        "SuperUnicorn.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/SuperUnicorn.rule",
        "buka_400k.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/buka_400k.rule",
        "rockyou-30000.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/rockyou-30000.rule",
        "HashMob.100k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.100k.rule",
        "HashMob.10k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.10k.rule",
        "HashMob.150k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.150k.rule",
        "HashMob.1k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.1k.rule",
        "HashMob.20k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.20k.rule",
        "HashMob.50k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.50k.rule",
        "HashMob.5k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.5k.rule",
        "HashMob.75k.rule": "https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/HashMob.75k.rule",
        "HashMob._100.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/HashMob._100.rule",
        "HashMob._66.rule": "https://www.hashmob.net/api/v2/downloads/research/rules/HashMob._66.rule",
    }
    primary_url = hashmob_rule_urls.get(file_name)
    if not primary_url:
        print(
            f"[i] Hashmob rule not in pinned URL list, using public prefix: {file_name}"
        )
        primary_url = f"https://www.hashmob.net/api/v2/downloads/research/rules/{file_name}"
    alt_url = f"https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}

    def _attempt():
        _hashmob_limiter.wait()
        with requests.get(primary_url, headers=headers, stream=True, timeout=60, allow_redirects=True) as r:
            if r.status_code == 429:
                raise _Hashmob429()
            if r.status_code == 404 and alt_url:
                print(f"[i] Hashmob rule not found at primary URL, trying fallback: {alt_url}")
                with requests.get(alt_url, headers=headers, stream=True, timeout=60, allow_redirects=True) as r2:
                    if r2.status_code == 429:
                        raise _Hashmob429()
                    r2.raise_for_status()
                    return _stream_response_to_file(r2, out_path, label=file_name)
            r.raise_for_status()
            return _stream_response_to_file(r, out_path, label=file_name)

    try:
        return _with_hashmob_backoff(_attempt)
    except Exception as e:
        print(f"Error downloading rule: {e}")
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
    try:
        resp = requests.get(url, timeout=30)
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
                    out_path = entry.get("file_name", file_name)
                    download_official_wordlist(file_name, out_path)
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
                out_path = entry.get("file_name", file_name)
                download_official_wordlist(file_name, out_path)
        except Exception as e:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error listing official wordlists: {e}")


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
    downloaded_rules = set()
    # Scan rules_dir for existing files
    if os.path.isdir(rules_dir):
        for fname in os.listdir(rules_dir):
            downloaded_rules.add(fname)

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
        jobs.append((file_name, out_path))

    if not jobs:
        return

    succeeded = 0
    failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(download_hashmob_rule, fn, op): fn for fn, op in jobs
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


def download_official_wordlist(file_name, out_path):
    """Download a file from the official wordlists directory with a progress bar."""
    url = f"https://hashmob.net/api/v2/downloads/research/official/{file_name}"
    out_path = sanitize_filename(file_name)
    dest_dir = get_hcat_wordlists_dir()
    archive_path = (
        os.path.join(dest_dir, out_path)
        if not os.path.isabs(out_path)
        else out_path
    )
    os.makedirs(os.path.dirname(archive_path), exist_ok=True)
    ok = _streamed_download(url, archive_path, label=file_name)
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
