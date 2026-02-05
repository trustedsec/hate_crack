import json
import sys
import os
import threading
import time
from queue import Queue
import shutil
from typing import Callable, Tuple

import requests
from bs4 import BeautifulSoup

from hate_crack.formatting import print_multicolumn_list

_TORRENT_CLEANUP_REGISTERED = False


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


def check_transmission_cli():
    import shutil

    if shutil.which("transmission-cli"):
        return True
    print("\n[!] transmission-cli is missing.")
    print("To install on macOS:  brew install transmission-cli")
    print("To install on Ubuntu/Debian:  sudo apt-get install transmission-cli")
    print("Please install transmission-cli and try again.")
    return False


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
                    path = os.path.join(os.path.dirname(config_path), path)
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
                    path = os.path.join(os.path.dirname(config_path), path)
                os.makedirs(path, exist_ok=True)
                return path
        except Exception:
            pass
    default = os.path.join(os.getcwd(), "rules")
    os.makedirs(default, exist_ok=True)
    return default


def cleanup_torrent_files(directory=None):
    """Remove stray .torrent files from the wordlists directory on graceful exit."""
    if directory is None:
        directory = get_hcat_wordlists_dir()
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


def fetch_all_weakpass_wordlists_multithreaded(total_pages=67, threads=10):
    wordlists = []
    lock = threading.Lock()
    q = Queue()
    headers = {"User-Agent": "Mozilla/5.0"}

    def worker():
        while True:
            page = q.get()
            if page is None:
                break
            try:
                url = f"https://weakpass.com/wordlists?page={page}"
                r = requests.get(url, headers=headers, timeout=30)
                soup = BeautifulSoup(r.text, "html.parser")
                app_div = soup.find("div", id="app")
                if not app_div or not app_div.has_attr("data-page"):
                    q.task_done()
                    continue
                data_page_val = app_div["data-page"]
                if not isinstance(data_page_val, str):
                    data_page_val = str(data_page_val)
                data = json.loads(data_page_val)
                wordlists_data = data.get("props", {}).get("wordlists", {})
                if isinstance(wordlists_data, dict) and "data" in wordlists_data:
                    wordlists_data = wordlists_data["data"]
                with lock:
                    for wl in wordlists_data:
                        wordlists.append(
                            {
                                "id": wl.get("id", ""),
                                "name": wl.get("name", ""),
                                "size": wl.get("size", ""),
                                "rank": wl.get("rank", ""),
                                "downloads": wl.get("downloaded", ""),
                                "torrent_url": wl.get("torrent_link", ""),
                            }
                        )
            except Exception as e:
                print(f"Error fetching page {page}: {e}")
            q.task_done()

    for page in range(1, total_pages + 1):
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


def download_torrent_file(torrent_url, save_dir=None, wordlist_id=None):
    register_torrent_cleanup()

    if not save_dir:
        save_dir = get_hcat_wordlists_dir()
    else:
        save_dir = os.path.expanduser(save_dir)
        if not os.path.isabs(save_dir):
            save_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), save_dir
            )
    os.makedirs(save_dir, exist_ok=True)
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
        save_dir, filename if filename.endswith(".torrent") else filename + ".torrent"
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

    if shutil.which("transmission-cli") is None:
        print("[ERROR] transmission-cli is not installed or not in your PATH.")
        print(
            "Please install it with: brew install transmission-cli (on macOS) or your package manager."
        )
        print(
            f"Torrent file saved at {local_filename}, but download will not start until transmission-cli is available."
        )
        return local_filename

    def run_transmission(torrent_file, output_dir):
        import subprocess

        print(f"Starting transmission-cli for {torrent_file}...")
        try:
            pkg_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
            kill_script = os.path.join(
                project_root, "wordlists", "kill_transmission.sh"
            )
            cmd = ["transmission-cli", "-w", output_dir, torrent_file]
            if os.path.isfile(kill_script):
                cmd.extend(["-f", kill_script])
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
            if proc.stdout is not None:
                for line in proc.stdout:
                    print(line, end="")
            proc.wait()
            if proc.returncode != 0:
                print(
                    f"transmission-cli failed for {torrent_file} (exit {proc.returncode})"
                )
                return
            else:
                print(f"Download complete for {torrent_file}")
        except Exception as e:
            print(f"Error running transmission-cli: {e}")

    run_transmission(local_filename, save_dir)
    return local_filename


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
        for idx in indices:
            entry = filtered_wordlists[idx - 1]
            torrent_url = entry.get("torrent_url")
            if not torrent_url:
                print(f"[!] Missing torrent URL for selection {idx}")
                continue
            download_torrent_file(torrent_url, wordlist_id=entry.get("id"))
    except KeyboardInterrupt:
        print("\nKeyboard interrupt: Returning to main menu...")
        return
    except Exception as e:
        print(f"Error: {e}")


# Hashview Integration - Real API implementation matching hate_crack.py
class HashviewAPI:
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
        resp = self.session.get(url)
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
        resp = self.session.get(url)
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            data = None
        hashtype = None
        if data:
            hashtype = data.get("hashtype") or data.get("hash_type")
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
        resp = self.session.get(url)
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
        return [
            hf for hf in all_hashfiles if int(hf.get("customer_id", 0)) == customer_id
        ]

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
        self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=True
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
            payload = resp.json()
        except Exception:
            return resp.json()

        msg = str(payload.get("msg", ""))
        if "invalid keyword argument for JobNotifications" in msg:
            # Retry without notify_email for older Hashview servers.
            data.pop("notify_email", None)
            resp = self.session.post(url, json=data, headers=headers)
            resp.raise_for_status()
            return resp.json()
        return payload

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

    def download_left_hashes(self, customer_id, hashfile_id, output_file=None):
        import sys
        import re

        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/left"
        resp = self.session.get(url, stream=True)
        resp.raise_for_status()
        if output_file is None:
            output_file = f"left_{customer_id}_{hashfile_id}.txt"
        output_file = os.fspath(output_file)
        output_abs = os.path.abspath(output_file)
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
        
        # Try to download found file and merge with corresponding .out file if it exists
        combined_count = 0
        combined_file = None
        out_dir = os.path.dirname(output_abs) or os.getcwd()
        found_file = os.path.join(out_dir, f"found_{customer_id}_{hashfile_id}.txt")
        
        try:
            # Try to download the found file
            found_url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/found"
            found_resp = self.session.get(found_url, stream=True, timeout=30)
            
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
                
                # Determine the .out file (either .txt.out for regular or .nt.txt.out for pwdump)
                out_file = output_abs + ".out"
                if not os.path.exists(out_file):
                    # Check for pwdump format .nt.txt.out file if caller used the .txt name.
                    if out_file.endswith(".txt.out") and not out_file.endswith(".nt.txt.out"):
                        out_file = out_file.replace(".txt.out", ".nt.txt.out")
                
                # Only merge if the .out file exists
                if os.path.exists(out_file):
                    # Read existing hashes from .out file into a set
                    out_hashes = set()
                    with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                out_hashes.add(line)
                    
                    original_count = len(out_hashes)
                    
                    # Read and add hashes from the found file
                    with open(found_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                out_hashes.add(line)
                    
                    combined_count = len(out_hashes) - original_count
                    
                    # Write combined results back to the .out file
                    combined_file = out_file
                    with open(combined_file, "w", encoding="utf-8") as f:
                        for line in sorted(out_hashes):
                            f.write(line + "\n")
                    
                    print(f"Merged {combined_count} new hashes from {found_file}")
                    print(f"Total unique hashes in {combined_file}: {len(out_hashes)}")
                
                # Delete the found file after successful merge
                try:
                    os.remove(found_file)
                    print(f"Deleted {found_file}")
                except Exception as e:
                    print(f"Warning: Could not delete {found_file}: {e}")
                    
        except Exception as e:
            # If there's any error downloading found file, just skip it
            print(f"Note: Could not download found hashes: {e}")
            # Clean up found file if it was partially written
            try:
                if os.path.exists(found_file):
                    os.remove(found_file)
            except Exception:
                pass
        
        return {
            "output_file": output_file,
            "size": downloaded,
            "combined_count": combined_count,
            "combined_file": combined_file,
        }

    def download_found_hashes(self, customer_id, hashfile_id, output_file=None):
        import sys

        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}/found"
        resp = self.session.get(url, stream=True)
        resp.raise_for_status()
        if output_file is None:
            output_file = f"found_{customer_id}_{hashfile_id}.txt"
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

        # Combine with corresponding left file output if it exists
        # Only combine if the output file matches the expected naming pattern
        combined_count = 0
        combined_file = None

        # Extract customer_id and hashfile_id from the output filename to ensure proper matching
        import re

        output_basename = os.path.basename(output_file)
        # Match pattern: found_{customer_id}_{hashfile_id}.txt
        match = re.match(r"found_(\d+)_(\d+)\.txt$", output_basename)

        if match:
            found_customer_id = match.group(1)
            found_hashfile_id = match.group(2)

            # Only proceed if the IDs from filename match the actual download IDs
            if (
                str(customer_id) == found_customer_id
                and str(hashfile_id) == found_hashfile_id
            ):
                left_base = f"left_{customer_id}_{hashfile_id}.txt"

                # Check for regular format .out file
                left_out = left_base + ".out"
                if not os.path.exists(left_out):
                    # Check for pwdump format .nt.txt.out file
                    left_out = f"left_{customer_id}_{hashfile_id}.nt.txt.out"

                if os.path.exists(left_out):
                    # Read existing hashes from .out file into a set
                    found_hashes = set()
                    with open(left_out, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                found_hashes.add(line)

                    original_count = len(found_hashes)

                    # Read and add hashes from the downloaded found file
                    with open(output_file, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                found_hashes.add(line)

                    combined_count = len(found_hashes) - original_count

                    # Write combined results to the .out file
                    combined_file = left_out
                    with open(combined_file, "w", encoding="utf-8") as f:
                        for line in sorted(found_hashes):
                            f.write(line + "\n")

                    print(f"Combined {combined_count} new hashes from {output_file}")
                    print(
                        f"Total unique hashes in {combined_file}: {len(found_hashes)}"
                    )
                    
                    # Delete the found file after successful merge
                    try:
                        os.remove(output_file)
                        print(f"Deleted {output_file} after merge")
                    except Exception as e:
                        print(f"Warning: Could not delete {output_file}: {e}")
            else:
                print(
                    f"Skipping combine: customer_id/hashfile_id mismatch (expected {customer_id}/{hashfile_id}, filename has {found_customer_id}/{found_hashfile_id})"
                )
        else:
            print(
                f"Skipping combine: output filename '{output_basename}' doesn't match expected pattern 'found_<customer_id>_<hashfile_id>.txt'"
            )

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

    def download_wordlist(self, wordlist_id, output_file=None):
        import sys

        url = f"{self.base_url}/v1/wordlists/{wordlist_id}"
        resp = self.session.get(url, stream=True)
        resp.raise_for_status()
        if output_file is None:
            output_file = f"wordlist_{wordlist_id}.gz"
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
        if total == 0:
            print(f"Downloaded {downloaded} bytes.")
        return {"output_file": output_file, "size": downloaded}

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
            print_fn("\n" + "=" * 100)
            print_fn(f"Hashfiles for Customer ID {customer_id}:")
            print_fn("=" * 100)
            print_fn(f"{'ID':<10} {'Name':<88}")
            print_fn("-" * 100)
            for hf in customer_hashfiles:
                hf_id = hf.get("id", "N/A")
                hf_name = hf.get("name", "N/A")
                if len(str(hf_name)) > 88:
                    hf_name = str(hf_name)[:85] + "..."
                print_fn(f"{hf_id:<10} {hf_name:<88}")
            print_fn("=" * 100)
            print_fn(f"Total: {len(customer_hashfiles)} hashfile(s)")
        else:
            print_fn(f"\nNo hashfiles found for customer ID {customer_id}")
            print_fn("This customer needs to have hashfiles uploaded before downloading left hashes.")
            print_fn("Please use the Hashview menu to upload a hashfile first.")
            raise ValueError("No hashfiles available for download")
    except ValueError:
        raise
    except Exception as exc:
        print_fn(f"\nWarning: Could not list hashfiles: {exc}")
        print_fn("You may need to manually find the hashfile ID in the web interface.")
    hashfile_raw = _safe_input("\nEnter hashfile ID: ").strip()
    if hashfile_raw.lower() == "q":
        raise ValueError("cancelled")
    hashfile_id = int(hashfile_raw)
    hcat_hash_type = "1000"
    output_file = f"left_{customer_id}_{hashfile_id}.txt"
    download_result = api_harness.download_left_hashes(
        customer_id, hashfile_id, output_file
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
    url = f"https://hashmob.net/api/v2/downloads/research/wordlists/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    base_backoff = 256
    max_backoff = 300
    penalty_add = 2
    penalty = base_backoff
    lock = getattr(download_hashmob_wordlist, "_rate_lock", None)
    if lock is None:
        lock = threading.Lock()
        download_hashmob_wordlist._rate_lock = lock
    while True:
        with lock:
            time.sleep(15)
        try:
            with requests.get(
                url, headers=headers, stream=True, timeout=60, allow_redirects=True
            ) as r:
                if r.status_code == 429:
                    print(
                        f"[!] Rate limit hit (429). Backing off for {penalty} seconds..."
                    )
                    time.sleep(penalty)
                    penalty = min(penalty + penalty_add, max_backoff)
                    penalty_add *= 2
                    continue
                if r.status_code in (301, 302, 303, 307, 308):
                    redirect_url = r.headers.get("Location")
                    if redirect_url:
                        print(f"Following redirect to: {redirect_url}")
                        return download_hashmob_wordlist(redirect_url, out_path)
                    print("Redirect with no Location header!")
                    return False
                r.raise_for_status()
                content_type = r.headers.get("Content-Type", "")
                if "text/plain" in content_type:
                    html = r.content.decode(errors="replace")
                    import re

                    match = re.search(
                        r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"]0;url=([^'\"]+)['\"]",
                        html,
                        re.IGNORECASE,
                    )
                    if match:
                        real_url = match.group(1)
                        print(f"Found meta refresh redirect to: {real_url}")
                        with requests.get(real_url, stream=True, timeout=120) as r2:
                            r2.raise_for_status()
                            with open(out_path, "wb") as f:
                                for chunk in r2.iter_content(chunk_size=8192):
                                    if chunk:
                                        f.write(chunk)
                        print(f"Downloaded {out_path}")
                        return True
                    print(
                        "Error: Received HTML instead of file. Possible permission or quota issue."
                    )
                    return False
                with open(out_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            print(f"Downloaded {out_path}")
            return True
        except Exception as e:
            if (
                hasattr(e, "response")
                and getattr(e.response, "status_code", None) == 429
            ):
                print(f"[!] Rate limit hit (429). Backing off for {penalty} seconds...")
                time.sleep(penalty)
                penalty = min(penalty + penalty_add, max_backoff)
                penalty_add *= 2
                continue
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
    url = hashmob_rule_urls.get(file_name)
    if not url:
        print(
            f"[i] Hashmob rule not in pinned URL list, using public prefix: {file_name}"
        )
        url = f"https://www.hashmob.net/api/v2/downloads/research/rules/{file_name}"
    alt_url = f"https://hashmob.net/api/v2/downloads/research/official/hashmob_rules/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    base_backoff = 256
    max_backoff = 300
    penalty_add = 2
    penalty = base_backoff
    lock = getattr(download_hashmob_rule, "_rate_lock", None)
    if lock is None:
        lock = threading.Lock()
        download_hashmob_rule._rate_lock = lock
    while True:
        with lock:
            time.sleep(15)
        try:
            with requests.get(
                url, headers=headers, stream=True, timeout=60, allow_redirects=True
            ) as r:
                if r.status_code == 429:
                    print(
                        f"[!] Rate limit hit (429). Backing off for {penalty} seconds..."
                    )
                    time.sleep(penalty)
                    penalty = min(penalty + penalty_add, max_backoff)
                    penalty_add *= 2
                    continue
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
                    ) as r_alt:
                        if r_alt.status_code == 429:
                            print(
                                f"[!] Rate limit hit (429). Backing off for {penalty} seconds..."
                            )
                            time.sleep(penalty)
                            penalty = min(penalty + penalty_add, max_backoff)
                            penalty_add *= 2
                            continue
                        r_alt.raise_for_status()
                        with open(out_path, "wb") as f:
                            for chunk in r_alt.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                    print(f"Downloaded {out_path}")
                    return True
                r.raise_for_status()
                with open(out_path, "wb") as f:
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
            print(f"Downloaded {out_path}")
            return True
        except Exception as e:
            # If it's a 429 error, handle backoff, else fail
            if (
                hasattr(e, "response")
                and getattr(e.response, "status_code", None) == 429
            ):
                print(f"[!] Rate limit hit (429). Backing off for {penalty} seconds...")
                time.sleep(penalty)
                penalty = min(penalty + penalty_add, max_backoff)
                penalty_add *= 2
                continue
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
        if sel.lower() == "a":
            try:
                for entry in data:
                    file_name = entry.get("file_name")
                    if not file_name:
                        print("No file_name found for an entry, skipping.")
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
                out_path = entry.get("file_name", file_name)
                download_official_wordlist(file_name, out_path)
        except Exception as e:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error listing official wordlists: {e}")


def list_and_download_hashmob_rules():
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
        for entry in rules:
            file_name = entry.get("file_name")
            if not file_name:
                print("No file_name found for an entry, skipping.")
                continue
            out_path = os.path.join(rules_dir, sanitize_filename(file_name))
            if already_downloaded(file_name):
                print(f"[i] Skipping already downloaded rule: {file_name}")
                continue
            download_hashmob_rule(file_name, out_path)
        return

    indices = parse_indices(sel, len(rules))
    if not indices:
        print("No valid selection.")
        return
    for idx in indices:
        entry = rules[idx - 1]
        file_name = entry.get("file_name")
        if not file_name:
            print("No file_name found for selection, skipping.")
            continue
        out_path = os.path.join(rules_dir, sanitize_filename(file_name))
        if already_downloaded(file_name):
            print(f"[i] Skipping already downloaded rule: {file_name}")
            continue
        download_hashmob_rule(file_name, out_path)


def download_official_wordlist(file_name, out_path):
    """Download a file from the official wordlists directory with a progress bar."""
    import sys

    url = f"https://hashmob.net/api/v2/downloads/research/official/{file_name}"
    archive_path = None
    try:
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            try:
                total = int(r.headers.get("content-length") or 0)
            except Exception:
                total = 0
            downloaded = 0
            chunk_size = 8192
            out_path = sanitize_filename(file_name)
            dest_dir = get_hcat_wordlists_dir()
            archive_path = (
                os.path.join(dest_dir, out_path)
                if not os.path.isabs(out_path)
                else out_path
            )
            temp_path = archive_path + ".part"
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            with open(temp_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            done = int(50 * downloaded / total)
                            percent = 100 * downloaded / total
                            bar = "=" * done + " " * (50 - done)
                            sys.stdout.write(
                                f"\r[{bar}] {percent:6.2f}% ({downloaded // 1024} KB/{total // 1024} KB)"
                            )
                            sys.stdout.flush()
                        else:
                            sys.stdout.write(f"\rDownloaded {downloaded // 1024} KB")
                            sys.stdout.flush()
            sys.stdout.write("\n")
        os.replace(temp_path, archive_path)
        print(f"Downloaded {archive_path}")
        if archive_path.endswith(".7z"):
            extract_with_7z(archive_path)
        return True
    except KeyboardInterrupt:
        print("\nKeyboard interrupt: Cleaning up partial download...")
        temp_path = f"{archive_path}.part" if archive_path else None
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                print(f"Removed partial file: {temp_path}")
            except Exception as e:
                print(f"Failed to remove partial file: {e}")
        return False
    except Exception as e:
        print(f"Error downloading official wordlist: {e}")
        return False


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


def download_hashmob_rules(print_fn=print) -> None:
    """Download Hashmob rules."""
    list_and_download_hashmob_rules()
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
    for tfile, wordlist_id in torrents:
        print_fn(f"[i] Downloading: {tfile}")
        download_torrent(tfile, wordlist_id=wordlist_id)
    print_fn("[i] All torrents processed.")
