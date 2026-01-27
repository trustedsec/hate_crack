import json
import os
import threading
from queue import Queue
import shutil
from typing import Callable, Tuple

import requests
from bs4 import BeautifulSoup

def check_7z():
    import shutil
    if shutil.which('7z') or shutil.which('7za'):
        return True
    print("\n[!] 7z (or 7za) is missing.")
    print("To install on macOS:  brew install p7zip")
    print("To install on Ubuntu/Debian:  sudo apt-get install p7zip-full")
    print("Please install 7z and try again.")
    return False

def check_transmission_cli():
    import shutil
    if shutil.which('transmission-cli'):
        return True
    print("\n[!] transmission-cli is missing.")
    print("To install on macOS:  brew install transmission-cli")
    print("To install on Ubuntu/Debian:  sudo apt-get install transmission-cli")
    print("Please install transmission-cli and try again.")
    return False


def get_hcat_wordlists_dir():
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
    candidates = [
        os.path.join(pkg_dir, 'config.json'),
        os.path.join(project_root, 'config.json')
    ]
    default = os.path.join(project_root, 'wordlists')
    for config_path in candidates:
        try:
            if os.path.isfile(config_path):
                with open(config_path) as f:
                    config = json.load(f)
                    path = config.get('hcatWordlists')
                    if path:
                        path = os.path.expanduser(path)
                        if not os.path.isabs(path):
                            path = os.path.join(project_root, path)
                        os.makedirs(path, exist_ok=True)
                        return path
        except Exception:
            continue
    os.makedirs(default, exist_ok=True)
    return default

def fetch_all_weakpass_wordlists_multithreaded(total_pages=67, threads=10, output_file="weakpass_wordlists.json"):
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
                if isinstance(wordlists_data, dict) and 'data' in wordlists_data:
                    wordlists_data = wordlists_data['data']
                with lock:
                    for wl in wordlists_data:
                        wordlists.append({
                            "id": wl.get("id", ""),
                            "name": wl.get("name", ""),
                            "size": wl.get("size", ""),
                            "rank": wl.get("rank", ""),
                            "downloads": wl.get("downloaded", ""),
                            "torrent_url": wl.get("torrent_link", "")
                        })
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
        if wl['name'] not in seen:
            unique_wordlists.append(wl)
            seen.add(wl['name'])

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(unique_wordlists, f, indent=2)
    print(f"Saved {len(unique_wordlists)} wordlists to {output_file}")

def download_torrent_file(torrent_url, save_dir=None, wordlist_id=None):

    if not save_dir:
        save_dir = get_hcat_wordlists_dir()
    else:
        save_dir = os.path.expanduser(save_dir)
        if not os.path.isabs(save_dir):
            save_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), save_dir)
    os.makedirs(save_dir, exist_ok=True)
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
        wordlist_base = filename.replace('.torrent', '').replace('.7z', '').replace('.txt', '')
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
                data_page_val = data_page_val.replace('&quot;', '"')
                try:
                    data = json.loads(data_page_val)
                    wordlist = data.get('props', {}).get('wordlist')
                    resolved_id = None
                    torrent_link_from_data = None
                    if wordlist:
                        resolved_id = wordlist.get('id')
                        torrent_link_from_data = wordlist.get('torrent_link')
                    else:
                        wordlists = data.get('props', {}).get('wordlists')
                        if isinstance(wordlists, dict) and 'data' in wordlists:
                            wordlists = wordlists['data']
                        if isinstance(wordlists, list):
                            for wl in wordlists:
                                if wl.get('torrent_link') == filename or wl.get('name') == filename:
                                    resolved_id = wl.get('id')
                                    torrent_link_from_data = wl.get('torrent_link')
                                    break
                                if wordlist_base in wl.get('name', ''):
                                    resolved_id = wl.get('id')
                                    torrent_link_from_data = wl.get('torrent_link')
                                    break
                    if torrent_link_from_data and resolved_id:
                        if not torrent_link_from_data.startswith('http'):
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
    local_filename = os.path.join(save_dir, filename if filename.endswith('.torrent') else filename + '.torrent')
    if r2.status_code == 200 and not content_type.startswith("text/html"):
        with open(local_filename, 'wb') as f:
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
        print("Please install it with: brew install transmission-cli (on macOS) or your package manager.")
        print(f"Torrent file saved at {local_filename}, but download will not start until transmission-cli is available.")
        return local_filename

    def run_transmission(torrent_file, output_dir):
        import subprocess
        import glob
        print(f"Starting transmission-cli for {torrent_file}...")
        try:
            pkg_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
            kill_script = os.path.join(project_root, "wordlists", "kill_transmission.sh")
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
                    print(line, end='')
            proc.wait()
            if proc.returncode != 0:
                print(f"transmission-cli failed for {torrent_file} (exit {proc.returncode})")
                return
            else:
                print(f"Download complete for {torrent_file}")
        except Exception as e:
            print(f"Error running transmission-cli: {e}")

    t = threading.Thread(target=run_transmission, args=(local_filename, save_dir))
    t.start()
    print(f"transmission-cli launched in background for {local_filename}")
    return local_filename

def weakpass_wordlist_menu(rank=-1):
    fetch_all_weakpass_wordlists_multithreaded()
    try:
        with open("weakpass_wordlists.json", "r", encoding="utf-8") as f:
            all_wordlists = json.load(f)
    except Exception as e:
        print(f"Failed to load local wordlist cache: {e}")
        return
    if rank == 0:
        filtered_wordlists = all_wordlists
    elif rank > 0:
        filtered_wordlists = [wl for wl in all_wordlists if str(wl.get('rank', '')) == str(rank)]
    else:
        # Default: show all with rank > 4
        filtered_wordlists = [wl for wl in all_wordlists if str(wl.get('rank', '')) > '4']
    col_width = 45
    cols = 3
    print("\nEach entry shows: [number]. [wordlist name] [effectiveness score] [rank]")
    print(f"Available Wordlists:")
    rows = (len(filtered_wordlists) + cols - 1) // cols
    lines = [''] * rows
    for idx, wl in enumerate(filtered_wordlists):
        col = idx // rows
        row = idx % rows
        effectiveness = wl.get('effectiveness', wl.get('downloads', ''))
        rank = wl.get('rank', '')
        entry = f"{idx+1:3d}. {wl['name'][:25]:<25} {effectiveness:<8} {rank:<2}"
        lines[row] += entry.ljust(col_width)
    for line in lines:
        print(line)
    def parse_indices(selection, max_index):
        indices = set()
        for part in selection.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                try:
                    start, end = map(int, part.split('-', 1))
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
        sel = input("\nEnter the number(s) to download (e.g. 1,3,5-7) or 'q' to cancel: ")
        if sel.lower() == 'q':
            print("Returning to menu...")
            return
        indices = parse_indices(sel, len(filtered_wordlists))
        if not indices:
            print("No valid selection.")
            return
        for idx in indices:
            entry = filtered_wordlists[idx - 1]
            torrent_url = entry.get('torrent_url')
            if not torrent_url:
                print(f"[!] Missing torrent URL for selection {idx}")
                continue
            download_torrent_file(torrent_url, wordlist_id=entry.get('id'))
    except KeyboardInterrupt:
        print("\nKeyboard interrupt: Returning to main menu...")
        return
    except Exception as e:
        print(f"Error: {e}")

# Hashview Integration - Real API implementation matching hate_crack.py
class HashviewAPI:
    def __init__(self, base_url, api_key, debug=False):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.debug = debug
        self.session = requests.Session()
        self.session.cookies.set('uuid', api_key)
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
        customers = self.list_customers().get('customers', [])
        for customer in customers:
            cid = int(customer.get('id', 0))
            hashfiles = self.get_customer_hashfiles(cid)
            hashfile_map = {}
            for hf in hashfiles:
                hfid = hf.get('id')
                if hfid is None:
                    continue
                hfid = int(hfid)
                # Try to get hashtype from hashfile dict, else fetch details
                hashtype = hf.get('hash_type') or hf.get('hashtype')
                if not hashtype:
                    details = self.get_hashfile_details(hfid)
                    hashtype = details.get('hashtype') or details.get('hash_type')
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
        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        try:
            data = resp.json()
        except Exception:
            data = None
        hashtype = None
        if data:
            hashtype = data.get('hashtype') or data.get('hash_type')
        return {'hashfile_id': hashfile_id, 'hashtype': hashtype, 'details': data, 'raw': resp.content}

    FILE_FORMATS = {
        'pwdump': 0,
        'netntlm': 1,
        'kerberos': 2,
        'shadow': 3,
        'user:hash': 4,
        'hash_only': 5,
    }

    def list_customers(self):
        url = f"{self.base_url}/v1/customers"
        resp = self.session.get(url)
        resp.raise_for_status()
        data = resp.json()
        if 'users' in data:
            customers = json.loads(data['users'])
            return {'customers': customers}
        return data

    def list_hashfiles(self):
        url = f"{self.base_url}/v1/hashfiles"
        resp = self.session.get(url)
        resp.raise_for_status()
        data = resp.json()
        if 'hashfiles' in data:
            if isinstance(data['hashfiles'], str):
                hashfiles = json.loads(data['hashfiles'])
            else:
                hashfiles = data['hashfiles']
            return hashfiles
        return []

    def get_customer_hashfiles(self, customer_id):
        all_hashfiles = self.list_hashfiles()
        return [hf for hf in all_hashfiles if int(hf.get('customer_id', 0)) == customer_id]

    def get_customer_hashfiles_with_hashtype(self, customer_id, target_hashtype="1000"):
        """Return hashfiles for a customer that match the requested hashtype."""
        customer_hashfiles = self.get_customer_hashfiles(customer_id)
        if not customer_hashfiles:
            return []
        target_str = str(target_hashtype)
        filtered = []
        for hf in customer_hashfiles:
            hashtype = hf.get('hashtype') or hf.get('hash_type')
            if hashtype is None:
                hf_id = hf.get('id')
                if hf_id is not None:
                    try:
                        details = self.get_hashfile_details(hf_id)
                        hashtype = details.get('hashtype')
                    except Exception:
                        hashtype = None
            if hashtype is not None and str(hashtype) == target_str:
                filtered.append(hf)
        return filtered

    def list_customers_with_hashfiles(self):
        """Return customers that have at least one hashfile."""
        customers_result = self.list_customers()
        customers = customers_result.get('customers', []) if isinstance(customers_result, dict) else customers_result
        if not customers:
            return []

        try:
            all_hashfiles = self.list_hashfiles()
        except Exception:
            all_hashfiles = []

        hashfiles_by_customer = {}
        for hf in all_hashfiles or []:
            try:
                cust_id = int(hf.get('customer_id', 0))
            except Exception:
                continue
            if cust_id <= 0:
                continue
            hashfiles_by_customer.setdefault(cust_id, []).append(hf)

        filtered_customers = []
        for customer in customers:
            try:
                cust_id = int(customer.get('id', 0))
            except Exception:
                continue
            if cust_id <= 0:
                continue
            customer_hashfiles = hashfiles_by_customer.get(cust_id, [])
            if not customer_hashfiles:
                continue
            filtered_customers.append(customer)
        return filtered_customers

    def display_customers_multicolumn(self, customers):
        if not customers:
            print("\nNo customers found.")
            return
        try:
            terminal_width = os.get_terminal_size().columns
        except:
            terminal_width = 120
        max_id_len = max(len(str(c.get('id', ''))) for c in customers)
        col_width = max_id_len + 2 + 30 + 2
        num_cols = max(1, terminal_width // col_width)
        print("\n" + "="*terminal_width)
        print("Available Customers:")
        print("="*terminal_width)
        num_customers = len(customers)
        rows = (num_customers + num_cols - 1) // num_cols
        for row in range(rows):
            line_parts = []
            for col in range(num_cols):
                idx = row + col * rows
                if idx < num_customers:
                    customer = customers[idx]
                    cust_id = customer.get('id', 'N/A')
                    cust_name = customer.get('name', 'N/A')
                    name_width = col_width - max_id_len - 2 - 2
                    if len(str(cust_name)) > name_width:
                        cust_name = str(cust_name)[:name_width-3] + "..."
                    entry = f"{cust_id}: {cust_name}"
                    line_parts.append(entry.ljust(col_width))
            print("".join(line_parts).rstrip())
        print("="*terminal_width)
        print(f"Total: {len(customers)} customer(s)")

    def upload_hashfile(self, file_path, customer_id, hash_type, file_format=5, hashfile_name=None):
        if hashfile_name is None:
            hashfile_name = os.path.basename(file_path)
        with open(file_path, 'rb') as f:
            file_content = f.read()
        url = (
            f"{self.base_url}/v1/hashfiles/upload/"
            f"{customer_id}/{file_format}/{hash_type}/{hashfile_name}"
        )
        headers = {'Content-Type': 'text/plain'}
        resp = self.session.post(url, data=file_content, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def create_job(self, name, hashfile_id, customer_id, limit_recovered=False, notify_email=True):
        url = f"{self.base_url}/v1/jobs/add"
        headers = {'Content-Type': 'application/json'}
        data = {
            "name": name,
            "hashfile_id": hashfile_id,
            "customer_id": customer_id,
        }
        resp = self.session.post(url, json=data, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def download_left_hashes(self, customer_id, hashfile_id, output_file=None):
        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        if output_file is None:
            output_file = f"left_{customer_id}_{hashfile_id}.txt"
        with open(output_file, 'wb') as f:
            f.write(resp.content)
        return {'output_file': output_file, 'size': len(resp.content)}

    def upload_cracked_hashes(self, file_path, hash_type='1000'):
        valid_lines = []
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if '31d6cfe0d16ae931b73c59d7e0c089c0' in line:
                    continue
                if not line or ':' not in line:
                    continue
                parts = line.split(':', 1)
                if len(parts) != 2:
                    break
                hash_value = parts[0].strip()
                plaintext = parts[1].strip()
                valid_lines.append(f"{hash_value}:{plaintext}")
        converted_content = '\n'.join(valid_lines)
        url = f"{self.base_url}/v1/hashes/import/{hash_type}"
        headers = {'Content-Type': 'text/plain'}
        resp = self.session.post(url, data=converted_content, headers=headers)
        resp.raise_for_status()
        try:
            json_response = resp.json()
            if 'type' in json_response and json_response['type'] == 'Error':
                raise Exception(f"Hashview API Error: {json_response.get('msg', 'Unknown error')}")
            return json_response
        except (json.JSONDecodeError, ValueError):
            raise Exception(f"Invalid API response: {resp.text[:200]}")

    def create_customer(self, name):
        url = f"{self.base_url}/v1/customers/add"
        headers = {'Content-Type': 'application/json'}
        data = {"name": name}
        resp = self.session.post(url, json=data, headers=headers)
        resp.raise_for_status()
        return resp.json()

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
                for key in ('file_ids', 'ids', 'hashfile_ids'):
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
    api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)
    customers = api_harness.list_customers_with_hashfiles()
    if customers:
        api_harness.display_customers_multicolumn(customers)
    else:
        print_fn("\nNo customers found with hashfiles.")
    customer_id = int(input_fn("\nEnter customer ID: "))
    try:
        customer_hashfiles = api_harness.get_customer_hashfiles(customer_id)
        if customer_hashfiles:
            print_fn("\n" + "=" * 100)
            print_fn(f"Hashfiles for Customer ID {customer_id}:")
            print_fn("=" * 100)
            print_fn(f"{'ID':<10} {'Name':<88}")
            print_fn("-" * 100)
            for hf in customer_hashfiles:
                hf_id = hf.get('id', 'N/A')
                hf_name = hf.get('name', 'N/A')
                if len(str(hf_name)) > 88:
                    hf_name = str(hf_name)[:85] + "..."
                print_fn(f"{hf_id:<10} {hf_name:<88}")
            print_fn("=" * 100)
            print_fn(f"Total: {len(customer_hashfiles)} hashfile(s)")
        else:
            print_fn(f"\nNo hashfiles found for customer ID {customer_id}")
    except Exception as exc:
        print_fn(f"\nWarning: Could not list hashfiles: {exc}")
        print_fn("You may need to manually find the hashfile ID in the web interface.")
    hashfile_id = int(input_fn("\nEnter hashfile ID: "))
    hcat_hash_type = "1000"
    output_file = f"left_{customer_id}_{hashfile_id}.txt"
    download_result = api_harness.download_left_hashes(customer_id, hashfile_id, output_file)
    print_fn(f"\n✓ Success: Downloaded {download_result['size']} bytes")
    print_fn(f"  File: {download_result['output_file']}")
    hcat_hash_file = download_result['output_file']
    print_fn("\nNow starting hate_crack with:")
    print_fn(f"  Hash file: {hcat_hash_file}")
    print_fn(f"  Hash type: {hcat_hash_type}")
    return hcat_hash_file, hcat_hash_type


def sanitize_filename(filename):
    """Sanitize a filename by replacing spaces and removing problematic characters."""
    import re

    filename = filename.replace(' ', '_')
    filename = re.sub(r'[^A-Za-z0-9._-]', '', filename)
    return filename


def get_hashmob_api_key():
    """Return hashmob_api_key from config.json in package or project root."""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(pkg_dir, os.pardir))
    for cfg in (os.path.join(pkg_dir, 'config.json'), os.path.join(project_root, 'config.json')):
        if os.path.isfile(cfg):
            try:
                with open(cfg) as f:
                    config = json.load(f)
                    key = config.get('hashmob_api_key')
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
        wordlists = [r for r in data if r.get('type') == 'wordlist']
        print("Available Hashmob Wordlists:")
        for idx, wl in enumerate(wordlists):
            print(f"{idx+1}. {wl.get('name', wl.get('file_name', ''))} - {wl.get('information', '')}")
        return wordlists
    except Exception as e:
        print(f"Error fetching Hashmob wordlists: {e}")
        return []


def download_hashmob_wordlist(file_name, out_path):
    """Download a wordlist file from Hashmob by file name."""
    url = f"https://hashmob.net/api/v2/downloads/research/wordlists/{file_name}"
    api_key = get_hashmob_api_key()
    headers = {"api-key": api_key} if api_key else {}
    try:
        with requests.get(url, headers=headers, stream=True, timeout=60, allow_redirects=True) as r:
            if r.status_code in (301, 302, 303, 307, 308):
                redirect_url = r.headers.get('Location')
                if redirect_url:
                    print(f"Following redirect to: {redirect_url}")
                    return download_hashmob_wordlist(redirect_url, out_path)
                print("Redirect with no Location header!")
                return False
            r.raise_for_status()
            content_type = r.headers.get('Content-Type', '')
            if 'text/plain' in content_type:
                html = r.content.decode(errors='replace')
                import re
                match = re.search(
                    r"<meta[^>]+http-equiv=['\"]refresh['\"][^>]+content=['\"]0;url=([^'\"]+)['\"]",
                    html,
                    re.IGNORECASE
                )
                if match:
                    real_url = match.group(1)
                    print(f"Found meta refresh redirect to: {real_url}")
                    with requests.get(real_url, stream=True, timeout=120) as r2:
                        r2.raise_for_status()
                        with open(out_path, 'wb') as f:
                            for chunk in r2.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                    print(f"Downloaded {out_path}")
                    return True
                print("Error: Received HTML instead of file. Possible permission or quota issue.")
                return False
            with open(out_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        print(f"Downloaded {out_path}")
        return True
    except Exception as e:
        print(f"Error downloading wordlist: {e}")
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
            print("Official Hashmob Wordlists (JSON):")
            for idx, entry in enumerate(data):
                print(f"{idx+1}. {entry}")
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
        print("Official Hashmob Wordlists:")
        for idx, entry in enumerate(data):
            name = entry.get('name', entry.get('file_name', str(entry)))
            file_name = entry.get('file_name', name)
            print(f"{idx+1}. {name} ({file_name})")
        print("a. Download ALL files")
        sel = input("Enter the number(s) to download (e.g. 1,3,5-7), or 'a' for all, or 'q' to quit: ")
        if sel.lower() == 'q':
            return
        if sel.lower() == 'a':
            try:
                for entry in data:
                    file_name = entry.get('file_name')
                    if not file_name:
                        print("No file_name found for an entry, skipping.")
                        continue
                    out_path = entry.get('file_name', file_name)
                    download_official_wordlist(file_name, out_path)
            except KeyboardInterrupt:
                print("\nKeyboard interrupt: Returning to download menu...")
                return
            return
        def parse_indices(selection, max_index):
            indices = set()
            for part in selection.split(','):
                part = part.strip()
                if not part:
                    continue
                if '-' in part:
                    try:
                        start, end = map(int, part.split('-', 1))
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
                file_name = entry.get('file_name')
                if not file_name:
                    print("No file_name found for selection, skipping.")
                    continue
                out_path = entry.get('file_name', file_name)
                download_official_wordlist(file_name, out_path)
        except Exception as e:
            print(f"Error: {e}")
    except Exception as e:
        print(f"Error listing official wordlists: {e}")


def download_official_wordlist(file_name, out_path):
    """Download a file from the official wordlists directory with a progress bar."""
    import sys

    url = f"https://hashmob.net/api/v2/downloads/research/official/{file_name}"
    try:
        with requests.get(url, stream=True, timeout=120) as r:
            r.raise_for_status()
            try:
                total = int(r.headers.get('content-length') or 0)
            except Exception:
                total = 0
            downloaded = 0
            chunk_size = 8192
            out_path = sanitize_filename(file_name)
            dest_dir = get_hcat_wordlists_dir()
            archive_path = os.path.join(dest_dir, out_path) if not os.path.isabs(out_path) else out_path
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            with open(archive_path, 'wb') as f:
                for chunk in r.iter_content(chunk_size=chunk_size):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            done = int(50 * downloaded / total)
                            percent = 100 * downloaded / total
                            bar = '=' * done + ' ' * (50 - done)
                            sys.stdout.write(
                                f"\r[{bar}] {percent:6.2f}% ({downloaded // 1024} KB/{total // 1024} KB)"
                            )
                            sys.stdout.flush()
                        else:
                            sys.stdout.write(f"\rDownloaded {downloaded // 1024} KB")
                            sys.stdout.flush()
            sys.stdout.write("\n")
        print(f"Downloaded {archive_path}")
        if archive_path.endswith('.7z'):
            extract_with_7z(archive_path)
        return True
    except Exception as e:
        print(f"Error downloading official wordlist: {e}")
        return False


def extract_with_7z(archive_path, output_dir=None, remove_archive=True):
    """Extract a .7z archive using the 7z or 7za command."""
    import subprocess

    if output_dir is None:
        output_dir = os.path.splitext(archive_path)[0]
    os.makedirs(output_dir, exist_ok=True)
    sevenz_bin = shutil.which('7z') or shutil.which('7za')
    if not sevenz_bin:
        print("[!] 7z or 7za not found in PATH. Please install p7zip-full or 7-zip to extract archives.")
        return False
    try:
        print(f"Extracting {archive_path} to {output_dir} ...")
        result = subprocess.run(
            [sevenz_bin, 'x', '-y', archive_path],
            capture_output=True,
            text=True,
            cwd=output_dir
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
    if any('id' not in wl or wl.get('id') in ("", None) for wl in all_wordlists):
        print_fn("[i] weakpass_wordlists.json missing wordlist IDs, refreshing cache...")
        fetch_all_wordlists()
        with open(cache_path, "r", encoding="utf-8") as f:
            all_wordlists = json.load(f)
    torrents = [(wl.get('torrent_url'), wl.get('id')) for wl in all_wordlists if wl.get('torrent_url')]
    print_fn(f"[i] Downloading {len(torrents)} torrents...")
    for tfile, wordlist_id in torrents:
        print_fn(f"[i] Downloading: {tfile}")
        download_torrent(tfile, wordlist_id=wordlist_id)
    print_fn("[i] All torrents processed.")
