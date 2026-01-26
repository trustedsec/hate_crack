import json
import os
from typing import Callable, Tuple



import threading
from queue import Queue
import requests
from bs4 import BeautifulSoup
import shutil

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

def download_torrent_file(torrent_url, save_dir=None):
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

    if not torrent_url.startswith("http"):
        filename = torrent_url
    else:
        filename = torrent_url.split("/")[-1]

    wordlist_base = filename.replace('.torrent', '').replace('.7z', '').replace('.txt', '')
    wordlist_uri = f"https://weakpass.com/wordlists/{wordlist_base}"
    print(f"[+] Fetching wordlist page: {wordlist_uri}")
    r = requests.get(wordlist_uri, headers=headers)
    if r.status_code != 200:
        print(f"[!] Failed to fetch wordlist page: {wordlist_uri}")
        return None

    soup = BeautifulSoup(r.text, "html.parser")
    app_div = soup.find("div", id="app")
    if not app_div or not app_div.has_attr("data-page"):
        print(f"[!] Could not find app data on {wordlist_uri}")
        return None

    data_page_val = app_div["data-page"]
    if not isinstance(data_page_val, str):
        data_page_val = str(data_page_val)
    data_page_val = data_page_val.replace('&quot;', '"')
    try:
        data = json.loads(data_page_val)
        wordlist = data.get('props', {}).get('wordlist')
        wordlist_id = None
        torrent_link_from_data = None
        if wordlist:
            wordlist_id = wordlist.get('id')
            torrent_link_from_data = wordlist.get('torrent_link')
        else:
            wordlists = data.get('props', {}).get('wordlists')
            if isinstance(wordlists, dict) and 'data' in wordlists:
                wordlists = wordlists['data']
            if isinstance(wordlists, list):
                for wl in wordlists:
                    if wl.get('torrent_link') == filename or wl.get('name') == filename:
                        wordlist_id = wl.get('id')
                        torrent_link_from_data = wl.get('torrent_link')
                        break
                    if wordlist_base in wl.get('name', ''):
                        wordlist_id = wl.get('id')
                        torrent_link_from_data = wl.get('torrent_link')
                        break
    except Exception as e:
        print(f"[!] Failed to parse data-page JSON: {e}")
        return None

    if not (torrent_link_from_data and wordlist_id):
        print(f"[!] No torrent link or id found in wordlist data for {filename}.")
        return None
    if not torrent_link_from_data.startswith('http'):
        torrent_link = f"https://weakpass.com/download/{wordlist_id}/{torrent_link_from_data}"
    else:
        torrent_link = torrent_link_from_data

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
            proc = subprocess.Popen([
                "transmission-cli",
                "-w", output_dir,
                torrent_file
            ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True)
            if proc.stdout is not None:
                for line in proc.stdout:
                    print(line, end='')
            proc.wait()
            if proc.returncode != 0:
                print(f"transmission-cli failed for {torrent_file} (exit {proc.returncode})")
                return
            else:
                print(f"Download complete for {torrent_file}")
            sevenz_files = glob.glob(os.path.join(output_dir, '*.7z'))
            if not sevenz_files:
                print("[i] No .7z files found to extract.")
                return
            for zfile in sevenz_files:
                print(f"[+] Extracting {zfile} ...")
                sevenz_bin = shutil.which('7z') or shutil.which('7za')
                if not sevenz_bin:
                    print("[!] 7z or 7za not found in PATH. Please install p7zip-full or 7-zip to extract archives.")
                    continue
                try:
                    extract_result = subprocess.run([
                        sevenz_bin, 'x', '-y', zfile, f'-o{output_dir}'
                    ], capture_output=True, text=True)
                    print(extract_result.stdout)
                    if extract_result.returncode == 0:
                        print(f"[+] Extraction complete: {zfile}")
                    else:
                        print(f"[!] Extraction failed for {zfile}: {extract_result.stderr}")
                except Exception as e:
                    print(f"[!] Error extracting {zfile}: {e}")
        except Exception as e:
            print(f"Error running transmission-cli: {e}")

    t = threading.Thread(target=run_transmission, args=(local_filename, save_dir))
    t.start()
    print(f"transmission-cli launched in background for {local_filename}")
    return local_filename

def weakpass_wordlist_menu():
    fetch_all_weakpass_wordlists_multithreaded()
    try:
        with open("weakpass_wordlists.json", "r", encoding="utf-8") as f:
            all_wordlists = json.load(f)
    except Exception as e:
        print(f"Failed to load local wordlist cache: {e}")
        return
    page = 0
    batch_size = 100
    while True:
        filtered_wordlists = [wl for wl in all_wordlists if str(wl.get('rank', '')) == '7']
        start_idx = page * batch_size
        end_idx = start_idx + batch_size
        page_wordlists = filtered_wordlists[start_idx:end_idx]
        if not page_wordlists:
            print("No more wordlists.")
            if page > 0:
                page -= 1
            continue
        col_width = 45
        cols = 3
        print("\nEach entry shows: [number]. [wordlist name] [effectiveness score] [rank]")
        print(f"Available Wordlists (Batch {page+1}):")
        rows = (len(page_wordlists) + cols - 1) // cols
        lines = [''] * rows
        for idx, wl in enumerate(page_wordlists):
            col = idx // rows
            row = idx % rows
            effectiveness = wl.get('effectiveness', wl.get('downloads', ''))
            rank = wl.get('rank', '')
            entry = f"{start_idx+idx+1:3d}. {wl['name'][:25]:<25} {effectiveness:<8} {rank:<2}"
            lines[row] += entry.ljust(col_width)
        for line in lines:
            print(line)
        sel = input("\nEnter the number to download, 'n' for next batch, 'p' for previous, or 'q' to cancel: ")
        if sel.lower() == 'q':
            print("Returning to menu...")
            return
        if sel.lower() == 'n':
            page += 1
            continue
        if sel.lower() == 'p' and page > 0:
            page -= 1
            continue
        try:
            sel_idx = int(sel) - 1 - start_idx
            if 0 <= sel_idx < len(page_wordlists):
                torrent_url = page_wordlists[sel_idx]['torrent_url']
                download_torrent_file(torrent_url)
            else:
                print("Invalid selection.")
        except Exception as e:
            print(f"Error: {e}")
import requests

# Hashview Integration - Real API implementation matching hate_crack.py
class HashviewAPI:
    def get_hashfile_details(self, hashfile_id):
        """Get hashfile details and hashtype for a given hashfile_id."""
        url = f"{self.base_url}/v1/hashfiles/{hashfile_id}"
        resp = self.session.get(url)
        resp.raise_for_status()
        # Try to parse JSON if available, else fallback to raw content
        try:
            data = resp.json()
        except Exception:
            data = None
        # If JSON, look for hashtype
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

    def __init__(self, base_url, api_key, debug=False):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.debug = debug
        self.session = requests.Session()
        self.session.cookies.set('uuid', api_key)
        self.session.verify = False
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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





def download_hashes_from_hashview(
    hashview_url: str,
    hashview_api_key: str,
    debug_mode: bool,
    input_fn: Callable[[str], str] = input,
    print_fn: Callable[..., None] = print,
) -> Tuple[str, str]:
    """Interactive Hashview download flow used by CLI."""
    api_harness = HashviewAPI(hashview_url, hashview_api_key, debug=debug_mode)
    result = api_harness.list_customers()
    if 'customers' in result and result['customers']:
        api_harness.display_customers_multicolumn(result['customers'])
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
    torrents = [wl['torrent_url'] for wl in all_wordlists if wl.get('torrent_url')]
    print_fn(f"[i] Downloading {len(torrents)} torrents...")
    for tfile in torrents:
        print_fn(f"[i] Downloading: {tfile}")
        download_torrent(tfile)
    print_fn("[i] All torrents processed.")
