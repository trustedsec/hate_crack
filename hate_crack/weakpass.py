
def check_7z():
    """
    Check if 7z (or 7za) is installed in PATH. Print instructions if missing.
    Returns True if found, False otherwise.
    """
    import shutil
    if shutil.which('7z') or shutil.which('7za'):
        return True
    print("\n[!] 7z (or 7za) is missing.")
    print("To install on macOS:  brew install p7zip")
    print("To install on Ubuntu/Debian:  sudo apt-get install p7zip-full")
    print("Please install 7z and try again.")
    return False

def check_transmission_cli():
    """
    Check if transmission-cli is installed in PATH. Print instructions if missing.
    Returns True if found, False otherwise.
    """
    import shutil
    if shutil.which('transmission-cli'):
        return True
    print("\n[!] transmission-cli is missing.")
    print("To install on macOS:  brew install transmission-cli")
    print("To install on Ubuntu/Debian:  sudo apt-get install transmission-cli")
    print("Please install transmission-cli and try again.")
    return False
"""
weakpass.py
Modularized Weakpass integration functions.
"""

import os
import threading
from queue import Queue
import requests
from bs4 import BeautifulSoup
import json
import shutil

def get_hcat_wordlists_dir():
    """Return the configured `hcatWordlists` directory from config.json.

    Looks for config.json in:
      1) The package directory (hate_crack/config.json)
      2) The project root (parent of package)
    Falls back to './wordlists' within the project root if not found.
    """
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
    """Fetch all Weakpass wordlist pages in parallel using threads and save to a local JSON file."""
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
    # Use configured hcat wordlists directory by default
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
